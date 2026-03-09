// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 Google LLC
 * Author: David Brazdil <dbrazdil@google.com>
 */

#include "linux/types.h"
#include <linux/kvm_host.h>
#include <linux/limits.h>

#include <asm/kvm_asm.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pkvm.h>

#include <hyp/adjust_pc.h>
#include <nvhe/iommu.h>
#include <nvhe/mm.h>
#include <nvhe/pfn_info.h>
#include <nvhe/pkvm.h>
#include <nvhe/mem_protect.h>

enum {
	IOMMU_DRIVER_NOT_READY = 0,
	IOMMU_DRIVER_INITIALIZING,
	IOMMU_DRIVER_READY,
};

struct pkvm_iommu_driver {
	const struct pkvm_iommu_ops *ops;
	atomic_t state;
};

static struct pkvm_iommu_driver iommu_drivers[PKVM_IOMMU_NR_DRIVERS];

/* IOMMU device list. Must only be accessed with host_kvm.lock held. */
static LIST_HEAD(iommu_list);

static bool iommu_finalized;
static DEFINE_HYP_SPINLOCK(iommu_registration_lock);

static void *iommu_mem_pool;
static size_t iommu_mem_remaining;

/* 由 userspace 显式指定：哪个 domain_id 代表 host DMA。 */
static unsigned int revpt_host_dma_domain = UINT_MAX;

static void assert_host_component_locked(void)
{
	hyp_assert_lock_held(&host_kvm.lock);
}

static void host_lock_component(void)
{
	hyp_spin_lock(&host_kvm.lock);
}

static void host_unlock_component(void)
{
	hyp_spin_unlock(&host_kvm.lock);
}

/*
 * Find IOMMU driver by its ID. The input ID is treated as unstrusted
 * and is properly validated.
 */
static inline struct pkvm_iommu_driver *get_driver(enum pkvm_iommu_driver_id id)
{
	size_t index = (size_t)id;

	if (index >= ARRAY_SIZE(iommu_drivers))
		return NULL;

	return &iommu_drivers[index];
}

static const struct pkvm_iommu_ops *get_driver_ops(enum pkvm_iommu_driver_id id)
{
	switch (id) {
	case PKVM_IOMMU_DRIVER_S2MPU:
		return IS_ENABLED(CONFIG_KVM_S2MPU) ? &pkvm_s2mpu_ops : NULL;
	case PKVM_IOMMU_DRIVER_SYSMMU_SYNC:
		return IS_ENABLED(CONFIG_KVM_S2MPU) ? &pkvm_sysmmu_sync_ops :
						      NULL;
	case PKVM_IOMMU_DRIVER_ROCKCHIP_IOMMU:
		return IS_ENABLED(CONFIG_KVM_ROCKCHIP_IOMMU) ?
			       &pkvm_rockchip_iommu_ops :
			       NULL;
	default:
		return NULL;
	}
}

static inline bool driver_acquire_init(struct pkvm_iommu_driver *drv)
{
	return atomic_cmpxchg_acquire(&drv->state, IOMMU_DRIVER_NOT_READY,
				      IOMMU_DRIVER_INITIALIZING) ==
	       IOMMU_DRIVER_NOT_READY;
}

static inline void driver_release_init(struct pkvm_iommu_driver *drv,
				       bool success)
{
	atomic_set_release(&drv->state, success ? IOMMU_DRIVER_READY :
						  IOMMU_DRIVER_NOT_READY);
}

static inline bool is_driver_ready(struct pkvm_iommu_driver *drv)
{
	return atomic_read(&drv->state) == IOMMU_DRIVER_READY;
}

static size_t __iommu_alloc_size(struct pkvm_iommu_driver *drv)
{
	return ALIGN(sizeof(struct pkvm_iommu) + drv->ops->data_size,
		     sizeof(unsigned long));
}

/* Global memory pool for allocating IOMMU list entry structs. */
static inline struct pkvm_iommu *alloc_iommu(struct pkvm_iommu_driver *drv,
					     void *mem, size_t mem_size)
{
	size_t size = __iommu_alloc_size(drv);
	void *ptr;

	assert_host_component_locked();

	/*
	 * If new memory is being provided, replace the existing pool with it.
	 * Any remaining memory in the pool is discarded.
	 */
	if (mem && mem_size) {
		iommu_mem_pool = mem;
		iommu_mem_remaining = mem_size;
	}

	if (size > iommu_mem_remaining)
		return NULL;

	ptr = iommu_mem_pool;
	iommu_mem_pool += size;
	iommu_mem_remaining -= size;
	return ptr;
}

static inline void free_iommu(struct pkvm_iommu_driver *drv,
			      struct pkvm_iommu *ptr)
{
	size_t size = __iommu_alloc_size(drv);

	assert_host_component_locked();

	if (!ptr)
		return;

	/* Only allow freeing the last allocated buffer. */
	if ((void *)ptr + size != iommu_mem_pool)
		return;

	iommu_mem_pool -= size;
	iommu_mem_remaining += size;
}

static bool is_overlap(phys_addr_t r1_start, size_t r1_size,
		       phys_addr_t r2_start, size_t r2_size)
{
	phys_addr_t r1_end = r1_start + r1_size;
	phys_addr_t r2_end = r2_start + r2_size;

	return (r1_start < r2_end) && (r2_start < r1_end);
}

static bool is_mmio_range(phys_addr_t base, size_t size)
{
	struct memblock_region *reg;
	phys_addr_t limit = BIT(host_kvm.pgt.ia_bits);
	size_t i;

	/* Check against limits of host IPA space. */
	if ((base >= limit) || !size || (size > limit - base))
		return false;

	for (i = 0; i < hyp_memblock_nr; i++) {
		reg = &hyp_memory[i];
		if (is_overlap(base, size, reg->base, reg->size))
			return false;
	}
	return true;
}

static int __snapshot_host_stage2(u64 start, u64 pa_max, u32 level,
				  kvm_pte_t *ptep,
				  enum kvm_pgtable_walk_flags flags,
				  void *const arg)
{
	struct pkvm_iommu_driver *const drv = arg;
	u64 end = start + kvm_granule_size(level);
	kvm_pte_t pte = *ptep;

	/*
	 * Valid stage-2 entries are created lazily, invalid ones eagerly.
	 * Note: In the future we may need to check if [start,end) is MMIO.
	 * Note: Drivers initialize their PTs to all memory owned by the host,
	 * so we only call the driver on regions where that is not the case.
	 */
	if (pte && !kvm_pte_valid(pte))
		drv->ops->host_stage2_idmap_prepare(start, end, /*prot*/ 0);
	return 0;
}

static int snapshot_host_stage2(struct pkvm_iommu_driver *const drv)
{
	struct kvm_pgtable_walker walker = {
		.cb = __snapshot_host_stage2,
		.arg = drv,
		.flags = KVM_PGTABLE_WALK_LEAF,
	};
	struct kvm_pgtable *pgt = &host_kvm.pgt;

	if (!drv->ops->host_stage2_idmap_prepare)
		return 0;

	return kvm_pgtable_walk(pgt, 0, BIT(pgt->ia_bits), &walker);
}

static bool validate_against_existing_iommus(struct pkvm_iommu *dev)
{
	struct pkvm_iommu *other;

	assert_host_component_locked();

	list_for_each_entry (other, &iommu_list, list) {
		/* Device ID must be unique. */
		if (dev->id == other->id)
			return false;

		/* MMIO regions must not overlap. */
		if (is_overlap(dev->pa, dev->size, other->pa, other->size))
			return false;
	}
	return true;
}

static struct pkvm_iommu *find_iommu_by_id(unsigned long id)
{
	struct pkvm_iommu *dev;

	assert_host_component_locked();

	list_for_each_entry (dev, &iommu_list, list) {
		if (dev->id == id)
			return dev;
	}
	return NULL;
}

/*
 * Initialize EL2 IOMMU driver.
 *
 * This is a common hypercall for driver initialization. Driver-specific
 * arguments are passed in a shared memory buffer. The driver is expected to
 * initialize it's page-table bookkeeping.
 */
int __pkvm_iommu_driver_init(enum pkvm_iommu_driver_id id, void *data,
			     size_t size)
{
	struct pkvm_iommu_driver *drv;
	const struct pkvm_iommu_ops *ops;
	int ret = 0;

	data = kern_hyp_va(data);

	/* New driver initialization not allowed after __pkvm_iommu_finalize(). */
	hyp_spin_lock(&iommu_registration_lock);
	if (iommu_finalized) {
		ret = -EPERM;
		goto out_unlock;
	}

	drv = get_driver(id);
	ops = get_driver_ops(id);
	if (!drv || !ops) {
		ret = -EINVAL;
		goto out_unlock;
	}

	if (!driver_acquire_init(drv)) {
		ret = -EBUSY;
		goto out_unlock;
	}

	drv->ops = ops;

	/* This can change stage-2 mappings. */
	if (ops->init) {
		ret = hyp_pin_shared_mem(data, data + size);
		if (!ret) {
			ret = ops->init(data, size);
			hyp_unpin_shared_mem(data, data + size);
		}
		if (ret)
			goto out_release;
	}

	/*
	 * Walk host stage-2 and pass current mappings to the driver. Start
	 * accepting host stage-2 updates as soon as the host lock is released.
	 */
	host_lock_component();
	ret = snapshot_host_stage2(drv);
	if (!ret)
		driver_release_init(drv, /*success=*/true);
	host_unlock_component();

out_release:
	if (ret)
		driver_release_init(drv, /*success=*/false);

out_unlock:
	hyp_spin_unlock(&iommu_registration_lock);
	return ret;
}

// pt-checked
// 来自host的hypercall，把一个 IOMMU 设备注册到 pKVM 的 EL2 管理里，并把这段设备 MMIO 从 host 普通可映射路径中“接管”出来。核心看下面的host_stage2_unmap_dev_locked和__pkvm_create_private_mapping
int __pkvm_iommu_register(unsigned long dev_id,
			  enum pkvm_iommu_driver_id drv_id, phys_addr_t dev_pa,
			  size_t dev_size, unsigned long parent_id,
			  void *kern_mem_va, size_t mem_size)
{
	struct pkvm_iommu *dev = NULL;
	struct pkvm_iommu_driver *drv;
	void *mem_va = NULL;
	int ret = 0;

	/* New device registration not allowed after __pkvm_iommu_finalize(). */
	hyp_spin_lock(&iommu_registration_lock);
	if (iommu_finalized) {
		ret = -EPERM;
		goto out_unlock;
	}

	drv = get_driver(drv_id);
	if (!drv || !is_driver_ready(drv)) {
		ret = -ENOENT;
		goto out_unlock;
	}

	if (dev_pa && dev_size) {
		if (!PAGE_ALIGNED(dev_pa) || !PAGE_ALIGNED(dev_size)) {
			ret = -EINVAL;
			goto out_unlock;
		}

		if (!is_mmio_range(dev_pa, dev_size)) {
			ret = -EINVAL;
			goto out_unlock;
		}
	}

	/*
	 * Accept memory donation if the host is providing new memory.
	 * Note: We do not return the memory even if there is an error later.
	 */
	// 这里是一些元数据。允许捐赠过来一些元数据。
	if (kern_mem_va && mem_size) {
		mem_va = kern_hyp_va(kern_mem_va);

		if (!PAGE_ALIGNED(mem_va) || !PAGE_ALIGNED(mem_size)) {
			ret = -EINVAL;
			goto out_unlock;
		}

		ret = __pkvm_host_donate_hyp(hyp_virt_to_pfn(mem_va),
					     mem_size >> PAGE_SHIFT);
		if (ret)
			goto out_unlock;
	}

	host_lock_component();

	/* Allocate memory for the new device entry. */
	dev = alloc_iommu(drv, mem_va, mem_size);
	if (!dev) {
		ret = -ENOMEM;
		goto out_free;
	}

	/* Populate the new device entry. */
	*dev = (struct pkvm_iommu){
		.children = LIST_HEAD_INIT(dev->children),
		.id = dev_id,
		.ops = drv->ops,
		.pa = dev_pa,
		.size = dev_size,
	};

	if (dev_pa && dev_size && !validate_against_existing_iommus(dev)) {
		ret = -EBUSY;
		goto out_free;
	}

	if (parent_id) {
		dev->parent = find_iommu_by_id(parent_id);
		if (!dev->parent) {
			ret = -EINVAL;
			goto out_free;
		}

		if (dev->parent->ops->validate_child) {
			ret = dev->parent->ops->validate_child(dev->parent,
							       dev);
			if (ret)
				goto out_free;
		}
	}

	if (dev->ops->validate) {
		ret = dev->ops->validate(dev);
		if (ret)
			goto out_free;
	}

	// 这里是把iommu的mmio区域捐赠给hyp
	if (dev_pa && dev_size) {
		/*
		* Unmap the device's MMIO range from host stage-2. If registration
		* is successful, future attempts to re-map will be blocked by
		* pkvm_iommu_host_stage2_adjust_range.
		*/
		// 从host去掉映射
		ret = host_stage2_unmap_dev_locked(dev_pa, dev_size);
		if (ret)
			goto out_free;

		/* Create EL2 mapping for the device. Do it last as it is irreversible. */
		// 给hyp加上映射
		dev->va = (void *)__pkvm_create_private_mapping(
			dev_pa, dev_size, PAGE_HYP_DEVICE);
		if (IS_ERR(dev->va)) {
			ret = PTR_ERR(dev->va);
			goto out_free;
		}
	}

	/* Register device and prevent host from mapping the MMIO range. */
	list_add_tail(&dev->list, &iommu_list);
	if (dev->parent)
		list_add_tail(&dev->siblings, &dev->parent->children);

out_free:
	if (ret)
		free_iommu(drv, dev);
	host_unlock_component();

out_unlock:
	hyp_spin_unlock(&iommu_registration_lock);
	return ret;
}

int __pkvm_iommu_finalize(void)
{
	int ret = 0;

	hyp_spin_lock(&iommu_registration_lock);
	if (!iommu_finalized)
		iommu_finalized = true;
	else
		ret = -EPERM;
	hyp_spin_unlock(&iommu_registration_lock);
	return ret;
}

// 分配新domain
// 调查一下是不是只有一个rkiommu实例，预期是的。
// 上面，是的。
int __pkvm_iommu_alloc_domain(unsigned int domain_id, u32 type)
{
	struct pkvm_iommu *dev;
	int ret;

	assert_host_component_locked();

	list_for_each_entry (dev, &iommu_list, list) {
		ret = dev->ops->alloc_domain ?
			      dev->ops->alloc_domain(domain_id, type) :
			      0;
		if (ret)
			return ret;
	}

	return ret;
}

// pt-checked
int __pkvm_iommu_free_domain(unsigned int domain_id)
{
	struct pkvm_iommu *dev;
	int ret;

	assert_host_component_locked();

	list_for_each_entry (dev, &iommu_list, list) {
		ret = dev->ops->free_domain ? dev->ops->free_domain(domain_id) :
					      0;
		if (ret)
			return ret;
	}

	return ret;
}

int __pkvm_iommu_attach_dev(unsigned int iommu_id, unsigned int domain_id)
{
	struct pkvm_iommu *dev;
	int ret;

	assert_host_component_locked();

	list_for_each_entry (dev, &iommu_list, list) {
		ret = dev->ops->attach_dev ?
			      dev->ops->attach_dev(iommu_id, domain_id) :
			      0;
		if (ret)
			return ret;
	}

	return ret;
}

int __pkvm_iommu_detach_dev(unsigned int iommu_id, unsigned int domain_id)
{
	struct pkvm_iommu *dev;
	int ret;

	assert_host_component_locked();

	list_for_each_entry (dev, &iommu_list, list) {
		ret = dev->ops->detach_dev ?
			      dev->ops->detach_dev(iommu_id, domain_id) :
			      0;
		if (ret)
			return ret;
	}

	return ret;
}

// pt-checked
// 确定一个已明确的事实：domain_id在这棵树里就是io页表的唯一标识符。
int __pkvm_iommu_map(unsigned int domain_id, unsigned long iova,
		     phys_addr_t paddr, size_t size, int prot)
{
	struct pkvm_iommu *dev;
	enum revpt_ref_type type;
	u64 pfn = paddr >> PAGE_SHIFT;
	u64 pages = PAGE_ALIGN(size) >> PAGE_SHIFT;
	int ret;

	assert_host_component_locked();

	list_for_each_entry (dev, &iommu_list, list) {
		ret = dev->ops->map ? dev->ops->map(domain_id, iova, paddr,
					    size, prot) :
			      0;
		if (ret)
			return ret;
	}

	/*
	 * 这里把 IOMMU 映射变更同步到测试账本：
	 * - 先用外部工具设置 host DMA domain_id
	 * - 该 domain 记为 HOST_DMA，其余按 ENCLAVE_DMA 记账
	 */
	type = (domain_id == revpt_host_dma_domain) ? REVPT_REF_HOST_DMA :
						      REVPT_REF_ENCLAVE_DMA;
	if (pages) {
		(void)revpt_ref_inc_range(pfn, pages, type);
		/* 立即触发区间检查，避免把违规延后到离线阶段才暴露。 */
		(void)revpt_check_range(pfn, pages);
	}

	return ret;
}

// pt-checked
size_t __pkvm_iommu_unmap(unsigned int domain_id, unsigned long iova,
		  size_t size)
{
	struct pkvm_iommu *dev;
	enum revpt_ref_type type;
	phys_addr_t paddr;
	u64 pages = PAGE_ALIGN(size) >> PAGE_SHIFT;
	size_t ret;

	assert_host_component_locked();

	/*
	 * 先快照旧映射，再执行 unmap：
	 * 这样可以正确把旧 PFN 的 DMA 引用计数减回去。
	 */
	paddr = __pkvm_iommu_iova_to_phys(domain_id, iova);

	list_for_each_entry (dev, &iommu_list, list) {
		ret = dev->ops->unmap ? dev->ops->unmap(domain_id, iova, size) :
					0;
		if (ret)
			return ret;
	}

	type = (domain_id == revpt_host_dma_domain) ? REVPT_REF_HOST_DMA :
						      REVPT_REF_ENCLAVE_DMA;
	if (pages && paddr) {
		(void)revpt_ref_dec_range(paddr >> PAGE_SHIFT, pages, type);
		(void)revpt_check_range(paddr >> PAGE_SHIFT, pages);
	}

	return ret;
}

phys_addr_t __pkvm_iommu_iova_to_phys(unsigned int domain_id,
				      unsigned long iova)
{
	struct pkvm_iommu *dev;
	phys_addr_t ret;

	assert_host_component_locked();

	list_for_each_entry (dev, &iommu_list, list) {
		ret = dev->ops->iova_to_phys ?
			      dev->ops->iova_to_phys(domain_id, iova) :
			      0;
		if (ret)
			return ret;
	}

	return ret;
}

int __pkvm_view_iopt(unsigned int domain_id, u64 *iovas, u64 *pas, u64 *ptes,
		     int cap, phys_addr_t phys_l, phys_addr_t phys_r)
{
	struct pkvm_iommu *dev;
	int ret = -ENOENT;

	assert_host_component_locked();

	list_for_each_entry (dev, &iommu_list, list) {
		if (dev->ops->get_iopt) {
			ret = dev->ops->get_iopt(domain_id, iovas, pas, ptes,
						 cap, phys_l, phys_r);
			return ret;
		}
	}

	return ret;
}

int __pkvm_iommu_flush_iotlb_all(unsigned int iommu_id)
{
	struct pkvm_iommu *dev;
	int ret;

	assert_host_component_locked();

	list_for_each_entry (dev, &iommu_list, list) {
		ret = dev->ops->flush_iotlb_all ?
			      dev->ops->flush_iotlb_all(iommu_id) :
			      0;
		if (ret)
			return ret;
	}

	return ret;
}

int __pkvm_iommu_rk_enable(unsigned int iommu_id)
{
	struct pkvm_iommu *dev;
	int ret;

	assert_host_component_locked();

	list_for_each_entry (dev, &iommu_list, list) {
		ret = dev->ops->rk_enable ? dev->ops->rk_enable(iommu_id) : 0;
		if (ret)
			return ret;
	}

	return ret;
}

int __pkvm_iommu_rk_disable(unsigned int iommu_id)
{
	struct pkvm_iommu *dev;
	int ret;

	assert_host_component_locked();

	list_for_each_entry (dev, &iommu_list, list) {
		ret = dev->ops->rk_disable ? dev->ops->rk_disable(iommu_id) : 0;
		if (ret)
			return ret;
	}

	return ret;
}

int __pkvm_iommu_rk_enable_hyp(unsigned int domain_id)
{
	struct pkvm_iommu *dev;
	int ret;

	assert_host_component_locked();

	list_for_each_entry (dev, &iommu_list, list) {
		ret = dev->ops->rk_enable_hyp ?
			      dev->ops->rk_enable_hyp(domain_id) :
			      0;
		if (ret)
			return ret;
	}

	return ret;
}

int __pkvm_iommu_rk_disable_hyp(unsigned int domain_id)
{
	struct pkvm_iommu *dev;
	int ret;

	assert_host_component_locked();

	list_for_each_entry (dev, &iommu_list, list) {
		ret = dev->ops->rk_disable_hyp ?
			      dev->ops->rk_disable_hyp(domain_id) :
			      0;
		if (ret)
			return ret;
	}

	return ret;
}

int __pkvm_iommu_pm_notify(unsigned long dev_id, enum pkvm_iommu_pm_event event)
{
	struct pkvm_iommu *dev;
	int ret;

	host_lock_component();
	dev = find_iommu_by_id(dev_id);
	if (dev) {
		if (event == PKVM_IOMMU_PM_SUSPEND) {
			ret = dev->ops->suspend ? dev->ops->suspend(dev) : 0;
			if (!ret)
				dev->powered = false;
		} else if (event == PKVM_IOMMU_PM_RESUME) {
			ret = dev->ops->resume ? dev->ops->resume(dev) : 0;
			if (!ret)
				dev->powered = true;
		} else {
			ret = -EINVAL;
		}
	} else {
		ret = -ENODEV;
	}
	host_unlock_component();
	return ret;
}

/*
 * Check host memory access against IOMMUs' MMIO regions.
 * Returns -EPERM if the address is within the bounds of a registered device.
 * Otherwise returns zero and adjusts boundaries of the new mapping to avoid
 * MMIO regions of registered IOMMUs.
 */
int pkvm_iommu_host_stage2_adjust_range(phys_addr_t addr, phys_addr_t *start,
					phys_addr_t *end)
{
	struct pkvm_iommu *dev;
	phys_addr_t new_start = *start;
	phys_addr_t new_end = *end;
	phys_addr_t dev_start, dev_end;

	assert_host_component_locked();

	list_for_each_entry (dev, &iommu_list, list) {
		dev_start = dev->pa;
		dev_end = dev_start + dev->size;

		if (addr < dev_start)
			new_end = min(new_end, dev_start);
		else if (addr >= dev_end)
			new_start = max(new_start, dev_end);
		else
			return -EPERM;
	}

	*start = new_start;
	*end = new_end;
	return 0;
}

bool pkvm_iommu_host_dabt_handler(struct kvm_cpu_context *host_ctxt, u32 esr,
				  phys_addr_t pa)
{
	struct pkvm_iommu *dev;

	assert_host_component_locked();

	list_for_each_entry (dev, &iommu_list, list) {
		if (dev->pa && dev->size) {
			if (pa < dev->pa || pa >= dev->pa + dev->size)
				continue;

			/* No 'powered' check - the host assumes it is powered. */
			if (!dev->ops->host_dabt_handler ||
			    !dev->ops->host_dabt_handler(dev, host_ctxt, esr,
							 pa, pa - dev->pa))
				return false;
		} else {
			if (!dev->ops->host_dabt_handler ||
			    !dev->ops->host_dabt_handler(dev, host_ctxt, esr,
							 pa, NULL))
				return false;
		}

		kvm_skip_host_instr();
		return true;
	}
	return false;
}

/*
每当 host stage-2 某段地址的可访问属性变化时（map/unmap/owner 注解变化），调用它把这个变化广播给 IOMMU 子系统
rkiommu似乎没有实现这里面用到的方法，所以应该什么都不会做。
*/
void pkvm_iommu_host_stage2_idmap(phys_addr_t start, phys_addr_t end,
				  enum kvm_pgtable_prot prot)
{
	struct pkvm_iommu_driver *drv;
	struct pkvm_iommu *dev;
	size_t i;

	assert_host_component_locked();

	for (i = 0; i < ARRAY_SIZE(iommu_drivers); i++) {
		drv = get_driver(i);
		if (drv && is_driver_ready(drv) &&
		    drv->ops->host_stage2_idmap_prepare)
			drv->ops->host_stage2_idmap_prepare(start, end, prot);
	}

	list_for_each_entry (dev, &iommu_list, list) {
		if (dev->powered && dev->ops->host_stage2_idmap_apply)
			dev->ops->host_stage2_idmap_apply(dev, start, end);
	}
}



struct revpt_baseline_walk_ctx {
	enum page_owner owner;
	enum revpt_ref_type ref_type;
};

static inline phys_addr_t revpt_stage2_pte_phys(kvm_pte_t pte)
{
	return (phys_addr_t)(pte & KVM_PTE_ADDR_MASK);
}

static int revpt_track_mapping_range(u64 pfn, u64 nr_pages,
				      enum page_owner owner,
				      enum revpt_ref_type ref_type)
{
	u64 i;

	for (i = 0; i < nr_pages; i++) {
		u64 cur = pfn + i;
		struct pfn_info info;

		if (revpt_snapshot_pfn(cur, &info)) {
			/* 首次出现的 PFN：建立追踪并设置默认 owner。 */
			(void)revpt_set_flags(cur, PFN_F_TRACKED | PFN_F_RAM, 0);
			(void)revpt_set_owner(cur, owner);
		} else if (!(info.flags & PFN_F_TRACKED)) {
			(void)revpt_set_flags(cur, PFN_F_TRACKED | PFN_F_RAM, 0);
			(void)revpt_set_owner(cur, owner);
		} else if (info.owner != owner) {
			/* 多主体同时可达：保持当前 owner，仅补齐授权。 */
			if (owner == OWN_HOST)
				(void)revpt_grant_access(cur, ACC_HOST_CPU);
			else if (owner == OWN_ENCLAVE)
				(void)revpt_grant_access(cur, ACC_ENCLAVE_CPU);
		}
	}

	(void)revpt_ref_inc_range(pfn, nr_pages, ref_type);
	return 0;
}

static int revpt_baseline_walk_cb(u64 start, u64 end, u32 level, kvm_pte_t *ptep,
				  enum kvm_pgtable_walk_flags flags,
				  void *arg)
{
	struct revpt_baseline_walk_ctx *ctx = arg;
	kvm_pte_t pte = READ_ONCE(*ptep);
	phys_addr_t pa;
	u64 pages;

	if (!kvm_pte_valid(pte))
		return 0;

	pa = revpt_stage2_pte_phys(pte);
	pages = (end - start) >> PAGE_SHIFT;
	if (!pages)
		return 0;

	return revpt_track_mapping_range(pa >> PAGE_SHIFT, pages, ctx->owner,
					 ctx->ref_type);
}

static int revpt_capture_baseline_locked(void)
{
	struct revpt_baseline_walk_ctx host_ctx = {
		.owner = OWN_HOST,
		.ref_type = REVPT_REF_HOST_CPU,
	};
	struct kvm_pgtable_walker host_walker = {
		.cb = revpt_baseline_walk_cb,
		.arg = &host_ctx,
		.flags = KVM_PGTABLE_WALK_LEAF,
	};
	int i, ret;

	/*
	 * 新语义：按“当前各主体页表可达性”重建测试初始状态。
	 * 这里不是全量物理页检查，而是遍历 host/guest 页表快照。
	 */
	revpt_reset_all();

	ret = kvm_pgtable_walk(&host_kvm.pgt, 0, BIT(host_kvm.pgt.ia_bits),
			       &host_walker);
	if (ret)
		return ret;

	for (i = 0; i < KVM_MAX_PVMS; i++) {
		struct kvm_shadow_vm *vm;
		struct revpt_baseline_walk_ctx guest_ctx = {
			.owner = OWN_ENCLAVE,
			.ref_type = REVPT_REF_ENCLAVE_CPU,
		};
		struct kvm_pgtable_walker guest_walker = {
			.cb = revpt_baseline_walk_cb,
			.arg = &guest_ctx,
			.flags = KVM_PGTABLE_WALK_LEAF,
		};

		vm = pkvm_shadow_table_get(index_to_shadow_handle(i));
		if (!vm)
			continue;

		hyp_spin_lock(&vm->lock);
		ret = kvm_pgtable_walk(&vm->pgt, 0, BIT(vm->pgt.ia_bits),
				       &guest_walker);
		hyp_spin_unlock(&vm->lock);
		if (ret)
			return ret;
	}

	return 0;
}

int __pkvm_revpt_set_host_dma_domain(unsigned int domain_id)
{
	host_lock_component();
	revpt_host_dma_domain = domain_id;
	host_unlock_component();
	return 0;
}

int __pkvm_revpt_sync(void)
{
	/* 主动全量复扫：用于板端测试命令触发“重新爬取元数据”。 */
	revpt_force_rescan();
	return 0;
}

int __pkvm_revpt_get_violations(struct pkvm_asgard_violation *out, u32 cap,
				 u32 *copied, u32 *total)
{
	return revpt_copy_violations(out, cap, copied, total);
}

int __pkvm_revpt_capture_baseline(void)
{
	int ret;

	host_lock_component();
	ret = revpt_capture_baseline_locked();
	host_unlock_component();

	return ret;
}
