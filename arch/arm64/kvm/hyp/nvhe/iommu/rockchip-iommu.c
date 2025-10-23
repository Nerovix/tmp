// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kvm_host.h>

#include <asm/kvm_hyp.h>
#include <asm/kvm_rockchip_iommu.h>

#include <nvhe/mm.h>
#include <nvhe/iommu.h>
#include <nvhe/memory.h>
#include <nvhe/spinlock.h>
#include <nvhe/trap_handler.h>

#include "rockchip_iommu.h"

#define DMA_MAPPING_ERROR (~(dma_addr_t)0)

struct hyp_rk_iommu_domain {
	struct list_head iommus; /* attached iommus */
	u32 *dt; /* page directory table */
	dma_addr_t dt_dma;
	hyp_spinlock_t iommus_lock; /* lock for iommus list */
	hyp_spinlock_t dt_lock; /* lock for modifying page directory table */
	struct list_head node; /* entry in hyp_rk_iommu.domains */
	bool shootdown_entire;
};
static struct hyp_rk_iommu_domain **domains;

struct hyp_rk_iommu {
	struct list_head domains; /* attached domains */
	hyp_spinlock_t domains_lock; /* lock for iommus list */
	phys_addr_t *bases_pa;
	void **bases_va;
	size_t *bases_size;
	int num_mmu;
	bool skip_read;
	struct list_head node; /* entry in hyp_rk_iommu_domain.iommus */
	bool shootdown_entire;
	bool iommu_enabled;
};
static struct hyp_rk_iommu **iommus;

struct hyp_rk_iommu_mem_pool {
	phys_addr_t pa;
	void *va;
	unsigned long physvirt_offset;
	unsigned int remaining_pages;
};
static struct hyp_rk_iommu_mem_pool mem_pool;

static struct hyp_rk_iommu_info info;

static void *pa_to_va(phys_addr_t pa)
{
	return (void *)((unsigned long)pa + mem_pool.physvirt_offset);
}

static phys_addr_t va_to_pa(void *va)
{
	return (phys_addr_t)((unsigned long)va - mem_pool.physvirt_offset);
}

static void *get_zeroed_pages(unsigned int pages)
{
	phys_addr_t pa;
	void *va;

	if (mem_pool.remaining_pages < pages)
		return ERR_PTR(-ENOMEM);

	/* Get next pa. */
	pa = mem_pool.pa + ((info.mem_pool_num_pages - mem_pool.remaining_pages)
			    << PAGE_SHIFT);
	mem_pool.remaining_pages -= pages;

	/* Calcuate va from the offset. */
	va = (void *)((unsigned long)(pa) + mem_pool.physvirt_offset);

	memset(va, 0, pages << PAGE_SHIFT);

	return va;
}

/* TODO: Implement memory coalescing. The driver may eventually run out of pages. */
static int release_pages(void *va, unsigned int pages)
{
	unsigned long offset;
	phys_addr_t pa;

	offset = (unsigned long)va - mem_pool.physvirt_offset;
	pa = (phys_addr_t)offset;

	if (pa < mem_pool.pa ||
	    pa >= mem_pool.pa + (info.mem_pool_num_pages << PAGE_SHIFT))
		return -EINVAL;

	if (mem_pool.remaining_pages + pages > info.mem_pool_num_pages)
		return -EINVAL;

	mem_pool.remaining_pages += pages;

	return 0;
}

static void udelay(int usec)
{
	unsigned long long freq, cycles, start, curr;

	/* Convert usec to timer cycles. */
	asm volatile("mrs %0, cntfrq_el0" : "=r"(freq));
	cycles = (freq * usec) / 0x10c7ul; /* 2**32 / 1000000 (rounded up) */

	/* Add delay for usec. */
	asm volatile("isb; mrs %0, cntpct_el0" : "=r"(start));
	while ((curr - start) < cycles)
		asm volatile("isb; mrs %0, cntpct_el0" : "=r"(curr));
}

static bool rk_iommu_host_dabt_handler(struct pkvm_iommu *dev,
				       struct kvm_cpu_context *host_ctxt,
				       u32 esr, phys_addr_t pa, size_t off)
{
	bool is_write = esr & ESR_ELx_WNR;
	unsigned int len = BIT((esr & ESR_ELx_SAS) >> ESR_ELx_SAS_SHIFT);
	int rd = (esr & ESR_ELx_SRT_MASK) >> ESR_ELx_SRT_SHIFT;
	void *addr = NULL;
	u32 mask;
	int i, j;

	for (i = 0; i < RK_IOMMU_MAX_IOMMUS; i++) {
		if (iommus[i]) {
			for (j = 0; j < iommus[i]->num_mmu; j++) {
				if (pa >= iommus[i]->bases_pa[j] &&
				    pa < (iommus[i]->bases_pa[j] +
					  iommus[i]->bases_size[j])) {
					addr = iommus[i]->bases_va[j] +
					       (pa - iommus[i]->bases_pa[j]);
				}
			}
		}
	}

	if (!addr)
		return false;

	/* Only handle MMIO access with u32 size and alignment. */
	if ((len != sizeof(u32)) || (off & (sizeof(u32) - 1)))
		return false;

	/* TODO: Selectively allow host's MMIO accesses. */

	if (is_write)
		writel_relaxed(cpu_reg(host_ctxt, rd), addr);
	else
		cpu_reg(host_ctxt, rd) = readl_relaxed(addr);

	return true;
}

static void rk_iommu_command(struct hyp_rk_iommu *iommu, u32 command)
{
	int i;

	for (i = 0; i < iommu->num_mmu; i++)
		writel(command, iommu->bases_va[i] + RK_MMU_COMMAND);
}

static void rk_iommu_zap_lines(struct hyp_rk_iommu *iommu,
			       dma_addr_t iova_start, size_t size)
{
	int i;
	dma_addr_t iova_end = iova_start + size;
	/*
	 * TODO(djkurtz): Figure out when it is more efficient to shootdown the
	 * entire iotlb rather than iterate over individual iovas.
	 */
	for (i = 0; i < iommu->num_mmu; i++) {
		dma_addr_t iova;

		for (iova = iova_start; iova < iova_end; iova += SPAGE_SIZE)
			rk_iommu_write(iommu->bases_va[i], RK_MMU_ZAP_ONE_LINE,
				       iova);
	}
}

static void rk_iommu_zap_iova(unsigned int domain_id, dma_addr_t iova,
			      size_t size)
{
	struct hyp_rk_iommu *iommu;

	/* shootdown these iova from all iommus using this domain */
	hyp_spin_lock(&domains[domain_id]->iommus_lock);
	list_for_each_entry (iommu, &domains[domain_id]->iommus, node) {
		/* Only zap IOMMU TLBs that are powered on. */
		if (iommu->iommu_enabled)
			rk_iommu_zap_lines(iommu, iova, size);
	}
	hyp_spin_unlock(&domains[domain_id]->iommus_lock);
}

static void rk_iommu_zap_iova_first_last(unsigned int domain_id,
					 dma_addr_t iova, size_t size)
{
	rk_iommu_zap_iova(domain_id, iova, SPAGE_SIZE);
	if (size > SPAGE_SIZE)
		rk_iommu_zap_iova(domain_id, iova + size - SPAGE_SIZE,
				  SPAGE_SIZE);
}

static int rk_iommu_flush_iotlb_all(unsigned int iommu_id)
{
	int i;

	for (i = 0; i < iommus[iommu_id]->num_mmu; i++) {
		/* Only zap IOMMU TLBs that are powered on. */
		if (iommus[iommu_id]->iommu_enabled)
			rk_iommu_write(iommus[iommu_id]->bases_va[i],
				       RK_MMU_COMMAND, RK_MMU_CMD_ZAP_CACHE);
	}

	return 0;
}

static int rk_iommu_alloc_domain(unsigned int domain_id, u32 type)
{
	struct hyp_rk_iommu_domain *rk_domain;

	if (domain_id >= RK_IOMMU_MAX_DOMAINS) {
		return -EINVAL;
	}

	rk_domain = get_zeroed_pages(1);
	if (IS_ERR_OR_NULL(rk_domain)) {
		return -ENOMEM;
	}
	domains[domain_id] = rk_domain;

	rk_domain->dt = get_zeroed_pages(1);
	if (IS_ERR_OR_NULL(rk_domain->dt)) {
		return -ENOMEM;
	}

	rk_domain->dt_dma = va_to_pa(rk_domain->dt);
	if (rk_domain->dt_dma == DMA_MAPPING_ERROR) {
		return -ENOMEM;
	}

	dcache_clean_poc((unsigned long)rk_domain->dt,
			 (unsigned long)rk_domain->dt +
				 NUM_DT_ENTRIES * sizeof(u32));

	hyp_spin_lock_init(&rk_domain->iommus_lock);
	hyp_spin_lock_init(&rk_domain->dt_lock);
	INIT_LIST_HEAD(&rk_domain->iommus);

	return 0;
}

static int rk_iommu_free_domain(unsigned int domain_id)
{
	int i;

	WARN_ON(!list_empty(&domains[domain_id]->iommus));

	for (i = 0; i < NUM_DT_ENTRIES; i++) {
		u32 dte = domains[domain_id]->dt[i];

		if (rk_dte_is_pt_valid(dte)) {
			phys_addr_t pt_phys = rk_dte_pt_address_v2(dte);
			u32 *page_table = pa_to_va(pt_phys);

			release_pages(page_table, 1);
		}
	}

	release_pages(domains[domain_id]->dt, 1);
	release_pages(domains[domain_id], 1);

	return 0;
}

static int rk_iommu_attach_dev(unsigned int iommu_id, unsigned int domain_id)
{
	struct hyp_rk_iommu_domain *domain = domains[domain_id];
	struct hyp_rk_iommu *iommu = iommus[iommu_id];
	struct hyp_rk_iommu *cur_iommu;
	bool skip_attach = false;

	hyp_spin_lock(&domain->iommus_lock);

	/* Check for duplicate iommu in domain. */
	list_for_each_entry (cur_iommu, &domain->iommus, node) {
		if (cur_iommu == iommu) {
			skip_attach = true;
			break;
		}
	}

	if (!skip_attach) {
		list_add_tail(&iommu->node, &domain->iommus);
	}

	hyp_spin_unlock(&domain->iommus_lock);

	hyp_spin_lock(&iommu->domains_lock);

	if (!skip_attach) {
		list_add_tail(&domain->node, &iommu->domains);
	}

	hyp_spin_unlock(&iommu->domains_lock);

	domain->shootdown_entire = iommu->shootdown_entire;

	return 0;
}

static int rk_iommu_detach_dev(unsigned int iommu_id, unsigned int domain_id)
{
	hyp_spin_lock(&domains[domain_id]->iommus_lock);
	list_del_init(&iommus[iommu_id]->node);
	hyp_spin_unlock(&domains[domain_id]->iommus_lock);

	hyp_spin_lock(&iommus[iommu_id]->domains_lock);
	list_del_init(&domains[domain_id]->node);
	hyp_spin_unlock(&iommus[iommu_id]->domains_lock);

	return 0;
}

static size_t rk_iommu_unmap_iova(unsigned int domain_id, u32 *pte_addr,
				  size_t size)
{
	unsigned int pte_count;
	unsigned int pte_total = size / SPAGE_SIZE;

	hyp_assert_lock_held(&domains[domain_id]->dt_lock);

	for (pte_count = 0; pte_count < pte_total; pte_count++) {
		u32 pte = pte_addr[pte_count];
		if (!rk_pte_is_page_valid(pte))
			break;

		pte_addr[pte_count] = rk_mk_pte_invalid(pte);
	}

	dcache_clean_poc((unsigned long)pte_addr,
			 (unsigned long)pte_addr + pte_count * sizeof(u32));

	return pte_count * SPAGE_SIZE;
}

static size_t rk_iommu_unmap(unsigned int domain_id, unsigned long iova,
			     size_t size)
{
	phys_addr_t pt_phys;
	u32 dte;
	u32 *pte_addr;
	size_t unmap_size;

	hyp_spin_lock(&domains[domain_id]->dt_lock);

	/*
	 * pgsize_bitmap specifies iova sizes that fit in one page table
	 * (1024 4-KiB pages = 4 MiB).
	 * So, size will always be 4096 <= size <= 4194304.
	 * Since iommu_unmap() guarantees that both iova and size will be
	 * aligned, we will always only be unmapping from a single dte here.
	 */
	dte = domains[domain_id]->dt[rk_iova_dte_index(iova)];
	/* Just return 0 if iova is unmapped */
	if (!rk_dte_is_pt_valid(dte)) {
		hyp_spin_unlock(&domains[domain_id]->dt_lock);
		return 0;
	}

	pt_phys = rk_dte_pt_address_v2(dte);
	pte_addr = (u32 *)pa_to_va(pt_phys) + rk_iova_pte_index(iova);
	unmap_size = rk_iommu_unmap_iova(domain_id, pte_addr, size);

	hyp_spin_unlock(&domains[domain_id]->dt_lock);

	/* Shootdown iotlb entries for iova range that was just unmapped */
	/* Do not zap tlb cache line if shootdown_entire set */
	if (!domains[domain_id]->shootdown_entire)
		rk_iommu_zap_iova(domain_id, iova, unmap_size);

	return unmap_size;
}

static u32 *rk_dte_get_page_table_v2(unsigned int domain_id, unsigned long iova)
{
	u32 *page_table, *dte_addr;
	u32 dte_index, dte;
	phys_addr_t pt_phys;
	dma_addr_t pt_dma;

	hyp_assert_lock_held(&domains[domain_id]->dt_lock);

	dte_index = rk_iova_dte_index(iova);
	dte_addr = &domains[domain_id]->dt[dte_index];
	dte = *dte_addr;
	if (rk_dte_is_pt_valid(dte))
		goto done;

	page_table = get_zeroed_pages(1);
	if (IS_ERR_OR_NULL(page_table))
		return ERR_PTR(-ENOMEM);

	pt_dma = va_to_pa(page_table);
	if (pt_dma == DMA_MAPPING_ERROR)
		return ERR_PTR(-ENOMEM);

	dte = rk_mk_dte_v2(pt_dma);
	*dte_addr = dte;

	dcache_clean_poc((unsigned long)page_table,
			 (unsigned long)page_table +
				 NUM_PT_ENTRIES * sizeof(u32));
	dcache_clean_poc((unsigned long)dte_addr,
			 (unsigned long)dte_addr + 1 * sizeof(u32));
done:
	pt_phys = rk_dte_pt_address_v2(dte);
	return (u32 *)pa_to_va(pt_phys);
}

static int rk_iommu_map_iova_v2(unsigned int domain_id, u32 *pte_addr,
				dma_addr_t pte_dma, dma_addr_t iova,
				phys_addr_t paddr, size_t size, int prot)
{
	unsigned int pte_count;
	unsigned int pte_total = size / SPAGE_SIZE;
	phys_addr_t page_phys;

	hyp_assert_lock_held(&domains[domain_id]->dt_lock);

	for (pte_count = 0; pte_count < pte_total; pte_count++) {
		u32 pte = pte_addr[pte_count];

		if (rk_pte_is_page_valid(pte))
			goto unwind;

		pte_addr[pte_count] = rk_mk_pte_v2(paddr, prot);

		paddr += SPAGE_SIZE;
	}

	dcache_clean_poc((unsigned long)pte_addr,
			 (unsigned long)pte_addr + pte_total * sizeof(u32));

	/*
	 * Zap the first and last iova to evict from iotlb any previously
	 * mapped cachelines holding stale values for its dte and pte.
	 * We only zap the first and last iova, since only they could have
	 * dte or pte shared with an existing mapping.
	 */
	/* Do not zap tlb cache line if shootdown_entire set */
	if (!domains[domain_id]->shootdown_entire)
		rk_iommu_zap_iova_first_last(domain_id, iova, size);

	return 0;
unwind:
	/* Unmap the range of iovas that we just mapped */
	rk_iommu_unmap_iova(domain_id, pte_addr, pte_count * SPAGE_SIZE);

	return -EADDRINUSE;
}

static int rk_iommu_map(unsigned int domain_id, unsigned long iova,
			phys_addr_t paddr, size_t size, int prot)
{
	dma_addr_t pte_dma;
	u32 *page_table, *pte_addr;
	u32 dte, pte_index;
	int ret;

	if (domain_id >= RK_IOMMU_MAX_DOMAINS || domains[domain_id] == NULL) {
		return -EINVAL;
	}

	hyp_spin_lock(&domains[domain_id]->dt_lock);

	/*
	 * pgsize_bitmap specifies iova sizes that fit in one page table
	 * (1024 4-KiB pages = 4 MiB).
	 * So, size will always be 4096 <= size <= 4194304.
	 * Since iommu_map() guarantees that both iova and size will be
	 * aligned, we will always only be mapping from a single dte here.
	 */
	page_table = rk_dte_get_page_table_v2(domain_id, iova);
	if (IS_ERR(page_table)) {
		hyp_spin_unlock(&domains[domain_id]->dt_lock);
		return PTR_ERR(page_table);
	}

	dte = domains[domain_id]->dt[rk_iova_dte_index(iova)];
	pte_index = rk_iova_pte_index(iova);
	pte_addr = &page_table[pte_index];
	pte_dma = rk_dte_pt_address_v2(dte) + pte_index * sizeof(u32);
	ret = rk_iommu_map_iova_v2(domain_id, pte_addr, pte_dma, iova, paddr,
				   size, prot);

	hyp_spin_unlock(&domains[domain_id]->dt_lock);

	return ret;
}

static phys_addr_t rk_iommu_iova_to_phys(unsigned int domain_id,
					 unsigned long iova)
{
	phys_addr_t pt_phys, phys = 0;
	u32 dte, pte;
	u32 *page_table;

	hyp_spin_lock(&domains[domain_id]->dt_lock);

	dte = domains[domain_id]->dt[rk_iova_dte_index(iova)];
	if (!rk_dte_is_pt_valid(dte))
		goto out;

	pt_phys = rk_dte_pt_address_v2(dte);
	page_table = (u32 *)pa_to_va(pt_phys);
	pte = page_table[rk_iova_pte_index(iova)];
	if (!rk_pte_is_page_valid(pte))
		goto out;

	phys = rk_pte_page_address_v2(pte) + rk_iova_page_offset(iova);
out:
	hyp_spin_unlock(&domains[domain_id]->dt_lock);

	return phys;
}

static bool rk_iommu_is_stall_active(struct hyp_rk_iommu *iommu)
{
	bool active = true;
	int i;

	for (i = 0; i < iommu->num_mmu; i++)
		active &= !!(rk_iommu_read(iommu->bases_va[i], RK_MMU_STATUS) &
			     RK_MMU_STATUS_STALL_ACTIVE);

	return active;
}

static bool rk_iommu_is_paging_enabled(struct hyp_rk_iommu *iommu)
{
	bool enable = true;
	int i;

	for (i = 0; i < iommu->num_mmu; i++)
		enable &= !!(rk_iommu_read(iommu->bases_va[i], RK_MMU_STATUS) &
			     RK_MMU_STATUS_PAGING_ENABLED);

	return enable;
}

static bool rk_iommu_is_reset_done(struct hyp_rk_iommu *iommu)
{
	bool done = true;
	int i;

	for (i = 0; i < iommu->num_mmu; i++)
		done &= rk_iommu_read(iommu->bases_va[i], RK_MMU_DTE_ADDR) == 0;

	return done;
}

static int rk_iommu_enable_stall(struct hyp_rk_iommu *iommu)
{
	bool val;

	if (iommu->skip_read)
		goto read_wa;

	if (rk_iommu_is_stall_active(iommu))
		return 0;

	/* Stall can only be enabled if paging is enabled */
	if (!rk_iommu_is_paging_enabled(iommu))
		return 0;

read_wa:
	rk_iommu_command(iommu, RK_MMU_CMD_ENABLE_STALL);
	if (iommu->skip_read)
		return 0;

	/* TODO: Poll instead of adding delay. */
	udelay(RK_MMU_POLL_TIMEOUT_US);

	val = rk_iommu_is_stall_active(iommu);
	if (!val)
		return -EAGAIN;

	return 0;
}

static int rk_iommu_disable_stall(struct hyp_rk_iommu *iommu)
{
	bool val;

	if (iommu->skip_read)
		goto read_wa;

	if (!rk_iommu_is_stall_active(iommu))
		return 0;

read_wa:
	rk_iommu_command(iommu, RK_MMU_CMD_DISABLE_STALL);
	if (iommu->skip_read)
		return 0;

	/* TODO: Poll instead of adding delay. */
	udelay(RK_MMU_POLL_TIMEOUT_US);

	val = rk_iommu_is_stall_active(iommu);
	if (!val)
		return -EAGAIN;

	return 0;
}

static int rk_iommu_enable_paging(struct hyp_rk_iommu *iommu)
{
	bool val;

	if (iommu->skip_read)
		goto read_wa;

	if (rk_iommu_is_paging_enabled(iommu))
		return 0;

read_wa:
	rk_iommu_command(iommu, RK_MMU_CMD_ENABLE_PAGING);
	if (iommu->skip_read)
		return 0;

	/* TODO: Poll instead of adding delay. */
	udelay(RK_MMU_POLL_TIMEOUT_US);

	val = rk_iommu_is_paging_enabled(iommu);
	if (!val)
		return -EAGAIN;

	return 0;
}

static int rk_iommu_disable_paging(struct hyp_rk_iommu *iommu)
{
	bool val;

	if (iommu->skip_read)
		goto read_wa;

	if (!rk_iommu_is_paging_enabled(iommu))
		return 0;

read_wa:
	rk_iommu_command(iommu, RK_MMU_CMD_DISABLE_PAGING);
	if (iommu->skip_read)
		return 0;

	/* TODO: Poll instead of adding delay. */
	udelay(RK_MMU_POLL_TIMEOUT_US);

	val = rk_iommu_is_paging_enabled(iommu);
	if (val)
		return -EAGAIN;

	return 0;
}

static u32 rk_iommu_read_dte_addr(void *base)
{
	return rk_iommu_read(base, RK_MMU_DTE_ADDR);
}

static int rk_iommu_force_reset(struct hyp_rk_iommu *iommu)
{
	int i;
	u32 dte_addr;
	bool val;
	u32 address_mask;

	if (iommu->skip_read)
		goto read_wa;

	/*
	 * Check if register DTE_ADDR is working by writing DTE_ADDR_DUMMY
	 * and verifying that upper 5 nybbles are read back.
	 */

	/*
	 * In v2: upper 7 nybbles are read back.
	 */
	for (i = 0; i < iommu->num_mmu; i++) {
		rk_iommu_write(iommu->bases_va[i], RK_MMU_DTE_ADDR,
			       DTE_ADDR_DUMMY);

		/* TODO: Poll instead of adding delay. */
		udelay(RK_MMU_POLL_TIMEOUT_US);

		address_mask = RK_DTE_PT_ADDRESS_MASK_V2;
		dte_addr = rk_iommu_read_dte_addr(iommu->bases_va[i]);
		if (dte_addr != (DTE_ADDR_DUMMY & address_mask))
			return -EFAULT;
	}

read_wa:
	rk_iommu_command(iommu, RK_MMU_CMD_FORCE_RESET);
	if (iommu->skip_read)
		return 0;

	/* TODO: Poll instead of adding delay. */
	udelay(RK_MMU_FORCE_RESET_TIMEOUT_US);

	val = rk_iommu_is_reset_done(iommu);
	if (!val)
		return -EAGAIN;

	return 0;
}

static int rk_iommu_enable(unsigned int iommu_id)
{
	struct hyp_rk_iommu_domain *domain;
	int ret, i;
	u32 dt_v2;
	u32 auto_gate;

	ret = rk_iommu_enable_stall(iommus[iommu_id]);
	if (ret)
		return ret;

	ret = rk_iommu_force_reset(iommus[iommu_id]);
	if (ret)
		goto out_disable_stall;

	hyp_spin_lock(&iommus[iommu_id]->domains_lock);

	for (i = 0; i < iommus[iommu_id]->num_mmu; i++) {
		list_for_each_entry (domain, &iommus[iommu_id]->domains, node) {
			dt_v2 = (domain->dt_dma & DT_LO_MASK) |
				((domain->dt_dma & DT_HI_MASK) >> DT_SHIFT);
			rk_iommu_write(iommus[iommu_id]->bases_va[i],
				       RK_MMU_DTE_ADDR, dt_v2);
		}

		rk_iommu_base_command(iommus[iommu_id]->bases_va[i],
				      RK_MMU_CMD_ZAP_CACHE);
		rk_iommu_write(iommus[iommu_id]->bases_va[i], RK_MMU_INT_MASK,
			       RK_MMU_IRQ_MASK);

		/* Workaround for iommu blocked, BIT(31) default to 1 */
		auto_gate = rk_iommu_read(iommus[iommu_id]->bases_va[i],
					  RK_MMU_AUTO_GATING);
		auto_gate |= DISABLE_FETCH_DTE_TIME_LIMIT;
		rk_iommu_write(iommus[iommu_id]->bases_va[i],
			       RK_MMU_AUTO_GATING, auto_gate);
	}

	hyp_spin_unlock(&iommus[iommu_id]->domains_lock);

	ret = rk_iommu_enable_paging(iommus[iommu_id]);

	if (!ret)
		iommus[iommu_id]->iommu_enabled = true;

out_disable_stall:
	rk_iommu_disable_stall(iommus[iommu_id]);
	return ret;
}

static int rk_iommu_disable(unsigned int iommu_id)
{
	int i;

	rk_iommu_enable_stall(iommus[iommu_id]);
	rk_iommu_disable_paging(iommus[iommu_id]);
	for (i = 0; i < iommus[iommu_id]->num_mmu; i++) {
		rk_iommu_write(iommus[iommu_id]->bases_va[i], RK_MMU_INT_MASK,
			       0);
		rk_iommu_write(iommus[iommu_id]->bases_va[i], RK_MMU_DTE_ADDR,
			       0);
	}
	rk_iommu_disable_stall(iommus[iommu_id]);

	iommus[iommu_id]->iommu_enabled = false;

	return 0;
}

static int rk_iommu_enable_hyp(unsigned int domain_id)
{
	struct hyp_rk_iommu *iommu;
	int i;
	u32 dt_v2;

	/* TODO: Running inference with VM #1 -> VM #2 -> VM #1 will fail.
	 *		 This will somehow make the list to be iterated infinitely.
	 */

	hyp_spin_lock(&domains[domain_id]->iommus_lock);
	list_for_each_entry (iommu, &domains[domain_id]->iommus, node) {
		for (i = 0; i < iommu->num_mmu; i++) {
			dt_v2 = (domains[domain_id]->dt_dma & DT_LO_MASK) |
				((domains[domain_id]->dt_dma & DT_HI_MASK) >>
				 DT_SHIFT);
			rk_iommu_write(iommu->bases_va[i], RK_MMU_DTE_ADDR,
				       dt_v2);
		}
	}
	hyp_spin_unlock(&domains[domain_id]->iommus_lock);

	return 0;
}

static int rk_iommu_disable_hyp(unsigned int domain_id)
{
	struct hyp_rk_iommu *iommu;
	int i;

	/* TODO: Running inference with VM #1 -> VM #2 -> VM #1 will fail.
	 *		 This will somehow make the list to be iterated infinitely.
	 */

	hyp_spin_lock(&domains[domain_id]->iommus_lock);
	list_for_each_entry (iommu, &domains[domain_id]->iommus, node) {
		for (i = 0; i < iommu->num_mmu; i++) {
			rk_iommu_write(iommu->bases_va[i], RK_MMU_DTE_ADDR, 0);

			rk_iommu_base_command(iommu->bases_va[i],
					      RK_MMU_CMD_ZAP_CACHE);
		}
	}
	hyp_spin_unlock(&domains[domain_id]->iommus_lock);

	return 0;
}

static int rk_iommu_init(void *data, size_t size)
{
	size_t domains_size, iommus_size;
	void *addr;
	int num_mmu;
	int i, ret = 0;

	if (size != sizeof(info))
		return -EINVAL;

	/* The host can concurrently modify 'data'. Copy it to avoid TOCTOU. */
	memcpy(&info, data, sizeof(info));

	addr = kern_hyp_va(info.mem_pool_host_va);
	mem_pool.pa = __hyp_pa(addr);
	mem_pool.remaining_pages = info.mem_pool_num_pages;

	/* Create a memory mapping for the hypervisor. */
	mem_pool.va = __pkvm_create_private_mapping(
		mem_pool.pa, mem_pool.remaining_pages << PAGE_SHIFT, PAGE_HYP);
	if (IS_ERR_OR_NULL(mem_pool.va))
		return PTR_ERR(mem_pool.va);

	/* The offset will be used to translate addresses. */
	mem_pool.physvirt_offset =
		(unsigned long)mem_pool.va - (unsigned long)mem_pool.pa;

	domains_size =
		sizeof(struct hyp_rk_iommu_domain *) * RK_IOMMU_MAX_DOMAINS;
	domains =
		get_zeroed_pages((domains_size + PAGE_SIZE - 1) >> PAGE_SHIFT);
	if (IS_ERR_OR_NULL(domains))
		return -ENOMEM;

	iommus_size = sizeof(struct hyp_rk_iommu *) * RK_IOMMU_MAX_IOMMUS;
	iommus = get_zeroed_pages((iommus_size + PAGE_SIZE - 1) >> PAGE_SHIFT);
	if (IS_ERR_OR_NULL(iommus))
		return -ENOMEM;
	iommus[info.iommu_id] = get_zeroed_pages(
		(sizeof(struct hyp_rk_iommu) + PAGE_SIZE - 1) >> PAGE_SHIFT);
	if (IS_ERR_OR_NULL(iommus[info.iommu_id]))
		return -ENOMEM;

	/* TODO: Do not hardcode Rockchip IOMMU MMIO regions. */
	num_mmu = 4;
	iommus[info.iommu_id]->bases_pa = get_zeroed_pages(
		(sizeof(phys_addr_t) * num_mmu + PAGE_SIZE - 1) >> PAGE_SHIFT);
	if (IS_ERR_OR_NULL(iommus[info.iommu_id]->bases_pa))
		return -ENOMEM;
	iommus[info.iommu_id]->bases_size = get_zeroed_pages(
		(sizeof(size_t) * num_mmu + PAGE_SIZE - 1) >> PAGE_SHIFT);
	if (IS_ERR_OR_NULL(iommus[info.iommu_id]->bases_size))
		return -ENOMEM;
	iommus[info.iommu_id]->bases_pa[0] = 0xfdab9000;
	iommus[info.iommu_id]->bases_pa[1] = 0xfdaba000;
	iommus[info.iommu_id]->bases_pa[2] = 0xfdaca000;
	iommus[info.iommu_id]->bases_pa[3] = 0xfdada000;
	iommus[info.iommu_id]->bases_size[0] = 0x1000;
	iommus[info.iommu_id]->bases_size[1] = 0x1000;
	iommus[info.iommu_id]->bases_size[2] = 0x1000;
	iommus[info.iommu_id]->bases_size[3] = 0x1000;
	iommus[info.iommu_id]->num_mmu = num_mmu;

	iommus[info.iommu_id]->bases_va = get_zeroed_pages(
		(sizeof(void *) * num_mmu + PAGE_SIZE - 1) >> PAGE_SHIFT);
	if (IS_ERR_OR_NULL(iommus[info.iommu_id]->bases_va))
		return -ENOMEM;
	for (i = 0; i < num_mmu; i++) {
		/*
		* Unmap the device's MMIO range from host stage-2. If registration
		* is successful, future attempts to re-map will be blocked by
		* pkvm_iommu_host_stage2_adjust_range.
		*/
		ret = host_stage2_unmap_dev_locked(
			iommus[info.iommu_id]->bases_pa[i],
			iommus[info.iommu_id]->bases_size[i]);
		if (ret)
			goto out;

		/* Create EL2 mapping for the device. Do it last as it is irreversible. */
		iommus[info.iommu_id]->bases_va[i] =
			(void *)__pkvm_create_private_mapping(
				iommus[info.iommu_id]->bases_pa[i],
				iommus[info.iommu_id]->bases_size[i],
				PAGE_HYP_DEVICE);
		if (IS_ERR(iommus[info.iommu_id]->bases_va[i])) {
			ret = PTR_ERR(iommus[info.iommu_id]->bases_va[i]);
			goto out;
		}
	}

	iommus[info.iommu_id]->skip_read = info.iommu_skip_read;
	iommus[info.iommu_id]->shootdown_entire = info.iommu_shootdown_entire;

	hyp_spin_lock_init(&iommus[info.iommu_id]->domains_lock);
	INIT_LIST_HEAD(&iommus[info.iommu_id]->domains);

	/* Take away memory pool from the host. */
	ret = __pkvm_host_donate_hyp(mem_pool.pa >> PAGE_SHIFT,
				     info.mem_pool_num_pages);
	if (ret)
		goto out_donate;
	else
		goto out;

out_donate:
	/* Try to return memory back if there was an error. */
	WARN_ON(__pkvm_hyp_donate_host(mem_pool.pa >> PAGE_SHIFT,
				       info.mem_pool_num_pages));
out:
	return ret;
}

static int get_all_domain_ids(unsigned int *domain_ids)
{
	int domains_count = 0;
	size_t i;
	for (i = 0; i < RK_IOMMU_MAX_DOMAINS; i++) {
		if (domains[i])
			domain_ids[domains_count++] = i;
	}
	return domains_count;
}

static int get_iopt(unsigned int domain_id, u64 *iovas, u64 *pas, u64 *ptes,
		    int cap, phys_addr_t phys_l, phys_addr_t phys_r)
{
	phys_addr_t pt_phys, phys;
	u32 dte, pte;
	u32 *page_table;
	size_t dte_index, pte_index;
	const int NUM = SPAGE_SIZE / sizeof(u32);
	int cnt = 0;

	if (domain_id >= RK_IOMMU_MAX_DOMAINS || !domains[domain_id] ||
	    !domains[domain_id]->dt)
		return -ENODEV;

	hyp_spin_lock(&domains[domain_id]->dt_lock);
	for (dte_index = 0; dte_index < NUM; dte_index++) {
		dte = domains[domain_id]->dt[dte_index];
		if (rk_dte_is_pt_valid(dte)) {
			pt_phys = rk_dte_pt_address_v2(dte);
			page_table = (u32 *)pa_to_va(pt_phys);
			for (pte_index = 0; pte_index < NUM; pte_index++) {
				pte = page_table[pte_index];
				if (!rk_pte_is_page_valid(pte))
					continue;
				phys= rk_pte_page_address_v2(pte);
				if(phys_l<=phys && phys<phys_r) {
					if (cnt >= cap) {
						cnt++;
					} else {
						iovas[cnt] = rk_dte_pte_to_iova(
							dte_index, pte_index);
						pas[cnt] = rk_pte_page_address_v2(pte);
						ptes[cnt] = pte;
						cnt++;
					}
				} 
			}
		}
	}

	hyp_spin_unlock(&domains[domain_id]->dt_lock);
	return cnt;
}

const struct pkvm_iommu_ops pkvm_rockchip_iommu_ops = (struct pkvm_iommu_ops){
	.init = rk_iommu_init,
	.alloc_domain = rk_iommu_alloc_domain,
	.free_domain = rk_iommu_free_domain,
	.attach_dev = rk_iommu_attach_dev,
	.detach_dev = rk_iommu_detach_dev,
	.map = rk_iommu_map,
	.unmap = rk_iommu_unmap,
	.iova_to_phys = rk_iommu_iova_to_phys,
	.flush_iotlb_all = rk_iommu_flush_iotlb_all,
	.rk_enable = rk_iommu_enable,
	.rk_disable = rk_iommu_disable,
	.rk_enable_hyp = rk_iommu_enable_hyp,
	.rk_disable_hyp = rk_iommu_disable_hyp,
	.host_dabt_handler = rk_iommu_host_dabt_handler,
	.get_all_domain_ids = get_all_domain_ids,
	.get_iopt = get_iopt,
};
