// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kvm_host.h>
#include <asm/kvm_rockchip_iommu.h>

/* Allocate 1024 KB (2^10 pages) for the hypervisor for now. */
#define NUM_PAGES_ORDER 10

int init_rockchip_iommu_driver(struct hyp_rk_iommu_info *info)
{
	static DEFINE_MUTEX(lock);

	u64 info_pfn;
	int ret;
	int i;

	mutex_lock(&lock);

	info->mem_pool_host_va = __get_free_pages(GFP_ATOMIC | GFP_DMA32, NUM_PAGES_ORDER);
	if (!info->mem_pool_host_va) {
		ret = -ENOMEM;
		goto out_free;
	}

	info->mem_pool_num_pages = 1 << NUM_PAGES_ORDER;

	/* Share info struct with the hypervisor. */
	info_pfn = __pa(info) >> PAGE_SHIFT;
	ret = kvm_call_hyp_nvhe(__pkvm_host_share_hyp, info_pfn);
	if (ret)
		goto out_unshare;

	/* Hypercall to initialize EL2 driver. */
	ret = pkvm_iommu_driver_init(PKVM_IOMMU_DRIVER_ROCKCHIP_IOMMU, info, sizeof(*info));

out_unshare:
	WARN_ON(kvm_call_hyp_nvhe(__pkvm_host_unshare_hyp, info_pfn));
out_free:
	if (ret)
		free_pages(info->mem_pool_host_va, NUM_PAGES_ORDER);
out:
	mutex_unlock(&lock);
	return ret;
}

int pkvm_iommu_rockchip_iommu_register(struct device *dev, phys_addr_t addr, struct hyp_rk_iommu_info *info)
{
	int ret;

	if (!is_protected_kvm_enabled())
		return -ENODEV;

	ret = init_rockchip_iommu_driver(info);
	if (ret)
		return ret;

	return pkvm_iommu_register(dev, PKVM_IOMMU_DRIVER_ROCKCHIP_IOMMU,
				   addr, NULL, NULL);
}
EXPORT_SYMBOL_GPL(pkvm_iommu_rockchip_iommu_register);