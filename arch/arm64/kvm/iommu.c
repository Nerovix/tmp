// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 - Google LLC
 * Author: David Brazdil <dbrazdil@google.com>
 */

#include <linux/kvm_host.h>

static unsigned long dev_to_id(struct device *dev)
{
	/* Use the struct device pointer as a unique identifier. */
	return (unsigned long)dev;
}

int pkvm_iommu_driver_init(enum pkvm_iommu_driver_id id, void *data, size_t size)
{
	return kvm_call_hyp_nvhe(__pkvm_iommu_driver_init, id, data, size);
}

int pkvm_iommu_register(struct device *dev, enum pkvm_iommu_driver_id drv_id,
			phys_addr_t pa, size_t size, struct device *parent)
{
	void *mem;
	int ret;

	/*
	 * Hypcall to register the device. It will return -ENOMEM if it needs
	 * more memory. In that case allocate a page and retry.
	 * We assume that hyp never allocates more than a page per hypcall.
	 */
	ret = kvm_call_hyp_nvhe(__pkvm_iommu_register, dev_to_id(dev),
				drv_id, pa, size, dev_to_id(parent), NULL, 0);
	if (ret == -ENOMEM) {
		mem = (void *)__get_free_page(GFP_KERNEL);
		if (!mem)
			return -ENOMEM;

		ret = kvm_call_hyp_nvhe(__pkvm_iommu_register, dev_to_id(dev),
					drv_id, pa, size, dev_to_id(parent),
					mem, PAGE_SIZE);
	}
	return ret;
}

int pkvm_iommu_suspend(struct device *dev)
{
	return kvm_call_hyp_nvhe(__pkvm_iommu_pm_notify, dev_to_id(dev),
				 PKVM_IOMMU_PM_SUSPEND);
}
EXPORT_SYMBOL_GPL(pkvm_iommu_suspend);

int pkvm_iommu_resume(struct device *dev)
{
	return kvm_call_hyp_nvhe(__pkvm_iommu_pm_notify, dev_to_id(dev),
				 PKVM_IOMMU_PM_RESUME);
}
EXPORT_SYMBOL_GPL(pkvm_iommu_resume);

int pkvm_iommu_finalize(void)
{
	return kvm_call_hyp_nvhe(__pkvm_iommu_finalize);
}
EXPORT_SYMBOL_GPL(pkvm_iommu_finalize);

int pkvm_iommu_alloc_domain(unsigned int domain_id, unsigned int type)
{
	return kvm_call_hyp_nvhe(__pkvm_iommu_alloc_domain, domain_id, type);
}
EXPORT_SYMBOL_GPL(pkvm_iommu_alloc_domain);

int pkvm_iommu_free_domain(unsigned int domain_id)
{
	return kvm_call_hyp_nvhe(__pkvm_iommu_free_domain, domain_id);
}
EXPORT_SYMBOL_GPL(pkvm_iommu_free_domain);

int pkvm_iommu_attach_dev(unsigned int iommu_id, unsigned int domain_id)
{
	return kvm_call_hyp_nvhe(__pkvm_iommu_attach_dev, iommu_id, domain_id);
}
EXPORT_SYMBOL_GPL(pkvm_iommu_attach_dev);

int pkvm_iommu_detach_dev(unsigned int iommu_id, unsigned int domain_id)
{
	return kvm_call_hyp_nvhe(__pkvm_iommu_detach_dev, iommu_id, domain_id);
}
EXPORT_SYMBOL_GPL(pkvm_iommu_detach_dev);

int pkvm_iommu_map(unsigned int domain_id, unsigned long iova, phys_addr_t paddr,
				size_t size, int prot)
{
	return kvm_call_hyp_nvhe(__pkvm_iommu_map, domain_id, iova, paddr, size, prot);
}
EXPORT_SYMBOL_GPL(pkvm_iommu_map);

size_t pkvm_iommu_unmap(unsigned int domain_id, unsigned long iova, size_t size)
{
	return kvm_call_hyp_nvhe(__pkvm_iommu_unmap, domain_id, iova, size);
}
EXPORT_SYMBOL_GPL(pkvm_iommu_unmap);

phys_addr_t pkvm_iommu_iova_to_phys(unsigned int domain_id, unsigned long iova)
{
	return kvm_call_hyp_nvhe(__pkvm_iommu_iova_to_phys, domain_id, iova);
}
EXPORT_SYMBOL_GPL(pkvm_iommu_iova_to_phys);

int pkvm_iommu_flush_iotlb_all(unsigned int iommu_id)
{
	return kvm_call_hyp_nvhe(__pkvm_iommu_flush_iotlb_all, iommu_id);
}
EXPORT_SYMBOL_GPL(pkvm_iommu_flush_iotlb_all);

int pkvm_iommu_rk_enable(unsigned int iommu_id)
{
	return kvm_call_hyp_nvhe(__pkvm_iommu_rk_enable, iommu_id);
}
EXPORT_SYMBOL_GPL(pkvm_iommu_rk_enable);

int pkvm_iommu_rk_disable(unsigned int iommu_id)
{
	return kvm_call_hyp_nvhe(__pkvm_iommu_rk_disable, iommu_id);
}
EXPORT_SYMBOL_GPL(pkvm_iommu_rk_disable);
