#ifndef _PKVM_ROCKCHIP_IOMMU_H_
#define _PKVM_ROCKCHIP_IOMMU_H_

#include <linux/errno.h>
#include <linux/module.h>
#define u64 unsigned long long
int rk_view_iopt(struct iommu_domain *domain, u64 *pool, int cap,
		 phys_addr_t phys_l, phys_addr_t phys_r);
int rk_iommu_domain_id_get(struct iommu_domain *dom);
struct iommu_domain *rk_virtual_iommu_domain_alloc(void);
int rk_iopt_map(struct iommu_domain *domain, unsigned long iova, phys_addr_t pa,
		size_t size, int prot);
#endif /* _PKVM_ROCKCHIP_IOMMU_H_ */