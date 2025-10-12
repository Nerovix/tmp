#ifndef _PKVM_ROCKCHIP_IOMMU_H_
#define _PKVM_ROCKCHIP_IOMMU_H_

#include <linux/errno.h>
#include <linux/module.h>
#define u64 unsigned long long
int rk_view_iopt(struct iommu_domain *domain, u64 *pool, int cap);
#endif /* _PKVM_ROCKCHIP_IOMMU_H_ */