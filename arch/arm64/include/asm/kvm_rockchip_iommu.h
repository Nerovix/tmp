/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ARM64_KVM_ROCKCHIP_IOMMU_H__
#define __ARM64_KVM_ROCKCHIP_IOMMU_H__

/* For now, only support up to 256 domains and iommus. */
#define RK_IOMMU_MAX_DOMAINS (1 << 8)
#define RK_IOMMU_MAX_IOMMUS  (1 << 8)

struct hyp_rk_iommu_info {
    void *mem_pool_host_va;
    unsigned int mem_pool_num_pages;
	unsigned int iommu_id;
	bool iommu_skip_read;
	bool iommu_shootdown_entire;
};

#endif /* __ARM64_KVM_ROCKCHIP_IOMMU_H__ */
