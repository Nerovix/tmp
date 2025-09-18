/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Rockchip Electronics Co., Ltd
 */
#ifndef __SOC_ROCKCHIP_IOMMU_H
#define __SOC_ROCKCHIP_IOMMU_H

struct device;

int rockchip_iommu_enable(struct device *dev);
int rockchip_iommu_disable(struct device *dev);
int rockchip_pagefault_done(struct device *master_dev);
void __iomem *rockchip_get_iommu_base(struct device *master_dev, int idx);
bool rockchip_iommu_is_enabled(struct device *dev);

extern int pkvm_rockchip_iommu_enable(struct device *dev);
extern int pkvm_rockchip_iommu_disable(struct device *dev);
extern void __iomem *pkvm_rockchip_get_iommu_base(struct device *master_dev, int idx);
extern bool pkvm_rockchip_iommu_is_enabled(struct device *dev);

int unprot_rockchip_iommu_enable(struct device *dev);
int unprot_rockchip_iommu_disable(struct device *dev);
int unprot_rockchip_pagefault_done(struct device *master_dev);
void __iomem *unprot_rockchip_get_iommu_base(struct device *master_dev, int idx);
bool unprot_rockchip_iommu_is_enabled(struct device *dev);

#endif
