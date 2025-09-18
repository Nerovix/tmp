/*
 * Rockchip IOMMU Dispatcher
 *
 * A hack to compile the original (unprotected) Rockchip IOMMU driver
 * and pKVM Rockchip IOMMU driver at the same time.
 */

#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <soc/rockchip/rockchip_iommu.h>

static int (*rockchip_iommu_enable_fn)(struct device *dev);
static int (*rockchip_iommu_disable_fn)(struct device *dev);
static int (*rockchip_pagefault_done_fn)(struct device *master_dev);
static void __iomem *(*rockchip_get_iommu_base_fn)(struct device *master_dev, int idx);
static bool (*rockchip_iommu_is_enabled_fn)(struct device *dev);

int rockchip_iommu_enable(struct device *dev)
{
/* NOTE: The pKVM driver function will be called if both modules are loaded. */
#if IS_ENABLED(CONFIG_PKVM_ROCKCHIP_IOMMU)
	if (!rockchip_iommu_enable_fn)
		rockchip_iommu_enable_fn = symbol_get(pkvm_rockchip_iommu_enable);
#endif
#if IS_ENABLED(CONFIG_ROCKCHIP_IOMMU)
	if (!rockchip_iommu_enable_fn)
		rockchip_iommu_enable_fn = symbol_get(unprot_rockchip_iommu_enable);	
#endif

	if (rockchip_iommu_enable_fn)
		return rockchip_iommu_enable_fn(dev);

	return -ENODEV;
}
EXPORT_SYMBOL(rockchip_iommu_enable);

int rockchip_iommu_disable(struct device *dev)
{
#if IS_ENABLED(CONFIG_PKVM_ROCKCHIP_IOMMU)
	if (!rockchip_iommu_disable_fn)
		rockchip_iommu_disable_fn = symbol_get(pkvm_rockchip_iommu_disable);
#endif
#if IS_ENABLED(CONFIG_ROCKCHIP_IOMMU)
	if (!rockchip_iommu_disable_fn)
		rockchip_iommu_disable_fn = symbol_get(unprot_rockchip_iommu_disable);
#endif

	if (rockchip_iommu_disable_fn)
		return rockchip_iommu_disable_fn(dev);

	return -ENODEV;
}
EXPORT_SYMBOL(rockchip_iommu_disable);

int rockchip_pagefault_done(struct device *master_dev)
{
#if IS_ENABLED(CONFIG_ROCKCHIP_IOMMU)
	if (!rockchip_pagefault_done_fn)
		rockchip_pagefault_done_fn = symbol_get(unprot_rockchip_pagefault_done);
#endif

	if (rockchip_pagefault_done_fn)
		return rockchip_pagefault_done_fn(master_dev);

	return 0;

}
EXPORT_SYMBOL(rockchip_pagefault_done);

void __iomem *rockchip_get_iommu_base(struct device *master_dev, int idx)
{
#if IS_ENABLED(CONFIG_PKVM_ROCKCHIP_IOMMU)
	if (!rockchip_get_iommu_base_fn)
		rockchip_get_iommu_base_fn = symbol_get(pkvm_rockchip_get_iommu_base);
#endif
#if IS_ENABLED(CONFIG_ROCKCHIP_IOMMU)
	if (!rockchip_get_iommu_base_fn)
		rockchip_get_iommu_base_fn = symbol_get(unprot_rockchip_get_iommu_base);
#endif

	if (rockchip_get_iommu_base_fn)
		return rockchip_get_iommu_base_fn(master_dev, idx);

	return NULL;
}
EXPORT_SYMBOL(rockchip_get_iommu_base);

bool rockchip_iommu_is_enabled(struct device *dev)
{
#if IS_ENABLED(CONFIG_PKVM_ROCKCHIP_IOMMU)
	if (!rockchip_iommu_is_enabled_fn)
		rockchip_iommu_is_enabled_fn = symbol_get(pkvm_rockchip_iommu_is_enabled);
#endif
#if IS_ENABLED(CONFIG_ROCKCHIP_IOMMU)
	if (!rockchip_iommu_is_enabled_fn)
		rockchip_iommu_is_enabled_fn = symbol_get(unprot_rockchip_iommu_is_enabled);
#endif

	if (rockchip_iommu_is_enabled_fn)
		return rockchip_iommu_is_enabled_fn(dev);

	return false;
}
EXPORT_SYMBOL(rockchip_iommu_is_enabled);

static int __init rockchip_iommu_dispatcher_init(void)
{
	rockchip_iommu_enable_fn = NULL;
	rockchip_iommu_disable_fn = NULL;
	rockchip_pagefault_done_fn = NULL;
	rockchip_get_iommu_base_fn = NULL;
	rockchip_iommu_is_enabled_fn = NULL;

	pr_info("rockchip-iommu-dispatcher: Rockchip IOMMU driver dispatcher enabled!\n");
	return 0;
}
module_init(rockchip_iommu_dispatcher_init);

static void __exit rockchip_iommu_dispatcher_exit(void)
{
	/* TODO: Some of these symbols could still be NULL. */
#if IS_ENABLED(CONFIG_PKVM_ROCKCHIP_IOMMU)
	if (rockchip_iommu_enable_fn) symbol_put(pkvm_rockchip_iommu_enable);
	if (rockchip_iommu_disable_fn) symbol_put(pkvm_rockchip_iommu_disable);
	if (rockchip_get_iommu_base_fn) symbol_put(pkvm_rockchip_get_iommu_base);
	if (rockchip_iommu_is_enabled_fn) symbol_put(pkvm_rockchip_iommu_is_enabled);
#endif
#if IS_ENABLED(CONFIG_ROCKCHIP_IOMMU)
	if (rockchip_iommu_enable_fn) symbol_put(unprot_rockchip_iommu_enable);
	if (rockchip_iommu_disable_fn) symbol_put(unprot_rockchip_iommu_disable);
	if (rockchip_pagefault_done_fn) symbol_put(unprot_rockchip_pagefault_done);
	if (rockchip_get_iommu_base_fn) symbol_put(unprot_rockchip_get_iommu_base);
	if (rockchip_iommu_is_enabled_fn) symbol_put(unprot_rockchip_iommu_is_enabled);
#endif

	rockchip_iommu_enable_fn = NULL;
	rockchip_iommu_disable_fn = NULL;
	rockchip_pagefault_done_fn = NULL;
	rockchip_get_iommu_base_fn = NULL;
	rockchip_iommu_is_enabled_fn = NULL;

	pr_info("rockchip-iommu-dispatcher: Rockchip IOMMU driver dispatcher disabled!\n");
}
module_exit(rockchip_iommu_dispatcher_exit);

MODULE_DESCRIPTION("Rockchip IOMMU Dispatcher");
MODULE_LICENSE("GPL v2");
