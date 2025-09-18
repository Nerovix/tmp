// SPDX-License-Identifier: GPL-2.0-only
/*
 * IOMMU API for Rockchip
 *
 * Module Authors:	Simon Xue <xxm@rock-chips.com>
 *			Daniel Kurtz <djkurtz@chromium.org>
 */

#include <linux/clk.h>
#include <linux/compiler.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dma-iommu.h>
#include <linux/dma-mapping.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/iommu.h>
#include <linux/iopoll.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/of.h>
#include <linux/of_iommu.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/kvm_host.h>
#include <linux/idr.h>
#include <soc/rockchip/rockchip_iommu.h>

#include <asm/kvm_rockchip_iommu.h>

 /*
  * Support mapping any size that fits in one page table:
  *   4 KiB to 4 MiB
  */
#define RK_IOMMU_PGSIZE_BITMAP 0x007ff000

static DEFINE_IDA(rk_iommu_domain_ida);
static DEFINE_IDA(rk_iommu_ida);

struct rk_iommu_domain {
	struct list_head iommus; /* attached iommus */
	spinlock_t iommus_lock; /* lock for iommus list */
	struct list_head node; /* entry in hyp_rk_iommu.domains */
	bool shootdown_entire;
	unsigned int id;

	struct iommu_domain domain;
};

struct rockchip_iommu_data {
	u32 version;
};

struct rk_iommu {
	struct device *dev;
	struct list_head domains; /* attached domains */
	spinlock_t domains_lock; /* lock for iommus list */
	void __iomem **bases;
	int num_mmu;
	int num_irq;
	struct clk_bulk_data *clocks;
	int num_clocks;
	bool skip_read; /* rk3126/rk3128 can't read vop iommu registers */
	bool dlr_disable; /* avoid access iommu when runtime ops called */
	bool master_handle_irq;
	struct iommu_device iommu;
	struct list_head node; /* entry in rk_iommu_domain.iommus */
	struct iommu_group *group;
	u32 version;
	bool shootdown_entire;
	bool iommu_enabled;
	unsigned int id;
};

struct rk_iommudata {
	struct device_link *link; /* runtime PM link from IOMMU to master */
	struct rk_iommu *iommu;
	bool defer_attach;
};

static struct device *dma_dev;
static struct rk_iommu *rk_iommu_from_dev(struct device *dev);

static struct rk_iommu_domain *to_rk_domain(struct iommu_domain *dom)
{
	return container_of(dom, struct rk_iommu_domain, domain);
}

void __iomem *pkvm_rockchip_get_iommu_base(struct device *master_dev, int idx)
{
	struct rk_iommu *iommu = rk_iommu_from_dev(master_dev);

	return iommu->bases[idx];
}
EXPORT_SYMBOL_GPL(pkvm_rockchip_get_iommu_base);

static irqreturn_t rk_iommu_irq(int irq, void *dev_id)
{
	struct rk_iommu *iommu = dev_id;
	irqreturn_t ret = IRQ_NONE;
	int err;

	err = pm_runtime_get_if_in_use(iommu->dev);
	if (WARN_ON_ONCE(err <= 0))
		return ret;

	if (WARN_ON(clk_bulk_enable(iommu->num_clocks, iommu->clocks)))
		goto out;

	clk_bulk_disable(iommu->num_clocks, iommu->clocks);

out:
	pm_runtime_put(iommu->dev);
	return ret;
}

static phys_addr_t rk_iommu_iova_to_phys_v2(struct iommu_domain *domain,
					    dma_addr_t iova)
{
	struct rk_iommu_domain *rk_domain = to_rk_domain(domain);

	return pkvm_iommu_iova_to_phys(rk_domain->id, (unsigned long)iova);
}

static int rk_iommu_map_v2(struct iommu_domain *domain, unsigned long _iova,
			phys_addr_t paddr, size_t size, int prot, gfp_t gfp)
{
	struct rk_iommu_domain *rk_domain = to_rk_domain(domain);
	dma_addr_t iova = (dma_addr_t)_iova;

	return pkvm_iommu_map(rk_domain->id, (unsigned long)iova, paddr, size, prot);
}

static size_t rk_iommu_unmap_v2(struct iommu_domain *domain, unsigned long _iova,
				size_t size, struct iommu_iotlb_gather *gather)
{
	struct rk_iommu_domain *rk_domain = to_rk_domain(domain);
	dma_addr_t iova = (dma_addr_t)_iova;

	return pkvm_iommu_unmap(rk_domain->id, (unsigned long)iova, size);
}

static void rk_iommu_flush_tlb_all(struct iommu_domain *domain)
{
	struct rk_iommu_domain *rk_domain = to_rk_domain(domain);
	struct list_head *pos;
	unsigned long flags;
	int i;

	spin_lock_irqsave(&rk_domain->iommus_lock, flags);
	list_for_each(pos, &rk_domain->iommus) {
		struct rk_iommu *iommu;
		int ret;

		iommu = list_entry(pos, struct rk_iommu, node);

		ret = pm_runtime_get_if_in_use(iommu->dev);
		if (WARN_ON_ONCE(ret < 0))
			continue;
		if (ret) {
			WARN_ON(clk_bulk_enable(iommu->num_clocks, iommu->clocks));
			pkvm_iommu_flush_iotlb_all(iommu->id);
			clk_bulk_disable(iommu->num_clocks, iommu->clocks);
			pm_runtime_put(iommu->dev);
		}
	}
	spin_unlock_irqrestore(&rk_domain->iommus_lock, flags);
}

static struct rk_iommu *rk_iommu_from_dev(struct device *dev)
{
	struct rk_iommudata *data = dev_iommu_priv_get(dev);

	return data ? data->iommu : NULL;
}

/* Must be called with iommu powered on and attached */
static void rk_iommu_disable(struct rk_iommu *iommu)
{
	/* Ignore error while disabling, just keep going */
	WARN_ON(clk_bulk_enable(iommu->num_clocks, iommu->clocks));
	pkvm_iommu_rk_disable(iommu->id);
	clk_bulk_disable(iommu->num_clocks, iommu->clocks);

	iommu->iommu_enabled = false;
}

int pkvm_rockchip_iommu_disable(struct device *dev)
{
	struct rk_iommu *iommu;

	iommu = rk_iommu_from_dev(dev);
	if (!iommu)
		return -ENODEV;

	rk_iommu_disable(iommu);

	return 0;
}
EXPORT_SYMBOL(pkvm_rockchip_iommu_disable);

/* Must be called with iommu powered on and attached */
static int rk_iommu_enable(struct rk_iommu *iommu)
{
	int ret;

	ret = clk_bulk_enable(iommu->num_clocks, iommu->clocks);
	if (ret)
		return ret;

	ret = pkvm_iommu_rk_enable(iommu->id);

	clk_bulk_disable(iommu->num_clocks, iommu->clocks);

	if (!ret)
		iommu->iommu_enabled = true;

	return ret;
}

int pkvm_rockchip_iommu_enable(struct device *dev)
{
	struct rk_iommu *iommu;

	iommu = rk_iommu_from_dev(dev);
	if (!iommu)
		return -ENODEV;

	return rk_iommu_enable(iommu);
}
EXPORT_SYMBOL(pkvm_rockchip_iommu_enable);

bool pkvm_rockchip_iommu_is_enabled(struct device *dev)
{
	struct rk_iommu *iommu;

	iommu = rk_iommu_from_dev(dev);
	if (!iommu)
		return false;

	return iommu->iommu_enabled;
}
EXPORT_SYMBOL(pkvm_rockchip_iommu_is_enabled);

static void rk_iommu_detach_device(struct iommu_domain *domain,
				   struct device *dev)
{
	struct rk_iommu *iommu;
	struct rk_iommu_domain *rk_domain = to_rk_domain(domain);
	unsigned long flags;
	int ret;

	/* Allow 'virtual devices' (eg drm) to detach from domain */
	iommu = rk_iommu_from_dev(dev);
	if (!iommu)
		return;

	dev_dbg(dev, "Detaching from iommu domain\n");

	pkvm_iommu_detach_dev(iommu->id, rk_domain->id);

	spin_lock_irqsave(&iommu->domains_lock, flags);
	list_del_init(&rk_domain->node);
	spin_unlock_irqrestore(&iommu->domains_lock, flags);

	spin_lock_irqsave(&rk_domain->iommus_lock, flags);
	list_del_init(&iommu->node);
	spin_unlock_irqrestore(&rk_domain->iommus_lock, flags);

	ret = pm_runtime_get_if_in_use(iommu->dev);
	WARN_ON_ONCE(ret < 0);
	if (ret > 0) {
		rk_iommu_disable(iommu);
		pm_runtime_put(iommu->dev);
	}
}

static int rk_iommu_attach_device(struct iommu_domain *domain,
		struct device *dev)
{
	struct rk_iommu *iommu;
	struct rk_iommu *cur_iommu;
	struct rk_iommu_domain *rk_domain = to_rk_domain(domain);
	bool skip_attach = false;
	unsigned long flags;
	int ret;

	/*
	 * Allow 'virtual devices' (e.g., drm) to attach to domain.
	 * Such a device does not belong to an iommu group.
	 */
	iommu = rk_iommu_from_dev(dev);
	if (!iommu)
		return 0;

	dev_dbg(dev, "Attaching to iommu domain\n");

	ret = pkvm_iommu_attach_dev(iommu->id, rk_domain->id);
	if (ret)
		return ret;

	/* Attach NULL for disable iommu */
	if (!domain)
		return 0;

	spin_lock_irqsave(&rk_domain->iommus_lock, flags);

	/* Check for duplicate iommu in domain. */
	list_for_each_entry(cur_iommu, &rk_domain->iommus, node) {
		if (cur_iommu == iommu) {
			skip_attach = true;
			break;
		}
	}

	if (!skip_attach) {
		list_add_tail(&iommu->node, &rk_domain->iommus);
	}

	spin_unlock_irqrestore(&rk_domain->iommus_lock, flags);

	spin_lock_irqsave(&iommu->domains_lock, flags);

	if (!skip_attach) {
		list_add_tail(&rk_domain->node, &iommu->domains);
	}

	spin_unlock_irqrestore(&iommu->domains_lock, flags);

	rk_domain->shootdown_entire = iommu->shootdown_entire;

	ret = pm_runtime_get_if_in_use(iommu->dev);
	if (!ret || WARN_ON_ONCE(ret < 0))
		return 0;

	ret = rk_iommu_enable(iommu);
	if (ret)
		rk_iommu_detach_device(&rk_domain->domain, dev);

	pm_runtime_put(iommu->dev);

	return ret;
}

static struct iommu_domain *rk_iommu_domain_alloc(unsigned type)
{
	struct rk_iommu_domain *rk_domain;
	int ret;

	if (type != IOMMU_DOMAIN_UNMANAGED && type != IOMMU_DOMAIN_DMA)
		return NULL;

	if (!dma_dev)
		return NULL;

	rk_domain = kzalloc(sizeof(*rk_domain), GFP_KERNEL);
	if (!rk_domain)
		return NULL;

	if (type == IOMMU_DOMAIN_DMA &&
	    iommu_get_dma_cookie(&rk_domain->domain))
		goto err_free_domain;

	rk_domain->id = ida_alloc_range(&rk_iommu_domain_ida, 0, RK_IOMMU_MAX_DOMAINS - 1, GFP_KERNEL);

	ret = pkvm_iommu_alloc_domain(rk_domain->id, 0);
	if (ret)
		goto err_put_cookie;

	spin_lock_init(&rk_domain->iommus_lock);
	INIT_LIST_HEAD(&rk_domain->iommus);

	rk_domain->domain.geometry.aperture_start = 0;
	rk_domain->domain.geometry.aperture_end   = DMA_BIT_MASK(32);
	rk_domain->domain.geometry.force_aperture = true;

	return &rk_domain->domain;

err_put_cookie:
	if (type == IOMMU_DOMAIN_DMA)
		iommu_put_dma_cookie(&rk_domain->domain);
err_free_domain:
	kfree(rk_domain);

	return NULL;
}

static void rk_iommu_domain_free_v2(struct iommu_domain *domain)
{
	struct rk_iommu_domain *rk_domain = to_rk_domain(domain);
	int i;

	WARN_ON(!list_empty(&rk_domain->iommus));

	pkvm_iommu_free_domain(rk_domain->id);

	kfree(rk_domain);
}

static struct iommu_device *rk_iommu_probe_device(struct device *dev)
{
	struct rk_iommudata *data;
	struct rk_iommu *iommu;

	data = dev_iommu_priv_get(dev);
	if (!data)
		return ERR_PTR(-ENODEV);

	iommu = rk_iommu_from_dev(dev);

	data->link = device_link_add(dev, iommu->dev,
				     DL_FLAG_STATELESS | DL_FLAG_PM_RUNTIME);

	data->defer_attach = false;

	/* set max segment size for dev, needed for single chunk map */
	if (!dev->dma_parms)
		dev->dma_parms = kzalloc(sizeof(*dev->dma_parms), GFP_KERNEL);
	if (!dev->dma_parms)
		return ERR_PTR(-ENOMEM);

	dma_set_max_seg_size(dev, DMA_BIT_MASK(32));

	return &iommu->iommu;
}

static void rk_iommu_release_device(struct device *dev)
{
	struct rk_iommudata *data = dev_iommu_priv_get(dev);

	device_link_del(data->link);
}

static struct iommu_group *rk_iommu_device_group(struct device *dev)
{
	struct rk_iommu *iommu;

	iommu = rk_iommu_from_dev(dev);

	return iommu_group_ref_get(iommu->group);
}

static bool rk_iommu_is_attach_deferred(struct iommu_domain *domain,
					struct device *dev)
{
	struct rk_iommudata *data = dev_iommu_priv_get(dev);

	return data->defer_attach;
}

static int rk_iommu_of_xlate(struct device *dev,
			     struct of_phandle_args *args)
{
	struct platform_device *iommu_dev;
	struct rk_iommudata *data;

	data = devm_kzalloc(dma_dev, sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	iommu_dev = of_find_device_by_node(args->np);

	data->iommu = platform_get_drvdata(iommu_dev);

	if (strstr(dev_name(dev), "vop"))
		data->defer_attach = true;

	dev_iommu_priv_set(dev, data);

	platform_device_put(iommu_dev);

	return 0;
}

static struct iommu_ops rk_iommu_ops_v2 = {
	.domain_alloc = rk_iommu_domain_alloc,
	.domain_free = rk_iommu_domain_free_v2,
	.attach_dev = rk_iommu_attach_device,
	.detach_dev = rk_iommu_detach_device,
	.map = rk_iommu_map_v2,
	.unmap = rk_iommu_unmap_v2,
	.flush_iotlb_all = rk_iommu_flush_tlb_all,
	.probe_device = rk_iommu_probe_device,
	.release_device = rk_iommu_release_device,
	.iova_to_phys = rk_iommu_iova_to_phys_v2,
	.is_attach_deferred = rk_iommu_is_attach_deferred,
	.device_group = rk_iommu_device_group,
	.pgsize_bitmap = RK_IOMMU_PGSIZE_BITMAP,
	.of_xlate = rk_iommu_of_xlate,
};

static const struct rockchip_iommu_data iommu_data_v2 = {
	.version = 0x2,
};

static const struct of_device_id rk_iommu_dt_ids[] = {
	{
		.compatible = "rockchip,iommu-v2",
		.data = &iommu_data_v2,
	},
	{ /* sentinel */ }
};

static int rk_iommu_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct rk_iommu *iommu;
	struct resource *res;
	int num_res = pdev->num_resources;
	int err, i;
	const struct of_device_id *match;
	struct rockchip_iommu_data *data;
	struct hyp_rk_iommu_info *info;

	iommu = devm_kzalloc(dev, sizeof(*iommu), GFP_KERNEL);
	if (!iommu)
		return -ENOMEM;

	match = of_match_device(rk_iommu_dt_ids, dev);
	if (!match)
		return -EINVAL;

	data = (struct rockchip_iommu_data *)match->data;
	iommu->version = data->version;
	dev_info(dev, "version = %x\n", iommu->version);

	platform_set_drvdata(pdev, iommu);
	iommu->dev = dev;
	iommu->num_mmu = 0;

	iommu->bases = devm_kcalloc(dev, num_res, sizeof(*iommu->bases),
				    GFP_KERNEL);
	if (!iommu->bases)
		return -ENOMEM;

	for (i = 0; i < num_res; i++) {
		res = platform_get_resource(pdev, IORESOURCE_MEM, i);
		if (!res)
			continue;
		iommu->bases[i] = devm_ioremap_resource(&pdev->dev, res);
		if (IS_ERR(iommu->bases[i]))
			continue;
		iommu->num_mmu++;
	}
	if (iommu->num_mmu == 0)
		return PTR_ERR(iommu->bases[0]);

	iommu->num_irq = platform_irq_count(pdev);
	if (iommu->num_irq < 0)
		return iommu->num_irq;

	iommu->skip_read = device_property_read_bool(dev,
					"rockchip,skip-mmu-read");
	iommu->dlr_disable = device_property_read_bool(dev,
					"rockchip,disable-device-link-resume");
	iommu->shootdown_entire = device_property_read_bool(dev,
					"rockchip,shootdown-entire");
	iommu->master_handle_irq = device_property_read_bool(dev,
					"rockchip,master-handle-irq");

	/*
	 * iommu clocks should be present for all new devices and devicetrees
	 * but there are older devicetrees without clocks out in the wild.
	 * So clocks as optional for the time being.
	 */
	err = devm_clk_bulk_get_all(dev, &iommu->clocks);
	if (err == -ENOENT)
		iommu->num_clocks = 0;
	else if (err < 0)
		return err;
	else
		iommu->num_clocks = err;

	err = clk_bulk_prepare(iommu->num_clocks, iommu->clocks);
	if (err)
		return err;

	iommu->group = iommu_group_alloc();
	if (IS_ERR(iommu->group)) {
		err = PTR_ERR(iommu->group);
		goto err_unprepare_clocks;
	}

	err = iommu_device_sysfs_add(&iommu->iommu, dev, NULL, dev_name(dev));
	if (err)
		goto err_put_group;

	iommu_device_set_ops(&iommu->iommu, &rk_iommu_ops_v2);
	iommu_device_set_fwnode(&iommu->iommu, &dev->of_node->fwnode);

	err = iommu_device_register(&iommu->iommu);
	if (err)
		goto err_remove_sysfs;

	/*
	 * Use the first registered IOMMU device for domain to use with DMA
	 * API, since a domain might not physically correspond to a single
	 * IOMMU device..
	 */
	if (!dma_dev)
		dma_dev = &pdev->dev;

	bus_set_iommu(&platform_bus_type, &rk_iommu_ops_v2);

	pm_runtime_enable(dev);

	if (iommu->skip_read)
		goto skip_request_irq;

	for (i = 0; i < iommu->num_irq; i++) {
		int irq = platform_get_irq(pdev, i);

		if (irq < 0)
			return irq;

		err = devm_request_irq(iommu->dev, irq, rk_iommu_irq,
				       IRQF_SHARED, dev_name(dev), iommu);
		if (err) {
			pm_runtime_disable(dev);
			goto err_unregister_group;
		}
	}

	/* Allocate a page for driver data. */
	BUILD_BUG_ON(sizeof(*info) > PAGE_SIZE);
	info = (struct hyp_rk_iommu_info *)__get_free_page(GFP_ATOMIC | GFP_DMA32);
	if (!info) {
		err = -ENOMEM;
		goto err_unregister_group;
	}

	spin_lock_init(&iommu->domains_lock);
	INIT_LIST_HEAD(&iommu->domains);

	iommu->id = ida_alloc_range(&rk_iommu_ida, 0, RK_IOMMU_MAX_IOMMUS - 1, GFP_KERNEL);
	info->iommu_id = iommu->id;
	info->iommu_skip_read = iommu->skip_read;
	info->iommu_shootdown_entire = iommu->shootdown_entire;

	err = pkvm_iommu_rockchip_iommu_register(dev, NULL, info);
	if (err && err != -ENODEV) {
		dev_err(dev, "could not register: %d\n", err);
		goto err_free_info;
	}

skip_request_irq:
	return 0;
err_free_info:
	free_page(info);
err_unregister_group:
	iommu_device_unregister(&iommu->iommu);
err_remove_sysfs:
	iommu_device_sysfs_remove(&iommu->iommu);
err_put_group:
	iommu_group_put(iommu->group);
err_unprepare_clocks:
	clk_bulk_unprepare(iommu->num_clocks, iommu->clocks);
	return err;
}

static void rk_iommu_shutdown(struct platform_device *pdev)
{
	struct rk_iommu *iommu = platform_get_drvdata(pdev);
	int i;

	for (i = 0; i < iommu->num_irq; i++) {
		int irq = platform_get_irq(pdev, i);

		devm_free_irq(iommu->dev, irq, iommu);
	}

	pm_runtime_force_suspend(&pdev->dev);
}

static int __maybe_unused rk_iommu_suspend(struct device *dev)
{
	struct rk_iommu *iommu = dev_get_drvdata(dev);


	if (iommu->dlr_disable)
		return 0;

	rk_iommu_disable(iommu);
	return 0;
}

static int __maybe_unused rk_iommu_resume(struct device *dev)
{
	struct rk_iommu *iommu = dev_get_drvdata(dev);

	if (iommu->dlr_disable)
		return 0;

	return rk_iommu_enable(iommu);
}

static const struct dev_pm_ops rk_iommu_pm_ops = {
	SET_RUNTIME_PM_OPS(rk_iommu_suspend, rk_iommu_resume, NULL)
	SET_SYSTEM_SLEEP_PM_OPS(pm_runtime_force_suspend,
				pm_runtime_force_resume)
};

static struct platform_driver rk_iommu_driver = {
	.probe = rk_iommu_probe,
	.shutdown = rk_iommu_shutdown,
	.driver = {
		   .name = "rk_iommu",
		   .of_match_table = rk_iommu_dt_ids,
		   .pm = &rk_iommu_pm_ops,
		   .suppress_bind_attrs = true,
	},
};

static int __init rk_iommu_init(void)
{
	return platform_driver_register(&rk_iommu_driver);
}
subsys_initcall(rk_iommu_init);

MODULE_DESCRIPTION("IOMMU API for Rockchip");
MODULE_AUTHOR("Simon Xue <xxm@rock-chips.com> and Daniel Kurtz <djkurtz@chromium.org>");
MODULE_ALIAS("platform:rockchip-iommu");
MODULE_LICENSE("GPL v2");
