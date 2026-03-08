// SPDX-License-Identifier: GPL-2.0-only
/*
 * AArch64-specific system calls implementation
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Catalin Marinas <catalin.marinas@arm.com>
 */

#include "linux/gfp.h"
#include "linux/iommu.h"
#include "linux/ip.h"
#include "linux/module.h"
#include "linux/platform_device.h"
#include "linux/types.h"
#include <linux/compiler.h>
#include <linux/device/bus.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/kvm_host.h>
#include <linux/kmod.h>

#include <asm/cpufeature.h>
#include <asm/syscall.h>

#include <linux/arm-smccc.h>
#include <kvm/arm_hypercalls.h>
#include "linux/pkvm-rockchip-iommu.h"

SYSCALL_DEFINE6(mmap, unsigned long, addr, unsigned long, len, unsigned long,
		prot, unsigned long, flags, unsigned long, fd, unsigned long,
		off)
{
	if (offset_in_page(off) != 0)
		return -EINVAL;

	return ksys_mmap_pgoff(addr, len, prot, flags, fd, off >> PAGE_SHIFT);
}

SYSCALL_DEFINE1(arm64_personality, unsigned int, personality)
{
	if (personality(personality) == PER_LINUX32 &&
	    !system_supports_32bit_el0())
		return -EINVAL;
	return ksys_personality(personality);
}
#ifdef u64
#define u64 unsigned long long
#endif

#ifdef u32
#define u32 unsigned int
#endif

SYSCALL_DEFINE4(view_stage2_pt, phys_addr_t, phys_l, phys_addr_t, phys_r, int,
		vm_handle, u64 __user *, user_pool)
{
#define cap (1 << 15)
	struct arm_smccc_res res;
	void *pool;
	u64 bytes;
	u64 i, j;
	if (check_mul_overflow((u64)cap, (u64)(4 * sizeof(u64)), (u64 *)&bytes))
		return -EINVAL;

	pool = kmalloc(bytes, GFP_KERNEL);
	if (!pool)
		return -ENOMEM;

	unsigned long start = (unsigned long)pool;
	unsigned long end = start + bytes;
	unsigned long cur = start & PAGE_MASK;
	u64 nr_pages = DIV_ROUND_UP(end - cur, PAGE_SIZE);
	int ret = 0;

	u64 *pfn_list = kmalloc(nr_pages * sizeof(u64), GFP_KERNEL);
	if (!pfn_list) {
		ret = -ENOMEM;
		goto free_pool;
	}

	int pages_to_unshare = 0;

	for (i = 0; i < nr_pages; i++, cur += PAGE_SIZE) {
		struct page *pg = is_vmalloc_addr((void *)cur) ?
					  vmalloc_to_page((void *)cur) :
					  virt_to_page((void *)cur);
		pfn_list[i] = page_to_pfn(pg);
		arm_smccc_hvc(
			KVM_HOST_SMCCC_ID(
				__KVM_HOST_SMCCC_FUNC___pkvm_host_share_hyp),
			pfn_list[i], 0, 0, 0, 0, 0, 0, &res);
		if (res.a0) {
			ret = -EFAULT;
			goto out;
		}
		pages_to_unshare = i + 1;
	}

	arm_smccc_hvc(
		KVM_HOST_SMCCC_ID(__KVM_HOST_SMCCC_FUNC___pkvm_view_stage2_pt),
		(unsigned long)pool, cap, phys_l, phys_r, vm_handle, 0, 0,
		&res);

	ret = res.a1;
	printk("syscall_view_stage2_pt : res.a0 = %lld, res.a1 = %lld\n",
	       res.a0, res.a1);

	if (res.a0) {
		ret = res.a0;
		goto out;
	}

	if (copy_to_user(user_pool, (u64 *)pool, cap * 4 * sizeof(u64))) {
		ret = -EFAULT;
		goto out;
	}
out:
	for (i = 0; i < pages_to_unshare; i++) {
		arm_smccc_hvc(
			KVM_HOST_SMCCC_ID(
				__KVM_HOST_SMCCC_FUNC___pkvm_host_unshare_hyp),
			pfn_list[i], 0, 0, 0, 0, 0, 0, &res);
	}
	kfree(pfn_list);
free_pool:
	kfree(pool);
	return ret;
#undef cap
}

SYSCALL_DEFINE1(stage2_pt_count, int, vm_handle)
{
	struct arm_smccc_res res;
	arm_smccc_hvc(
		KVM_HOST_SMCCC_ID(__KVM_HOST_SMCCC_FUNC___pkvm_stage2_pt_count),
		vm_handle, 0, 0, 0, 0, 0, 0, &res);
	return res.a1;
}

SYSCALL_DEFINE1(get_shadow_handles, unsigned int __user *, shadow_handles)
{
	struct arm_smccc_res res;
	u32 *pool;
	u64 bytes;
	size_t i, j;
	int ret = 0;
	u32 cap = 1 << 10;
	if (check_mul_overflow(cap, (u32)sizeof(u32), (u32 *)&bytes))
		return -EINVAL;
	pool = kmalloc(bytes, GFP_KERNEL);

	if (!pool) {
		return -ENOMEM;
	}

	unsigned long start = (unsigned long)pool;
	unsigned long end = start + bytes;
	unsigned long cur = start & PAGE_MASK;
	u64 nr_pages = DIV_ROUND_UP(end - cur, PAGE_SIZE);
	u64 ans;

	u64 *pfn_list = kmalloc(nr_pages * sizeof(u64), GFP_KERNEL);
	if (!pfn_list) {
		ret = -ENOMEM;
		goto free_pool;
	}

	int pages_to_unshare = 0;
	for (i = 0; i < nr_pages; i++, cur += PAGE_SIZE) {
		struct page *pg = is_vmalloc_addr((void *)cur) ?
					  vmalloc_to_page((void *)cur) :
					  virt_to_page((void *)cur);
		pfn_list[i] = page_to_pfn(pg);
		arm_smccc_hvc(
			KVM_HOST_SMCCC_ID(
				__KVM_HOST_SMCCC_FUNC___pkvm_host_share_hyp),
			pfn_list[i], 0, 0, 0, 0, 0, 0, &res);
		if (res.a0) {
			ret = -EFAULT;
			goto out;
		}
		pages_to_unshare = i + 1;
	}

	arm_smccc_hvc(KVM_HOST_SMCCC_ID(
			      __KVM_HOST_SMCCC_FUNC___pkvm_get_shadow_handles),
		      (unsigned long)pool, cap, 0, 0, 0, 0, 0, &res);
	printk("syscall_get_shadow_handles : res.a0 = %lld, res.a1 = %lld\n",
	       res.a0, res.a1);
	ret = res.a1;
	if (res.a0) {
		printk("syscall_get_shadow_handles error : res.a0 = %lld\n",
		       res.a0);
		ret = res.a0;
		goto out;
	}
	if (copy_to_user(shadow_handles, pool, ret * sizeof(u32))) {
		ret = -EFAULT;
		goto out;
	}
out:
	for (i = 0; i < nr_pages; i++) {
		arm_smccc_hvc(
			KVM_HOST_SMCCC_ID(
				__KVM_HOST_SMCCC_FUNC___pkvm_host_unshare_hyp),
			pfn_list[i], 0, 0, 0, 0, 0, 0, &res);
	}
	kfree(pfn_list);
free_pool:
	kfree(pool);
	printk("syscall get_shadow_handles returning %d\n", ret);
	return ret;
}

static int dev_count;
static typeof(rk_iommu_domain_id_get) *rk_iommu_domain_id_fn;
static int printk_devname(struct device *dev, void *data)
{
	struct iommu_domain *domain;
	int domain_id;
	domain = iommu_get_domain_for_dev(dev);
	if (!domain)
		return 0;
	dev_count++;
	printk("ls_dev: %s, ", dev_name(dev));
	domain_id = rk_iommu_domain_id_fn(domain);
	if (domain_id < 0) {
		printk("not a rk_iommu_domain\n");
	} else {
		printk("domain_id = %d\n", domain_id);
	}
	return 0;
}
#define VDEV_MAX 50
struct iommu_domain *domains[VDEV_MAX];
static int domains_count = 0;
SYSCALL_DEFINE0(ls_devices)
{
	int ret, i;
	dev_count = 0;
	rk_iommu_domain_id_fn = symbol_get(rk_iommu_domain_id_get);
	if (!rk_iommu_domain_id_fn) {
		printk("ls_devices: cannot find rk_iommu_domain_id_get, insmod iommu driver first\n");
		return -EINVAL;
	}
	printk("ls_dev: all devices with an IOMMU domain:\n");
	ret = bus_for_each_dev(&platform_bus_type, NULL, NULL, printk_devname);
	if (ret) {
		printk("ls_dev: bus_for_each_dev failed, ret = %d\n", ret);
		return ret;
	}

	for (i = 0; i < VDEV_MAX; i++) {
		if (domains[i]) {
			printk("ls_dev: vdev_%d, domain_id = %d, virtual rk iommu domain",
			       i, rk_iommu_domain_id_fn(domains[i]));
			dev_count++;
		}
	}

	printk("ls_dev: ls devices done, %d devices with an IOMMU domain are found.\n",
	       dev_count);
	symbol_put(rk_iommu_domain_id_get);
	return 0;
}

int find_iommu_domain_by_dev_name(char *name, struct iommu_domain **out_domain)
{
	struct device *dev;
	struct iommu_domain *domain;

	dev = bus_find_device_by_name(&platform_bus_type, NULL, name);
	if (!dev) {
		char pre[6];
		if (strlen(name) >= 6) {
			strncpy(pre, name, 5);
			pre[5] = '\0';
			if (strcmp(pre, "vdev_") == 0) {
				int vdev_id = 0, i;
				for (i = 5; i < strlen(name); i++) {
					vdev_id =
						vdev_id * 10 + (name[i] - '0');
				}
				if (vdev_id >= 0 && vdev_id < VDEV_MAX) {
					domain = domains[vdev_id];
					goto found;
				}
				printk("view_iopt/iopt_map: invalid virtual device id %d\n",
				       vdev_id);
				return -ENODEV;
			}
		}
		printk("view_iopt/iopt_map: cannot find device %s\n", name);
		return -ENODEV;
	} else {
		domain = iommu_get_domain_for_dev(dev);
	}
found:
	if (!domain) {
		printk("view_iopt: device %s has no iommu domain\n", name);
		return -ENODEV;
	}
	*out_domain = domain;
	return 0;
}

SYSCALL_DEFINE4(view_iopt, char __user *, device_name, phys_addr_t, phys_l,
		phys_addr_t, phys_r, u64 __user *, user_pool)
{
#define cap (1 << 15)
	char name[100];
	u64 *pool;
	int ret = 0;
	struct iommu_domain *domain;
	typeof(rk_view_iopt) *view_iopt_fn;

	ret = strncpy_from_user_nofault(name, device_name, 100);
	if (ret < 0) {
		printk("view_iopt/iopt_map: copy from user failed\n");
		return -EFAULT;
	}

	if ((ret = find_iommu_domain_by_dev_name(name, &domain))) {
		return ret;
	}

	view_iopt_fn = symbol_get(rk_view_iopt);
	if (!view_iopt_fn) {
		printk("view_iopt: cannot find rk_view_iopt, insmod iommu driver first\n");
		return -EINVAL;
	}

	unsigned long bytes;
	if (check_mul_overflow((u64)cap, (u64)(3 * sizeof(u64)),
			       (u64 *)&bytes)) {
		printk("view_iopt: cap is too large!\n");
		return -EINVAL;
	}

	pool = kmalloc(bytes, GFP_KERNEL);
	if (!pool) {
		printk("view_iopt: kmalloc failed\n");
		return -ENOMEM;
	}

	unsigned long start = (unsigned long)pool;
	unsigned long end = start + bytes;
	unsigned long cur = start & PAGE_MASK;
	u64 nr_pages = DIV_ROUND_UP(end - cur, PAGE_SIZE);
	int i, j;

	u64 *pfn_list = kmalloc(nr_pages * sizeof(u64), GFP_KERNEL);
	if (!pfn_list) {
		printk("view_iopt: kmalloc pfn_list failed\n");
		kfree(pool);
		return -ENOMEM;
	}

	struct arm_smccc_res res;

	for (i = 0; i < nr_pages; i++, cur += PAGE_SIZE) {
		struct page *pg = is_vmalloc_addr((void *)cur) ?
					  vmalloc_to_page((void *)cur) :
					  virt_to_page((void *)cur);
		pfn_list[i] = page_to_pfn(pg);
		arm_smccc_hvc(
			KVM_HOST_SMCCC_ID(
				__KVM_HOST_SMCCC_FUNC___pkvm_host_share_hyp),
			pfn_list[i], 0, 0, 0, 0, 0, 0, &res);
		if (res.a0) {
			for (j = 0; j <= i; j++)
				arm_smccc_hvc(
					KVM_HOST_SMCCC_ID(
						__KVM_HOST_SMCCC_FUNC___pkvm_host_unshare_hyp),
					pfn_list[j], 0, 0, 0, 0, 0, 0, &res);
			kfree(pfn_list);
			kfree(pool);
			printk("view_iopt: host_share_hyp failed\n");
			return -EFAULT;
		}
	}

	ret = view_iopt_fn(domain, pool, cap, phys_l, phys_r);
	symbol_put(rk_view_iopt);
	if (ret < 0) {
		printk("view_iopt: hypercall view_iopt returned %d\n", ret);
		for (j = 0; j < nr_pages; j++)
			arm_smccc_hvc(
				KVM_HOST_SMCCC_ID(
					__KVM_HOST_SMCCC_FUNC___pkvm_host_unshare_hyp),
				pfn_list[j], 0, 0, 0, 0, 0, 0, &res);
		kfree(pfn_list);
		kfree(pool);
		return ret;
	}

	if (copy_to_user(user_pool, pool, cap * 3 * sizeof(u64))) {
		printk("view_iopt: copy to user failed\n");
		for (j = 0; j < nr_pages; j++)
			arm_smccc_hvc(
				KVM_HOST_SMCCC_ID(
					__KVM_HOST_SMCCC_FUNC___pkvm_host_unshare_hyp),
				pfn_list[j], 0, 0, 0, 0, 0, 0, &res);
		kfree(pfn_list);
		kfree(pool);
		return -EFAULT;
	}
	for (j = 0; j < nr_pages; j++)
		arm_smccc_hvc(
			KVM_HOST_SMCCC_ID(
				__KVM_HOST_SMCCC_FUNC___pkvm_host_unshare_hyp),
			pfn_list[j], 0, 0, 0, 0, 0, 0, &res);
	kfree(pfn_list);
	kfree(pool);
	printk("view_iopt: iopt walk succeeded\n");
	return ret;
#undef cap
}

/*
 * Allocate a new dummy rk_iommu domain and store it in domains[].
 */
SYSCALL_DEFINE0(alloc_domain)
{
	struct iommu_domain *rk_domain = NULL;
	if (domains_count >= VDEV_MAX) {
		printk("alloc_domain: maximum number of virtual rk_iommu domains reached\n");
		return -ENOMEM;
	}

	printk("alloc_domain: allocating a new virtual rk_iommu domain...\n");

	typeof(rk_virtual_iommu_domain_alloc) *domain_alloc_fn;
	domain_alloc_fn = symbol_get(rk_virtual_iommu_domain_alloc);
	if (!domain_alloc_fn) {
		printk("alloc_domain: cannot find rk_virtual_iommu_domain_alloc, insmod iommu driver first\n");
		return -EINVAL;
	}
	rk_domain = domain_alloc_fn();
	symbol_put(rk_virtual_iommu_domain_alloc); 
	domains[domains_count++] = rk_domain;
	printk("alloc_domain: created virtual rk_iommu domain vdev_%d\n",
	       domains_count - 1);
	return domains_count - 1;
}

SYSCALL_DEFINE3(iopt_map, char __user *, device_name, unsigned long, iova,
		phys_addr_t, pa)
{
	char name[100];
	int ret = 0;
	struct iommu_domain *domain;

	ret = strncpy_from_user_nofault(name, device_name, 100);
	if (ret < 0) {
		printk("iopt_map: copy from user failed\n");
		return -EFAULT;
	}
	if ((ret = find_iommu_domain_by_dev_name(name, &domain))) {
		return ret;
	}
	typeof(rk_iopt_map) *rk_iopt_map_fn;
	rk_iopt_map_fn = symbol_get(rk_iopt_map);
	if (!rk_iopt_map_fn) {
		printk("iopt_map: cannot find rk_iopt_map, insmod iommu driver first\n");
		return -EINVAL;
	}

	ret = rk_iopt_map_fn(domain, iova, pa, PAGE_SIZE,
			     IOMMU_READ | IOMMU_WRITE);
	symbol_put(rk_iopt_map);
	printk("iopt_map: rk_iopt_map returned %d\n", ret);
	return ret;
}

asmlinkage long sys_ni_syscall(void);

asmlinkage long __arm64_sys_ni_syscall(const struct pt_regs *__unused)
{
	return sys_ni_syscall();
}

/*
 * Wrappers to pass the pt_regs argument.
 */
#define __arm64_sys_personality __arm64_sys_arm64_personality

#undef __SYSCALL
#define __SYSCALL(nr, sym)                                                     \
	asmlinkage long __arm64_##sym(const struct pt_regs *);
#include <asm/unistd.h>

#undef __SYSCALL
#define __SYSCALL(nr, sym) [nr] = __arm64_##sym,

const syscall_fn_t sys_call_table[__NR_syscalls] = {
	[0 ... __NR_syscalls - 1] = __arm64_sys_ni_syscall,
#include <asm/unistd.h>
};
