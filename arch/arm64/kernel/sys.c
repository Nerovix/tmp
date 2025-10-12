// SPDX-License-Identifier: GPL-2.0-only
/*
 * AArch64-specific system calls implementation
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Catalin Marinas <catalin.marinas@arm.com>
 */

#include "linux/iommu.h"
#include "linux/platform_device.h"
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

#define u64 unsigned long long
#define u32 unsigned int

SYSCALL_DEFINE4(view_stage2_pt, u64, ipa_l, u64, ipa_r, int, vm_handle,
		u64 __user *, user_pool)
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
	u64 ans;

	u64 *pfn_list = kmalloc(nr_pages * sizeof(u64), GFP_KERNEL);
	if (!pfn_list) {
		kfree(pool);
		return -ENOMEM;
	}

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
			return -EFAULT;
		}
	}

	arm_smccc_hvc(
		KVM_HOST_SMCCC_ID(__KVM_HOST_SMCCC_FUNC___pkvm_view_stage2_pt),
		(unsigned long)pool, cap, ipa_l, ipa_r, vm_handle, 0, 0, &res);

	ans = res.a1;
	printk("syscall_view_stage2_pt : res.a0 = %lld, res.a1 = %lld\n",
	       res.a0, res.a1);

	if (res.a0) {
		for (j = 0; j < nr_pages; j++)
			arm_smccc_hvc(
				KVM_HOST_SMCCC_ID(
					__KVM_HOST_SMCCC_FUNC___pkvm_host_unshare_hyp),
				pfn_list[j], 0, 0, 0, 0, 0, 0, &res);
		kfree(pfn_list);
		kfree(pool);
		return res.a0;
	}

	for (i = 0; i < nr_pages; i++) {
		arm_smccc_hvc(
			KVM_HOST_SMCCC_ID(
				__KVM_HOST_SMCCC_FUNC___pkvm_host_unshare_hyp),
			pfn_list[i], 0, 0, 0, 0, 0, 0, &res);
	}
	kfree(pfn_list);
	if (copy_to_user(user_pool, (u64 *)pool, cap * 4 * sizeof(u64))) {
		kfree(pool);
		return -EFAULT;
	}
	kfree(pool);
	return ans;
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
	u32 cap = 1 << 10;
	if (check_mul_overflow(cap, (u32)sizeof(u32), (u32 *)&bytes))
		return -EINVAL;
	pool = kmalloc(bytes, GFP_KERNEL);

	if (!pool)
		return -ENOMEM;

	unsigned long start = (unsigned long)pool;
	unsigned long end = start + bytes;
	unsigned long cur = start & PAGE_MASK;
	u64 nr_pages = DIV_ROUND_UP(end - cur, PAGE_SIZE);
	u64 ans;

	u64 *pfn_list = kmalloc(nr_pages * sizeof(u64), GFP_KERNEL);
	if (!pfn_list) {
		kfree(pool);
		return -ENOMEM;
	}

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
			return -EFAULT;
		}
	}

	arm_smccc_hvc(KVM_HOST_SMCCC_ID(
			      __KVM_HOST_SMCCC_FUNC___pkvm_get_shadow_handles),
		      (unsigned long)pool, cap, 0, 0, 0, 0, 0, &res);
	printk("syscall_get_shadow_handles : res.a0 = %lld, res.a1 = %lld\n",
	       res.a0, res.a1);
	long long ret = res.a1;
	if (res.a0) {
		printk("syscall_get_shadow_handles error : res.a0 = %lld\n",
		       res.a0);
		for (i = 0; i < nr_pages; i++) {
			arm_smccc_hvc(
				KVM_HOST_SMCCC_ID(
					__KVM_HOST_SMCCC_FUNC___pkvm_host_unshare_hyp),
				pfn_list[i], 0, 0, 0, 0, 0, 0, &res);
		}
		kfree(pfn_list);
		kfree(pool);
		return res.a0;
	}
	for (i = 0; i < nr_pages; i++) {
		arm_smccc_hvc(
			KVM_HOST_SMCCC_ID(
				__KVM_HOST_SMCCC_FUNC___pkvm_host_unshare_hyp),
			pfn_list[i], 0, 0, 0, 0, 0, 0, &res);
	}
	kfree(pfn_list);
	if (copy_to_user(shadow_handles, pool, ret * sizeof(u32))) {
		kfree(pool);
		return -EFAULT;
	}
	kfree(pool);
	printk("syscall_get_shadow_handles returning %lld\n", ret);
	return ret;
}



SYSCALL_DEFINE2(view_iopt, char __user *, device_name, u64 __user *, user_pool)
{
#define cap (1 << 15)
	char name[100];
	u64 *pool;
	int ret = 0;
	struct device *dev;
	struct iommu_domain *domain;
	typeof(rk_view_iopt) *view_iopt_fn;

	ret = strncpy_from_user_nofault(name, device_name, 100);
	if (ret < 0) {
		printk("view_iopt: copy from user failed\n");
		return -EFAULT;
	}

	dev = bus_find_device_by_name(&platform_bus_type, NULL, name);
	if (!dev) {
		printk("view_iopt: cannot find device %s\n", name);
		return -ENODEV;
	}

	domain = iommu_get_domain_for_dev(dev);
	if (!domain) {
		printk("view_iopt: device %s has no iommu domain\n", name);
		return -ENODEV;
	}

	pool = kmalloc(cap * 3 * sizeof(u64), GFP_KERNEL);
	if (!pool){
		printk("view_iopt: kmalloc failed\n");
		return -ENOMEM;
	}

	view_iopt_fn = symbol_get(rk_view_iopt);
	if(!view_iopt_fn){
		printk("view_iopt: cannot find rk_view_iopt, insmod iommu driver first\n");
		kfree(pool);
		return -EINVAL;
	}

	ret = view_iopt_fn(domain, pool, cap);
	symbol_put(rk_view_iopt);
	if (ret < 0) {
		printk("view_iopt: hypercall view_iopt returned %d\n", ret);
		kfree(pool);
		return ret;
	}

	if (copy_to_user(user_pool, pool, cap * 3 * sizeof(u64))) {
		printk("view_iopt: copy to user failed\n");
		kfree(pool);
		return -EFAULT;
	}
	kfree(pool);
	return ret;
#undef cap
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
