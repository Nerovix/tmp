// SPDX-License-Identifier: GPL-2.0-only
/*
 * AArch64-specific system calls implementation
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Catalin Marinas <catalin.marinas@arm.com>
 */

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/kvm_host.h>

#include <asm/cpufeature.h>
#include <asm/syscall.h>

#include <linux/arm-smccc.h>
#include <kvm/arm_hypercalls.h>

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

SYSCALL_DEFINE5(view_stage2_pt, u64, cap, u64 __user *, ipa, u64 __user *, pa,
		u64 __user *, level, u64 __user *, prot)
{
	struct arm_smccc_res res;
	size_t bytes = cap * 4 * sizeof(u64);
	void *pool = kvmalloc(bytes, GFP_KERNEL);
	if (!pool)
		return -ENOMEM;
	u64 i,j;

	unsigned long start = (unsigned long)pool;
	unsigned long end = start + bytes;
	unsigned long cur = start & PAGE_MASK;
	u64 nr_pages = DIV_ROUND_UP(end - cur, PAGE_SIZE);
	u64 ans;

	u64 *pfn_list = kvmalloc(nr_pages * sizeof(u64), GFP_KERNEL);
	if (!pfn_list) {
		kvfree(pool);
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
			kvfree(pfn_list);
			kvfree(pool);
			return -114514;
		}
	}

	arm_smccc_hvc(
		KVM_HOST_SMCCC_ID(__KVM_HOST_SMCCC_FUNC___pkvm_view_stage2_pt),
		(unsigned long)pool, cap, 0, 0, 0, 0, 0, &res);
		
	ans = res.a1;

	if (res.a0) {
		for (j = 0; j < nr_pages; j++)
			arm_smccc_hvc(
				KVM_HOST_SMCCC_ID(
					__KVM_HOST_SMCCC_FUNC___pkvm_host_unshare_hyp),
				pfn_list[j], 0, 0, 0, 0, 0, 0, &res);
		kvfree(pfn_list);
		kvfree(pool);
		printk("2\n");
		return res.a0;
	}

	for (i = 0; i < nr_pages; i++) {
		arm_smccc_hvc(
			KVM_HOST_SMCCC_ID(
				__KVM_HOST_SMCCC_FUNC___pkvm_host_unshare_hyp),
			pfn_list[i], 0, 0, 0, 0, 0, 0, &res);
	}
	kvfree(pfn_list);
	if (ipa && copy_to_user(ipa, (u64 *)pool, cap * sizeof(u64))) {
		kvfree(pool);
		return -EFAULT;
	}
	if (pa && copy_to_user(pa, (u64 *)pool + cap, cap * sizeof(u64))) {
		kvfree(pool);
		return -EFAULT;
	}
	if (level &&
	    copy_to_user(level, (u64 *)pool + 2 * cap, cap * sizeof(u64))) {
		kvfree(pool);
		return -EFAULT;
	}
	if (prot &&
	    copy_to_user(prot, (u64 *)pool + 3 * cap, cap * sizeof(u64))) {
		kvfree(pool);
		return -EFAULT;
	}

	kvfree(pool);
	// printk("1\n");
	return ans;
}

SYSCALL_DEFINE0(get_stage2_pt_size)
{
	struct arm_smccc_res res;

	arm_smccc_hvc(KVM_HOST_SMCCC_ID(
			      __KVM_HOST_SMCCC_FUNC___pkvm_get_stage2_pt_size),
		      0, 0, 0, 0, 0, 0, 0, &res);
	return res.a1;
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
