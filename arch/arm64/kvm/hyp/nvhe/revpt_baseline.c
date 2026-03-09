// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kvm_host.h>

#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>
#include <nvhe/pfn_info.h>
#include <nvhe/pkvm.h>
#include <nvhe/revpt_baseline.h>

struct revpt_baseline_walk_ctx {
	enum page_owner owner;
	enum revpt_ref_type ref_type;
};

static inline phys_addr_t revpt_stage2_pte_phys(kvm_pte_t pte)
{
	return (phys_addr_t)(pte & KVM_PTE_ADDR_MASK);
}

static int revpt_track_mapping_range(u64 pfn, u64 nr_pages,
				      enum page_owner owner,
				      enum revpt_ref_type ref_type)
{
	u64 i;

	for (i = 0; i < nr_pages; i++) {
		u64 cur = pfn + i;
		struct pfn_info info;

		if (revpt_snapshot_pfn(cur, &info)) {
			/* 首次出现的 PFN：建立追踪并设置默认 owner。 */
			(void)revpt_set_flags(cur, PFN_F_TRACKED | PFN_F_RAM, 0);
			(void)revpt_set_owner(cur, owner);
		} else if (!(info.flags & PFN_F_TRACKED)) {
			(void)revpt_set_flags(cur, PFN_F_TRACKED | PFN_F_RAM, 0);
			(void)revpt_set_owner(cur, owner);
		} else if (info.owner != owner) {
			/* 多主体同时可达：保持当前 owner，仅补齐授权。 */
			if (owner == OWN_HOST)
				(void)revpt_grant_access(cur, ACC_HOST_CPU);
			else if (owner == OWN_ENCLAVE)
				(void)revpt_grant_access(cur, ACC_ENCLAVE_CPU);
			else if (owner == OWN_HYP)
				(void)revpt_grant_access(cur, ACC_HYP_CPU);
		}
	}

	(void)revpt_ref_inc_range(pfn, nr_pages, ref_type);
	return 0;
}

static int revpt_stage2_walk_cb(u64 start, u64 end, u32 level, kvm_pte_t *ptep,
				enum kvm_pgtable_walk_flags flags,
				void *arg)
{
	struct revpt_baseline_walk_ctx *ctx = arg;
	kvm_pte_t pte = READ_ONCE(*ptep);
	phys_addr_t pa;
	u64 pages;

	if (!kvm_pte_valid(pte))
		return 0;

	pa = revpt_stage2_pte_phys(pte);
	pages = (end - start) >> PAGE_SHIFT;
	if (!pages)
		return 0;

	return revpt_track_mapping_range(pa >> PAGE_SHIFT, pages, ctx->owner,
					 ctx->ref_type);
}

static int revpt_hyp_walk_cb(u64 start, u64 end, u32 level, kvm_pte_t *ptep,
			     enum kvm_pgtable_walk_flags flags,
			     void *arg)
{
	kvm_pte_t pte = READ_ONCE(*ptep);
	phys_addr_t pa;
	u64 pages;

	if (!kvm_pte_valid(pte))
		return 0;

	pa = (phys_addr_t)(pte & KVM_PTE_ADDR_MASK);
	pages = (end - start) >> PAGE_SHIFT;
	if (!pages)
		return 0;

	return revpt_track_mapping_range(pa >> PAGE_SHIFT, pages,
					 OWN_HYP, REVPT_REF_HYP_CPU);
}

int revpt_capture_cpu_baseline_locked(void)
{
	struct revpt_baseline_walk_ctx host_ctx = {
		.owner = OWN_HOST,
		.ref_type = REVPT_REF_HOST_CPU,
	};
	struct kvm_pgtable_walker host_walker = {
		.cb = revpt_stage2_walk_cb,
		.arg = &host_ctx,
		.flags = KVM_PGTABLE_WALK_LEAF,
	};
	struct kvm_pgtable_walker hyp_walker = {
		.cb = revpt_hyp_walk_cb,
		.arg = NULL,
		.flags = KVM_PGTABLE_WALK_LEAF,
	};
	struct kvm_shadow_vm *locked_vms[KVM_MAX_PVMS];
	int i, nr_locked = 0, ret;

	/*
	 * 为了尽量保证“初始状态”一致性：
	 * 先拿齐所有相关页表锁，再统一遍历。
	 */
	hyp_spin_lock(&pkvm_pgd_lock);
	for (i = 0; i < KVM_MAX_PVMS; i++) {
		struct kvm_shadow_vm *vm;

		vm = pkvm_shadow_table_get(index_to_shadow_handle(i));
		if (!vm)
			continue;
		hyp_spin_lock(&vm->lock);
		locked_vms[nr_locked++] = vm;
	}

	/* 新语义：从页表快照重建 rev_pt 起始状态。 */
	revpt_reset_all();

	ret = kvm_pgtable_walk(&pkvm_pgtable, 0, BIT(pkvm_pgtable.ia_bits),
			       &hyp_walker);
	if (ret)
		goto out_unlock;

	ret = kvm_pgtable_walk(&host_kvm.pgt, 0, BIT(host_kvm.pgt.ia_bits),
			       &host_walker);
	if (ret)
		goto out_unlock;

	for (i = 0; i < nr_locked; i++) {
		struct revpt_baseline_walk_ctx guest_ctx = {
			.owner = OWN_ENCLAVE,
			.ref_type = REVPT_REF_ENCLAVE_CPU,
		};
		struct kvm_pgtable_walker guest_walker = {
			.cb = revpt_stage2_walk_cb,
			.arg = &guest_ctx,
			.flags = KVM_PGTABLE_WALK_LEAF,
		};
		struct kvm_shadow_vm *vm = locked_vms[i];

		ret = kvm_pgtable_walk(&vm->pgt, 0, BIT(vm->pgt.ia_bits),
				       &guest_walker);
		if (ret)
			goto out_unlock;
	}

out_unlock:
	for (i = nr_locked - 1; i >= 0; i--)
		hyp_spin_unlock(&locked_vms[i]->lock);
	hyp_spin_unlock(&pkvm_pgd_lock);
	return ret;
}
