// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kernel.h>
#include <linux/kvm_host.h>

#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>
#include <nvhe/pfn_info.h>
#include <nvhe/pkvm.h>
#include <nvhe/revpt_baseline.h>

struct revpt_test_cfg revpt_test_cfg;

struct revpt_baseline_walk_ctx {
	enum page_owner owner;
	enum revpt_ref_type ref_type;
	u64 *cpu_snapshot_pages;
};

static inline phys_addr_t revpt_stage2_pte_phys(kvm_pte_t pte)
{
	return (phys_addr_t)(pte & KVM_PTE_ADDR_MASK);
}

bool revpt_pa_overlap_enabled(phys_addr_t pa, u64 size,
			      u64 *clip_pfn, u64 *clip_pages)
{
	u64 range_start, range_end, ent_start, ent_end;

	if (!size || !revpt_test_cfg.hpa_size)
		return false;

	range_start = revpt_test_cfg.hpa_start;
	range_end = range_start + revpt_test_cfg.hpa_size;
	ent_start = pa;
	ent_end = ent_start + size;

	if (ent_end <= range_start || ent_start >= range_end)
		return false;

	ent_start = max(ent_start, range_start);
	ent_end = min(ent_end, range_end);
	if (ent_end <= ent_start)
		return false;

	*clip_pfn = ent_start >> PAGE_SHIFT;
	*clip_pages = (ent_end - ent_start) >> PAGE_SHIFT;
	return *clip_pages != 0;
}

static int revpt_track_mapping_range(u64 pfn, u64 nr_pages,
			      enum page_owner owner,
			      enum revpt_ref_type ref_type,
			      u64 *cpu_snapshot_pages)
{
	u64 i;

	for (i = 0; i < nr_pages; i++) {
		u64 cur = pfn + i;

		(void)revpt_set_flags(cur, PFN_F_TRACKED | PFN_F_RAM, 0);
		(void)revpt_set_owner(cur, owner);
		(void)revpt_ref_inc(cur, ref_type);
		(*cpu_snapshot_pages)++;
	}

	return 0;
}

static int revpt_stage2_walk_cb(u64 start, u64 end, u32 level, kvm_pte_t *ptep,
				enum kvm_pgtable_walk_flags flags,
				void *arg)
{
	struct revpt_baseline_walk_ctx *ctx = arg;
	kvm_pte_t pte = READ_ONCE(*ptep);
	phys_addr_t pa;
	u64 clip_pfn, clip_pages;

	if (!kvm_pte_valid(pte))
		return 0;

	pa = revpt_stage2_pte_phys(pte);
	if (!revpt_pa_overlap_enabled(pa, end - start, &clip_pfn, &clip_pages))
		return 0;

	return revpt_track_mapping_range(clip_pfn, clip_pages, ctx->owner,
					 ctx->ref_type,
					 ctx->cpu_snapshot_pages);
}

static int revpt_hyp_walk_cb(u64 start, u64 end, u32 level, kvm_pte_t *ptep,
			     enum kvm_pgtable_walk_flags flags,
			     void *arg)
{
	struct revpt_baseline_walk_ctx *ctx = arg;
	kvm_pte_t pte = READ_ONCE(*ptep);
	phys_addr_t pa;
	u64 clip_pfn, clip_pages;

	if (!kvm_pte_valid(pte))
		return 0;

	pa = (phys_addr_t)(pte & KVM_PTE_ADDR_MASK);
	if (!revpt_pa_overlap_enabled(pa, end - start, &clip_pfn, &clip_pages))
		return 0;

	return revpt_track_mapping_range(clip_pfn, clip_pages,
					 OWN_HYP, REVPT_REF_HYP_CPU,
					 ctx->cpu_snapshot_pages);
}

int revpt_capture_cpu_baseline_locked(u64 *cpu_snapshot_pages)
{
	struct revpt_baseline_walk_ctx host_ctx = {
		.owner = OWN_HOST,
		.ref_type = REVPT_REF_HOST_CPU,
		.cpu_snapshot_pages = cpu_snapshot_pages,
	};
	struct kvm_pgtable_walker host_walker = {
		.cb = revpt_stage2_walk_cb,
		.arg = &host_ctx,
		.flags = KVM_PGTABLE_WALK_LEAF,
	};
	struct revpt_baseline_walk_ctx hyp_ctx = {
		.owner = OWN_HYP,
		.ref_type = REVPT_REF_HYP_CPU,
		.cpu_snapshot_pages = cpu_snapshot_pages,
	};
	struct kvm_pgtable_walker hyp_walker = {
		.cb = revpt_hyp_walk_cb,
		.arg = &hyp_ctx,
		.flags = KVM_PGTABLE_WALK_LEAF,
	};
	struct kvm_shadow_vm *locked_vms[KVM_MAX_PVMS];
	int i, nr_locked = 0, ret;

	hyp_spin_lock(&pkvm_pgd_lock);
	for (i = 0; i < KVM_MAX_PVMS; i++) {
		struct kvm_shadow_vm *vm;

		vm = pkvm_shadow_table_get(index_to_shadow_handle(i));
		if (!vm)
			continue;
		hyp_spin_lock(&vm->lock);
		locked_vms[nr_locked++] = vm;
	}

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
			.cpu_snapshot_pages = cpu_snapshot_pages,
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
