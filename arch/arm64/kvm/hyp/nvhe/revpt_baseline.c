// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kernel.h>
#include <linux/kvm_host.h>

#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>
#include <nvhe/pfn_info.h>
#include <nvhe/pkvm.h>
#include <nvhe/revpt_baseline.h>

struct revpt_test_cfg revpt_test_cfg;

enum revpt_cpu_pass {
	REVPT_CPU_PASS_OWNER = 0,
	REVPT_CPU_PASS_BORROW_ACCESS,
	REVPT_CPU_PASS_REF,
};

struct revpt_baseline_walk_ctx {
	enum page_owner owner;
	enum revpt_ref_type ref_type;
	u8 borrow_access;
	enum revpt_cpu_pass pass;
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

static inline enum pkvm_page_state revpt_stage2_leaf_state(kvm_pte_t pte)
{
	/*
	 * Reuse pKVM stage-2 SW bits semantics from mem_protect:
	 * PKVM_PAGE_{OWNED,SHARED_OWNED,SHARED_BORROWED}.
	 */
	return pkvm_getstate(kvm_pgtable_stage2_pte_prot(pte));
}

static inline bool revpt_stage2_leaf_is_owner_mapping(kvm_pte_t pte)
{
	enum pkvm_page_state state = revpt_stage2_leaf_state(pte);

	return state == PKVM_PAGE_OWNED || state == PKVM_PAGE_SHARED_OWNED;
}

static inline bool revpt_stage2_leaf_is_borrowed_mapping(kvm_pte_t pte)
{
	return revpt_stage2_leaf_state(pte) == PKVM_PAGE_SHARED_BORROWED;
}

static inline enum pkvm_page_state revpt_hyp_leaf_state(kvm_pte_t pte)
{
	return pkvm_getstate(kvm_pgtable_hyp_pte_prot(pte));
}

static inline bool revpt_hyp_leaf_is_owner_mapping(kvm_pte_t pte)
{
	enum pkvm_page_state state = revpt_hyp_leaf_state(pte);

	return state == PKVM_PAGE_OWNED || state == PKVM_PAGE_SHARED_OWNED;
}

static inline bool revpt_hyp_leaf_is_borrowed_mapping(kvm_pte_t pte)
{
	return revpt_hyp_leaf_state(pte) == PKVM_PAGE_SHARED_BORROWED;
}

static int revpt_track_owner_range(u64 pfn, u64 nr_pages, enum page_owner owner,
				   u64 *cpu_snapshot_pages)
{
	u64 i;

	for (i = 0; i < nr_pages; i++) {
		u64 cur = pfn + i;
		struct pfn_info info;

		(void)revpt_set_flags(cur, PFN_F_TRACKED | PFN_F_RAM, 0);
		if (revpt_snapshot_pfn(cur, &info))
			return -EINVAL;

		if (!(info.flags & PFN_F_TRACKED) || info.owner == OWN_FREE) {
			if (revpt_set_owner(cur, owner))
				return -EINVAL;
		} else if (info.owner != owner) {
			return -EINVAL;
		}

		(*cpu_snapshot_pages)++;
	}

	return 0;
}

static int revpt_track_borrow_range(u64 pfn, u64 nr_pages, u8 borrow_access,
				    u64 *cpu_snapshot_pages)
{
	u64 i;

	for (i = 0; i < nr_pages; i++) {
		u64 cur = pfn + i;

		(void)revpt_set_flags(cur, PFN_F_TRACKED | PFN_F_RAM, 0);
		(void)revpt_grant_access(cur, borrow_access);
		(*cpu_snapshot_pages)++;
	}

	return 0;
}

static int revpt_track_ref_range(u64 pfn, u64 nr_pages, enum revpt_ref_type ref_type,
				 u64 *cpu_snapshot_pages)
{
	u64 i;

	for (i = 0; i < nr_pages; i++) {
		u64 cur = pfn + i;

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
	if (!revpt_pa_overlap_enabled(pa, kvm_granule_size(level), &clip_pfn, &clip_pages))
		return 0;

	switch (ctx->pass) {
	case REVPT_CPU_PASS_OWNER:
		if (!revpt_stage2_leaf_is_owner_mapping(pte))
			return 0;
		return revpt_track_owner_range(clip_pfn, clip_pages, ctx->owner,
					      ctx->cpu_snapshot_pages);
	case REVPT_CPU_PASS_BORROW_ACCESS:
		if (!revpt_stage2_leaf_is_borrowed_mapping(pte))
			return 0;
		return revpt_track_borrow_range(clip_pfn, clip_pages,
					       ctx->borrow_access,
					       ctx->cpu_snapshot_pages);
	case REVPT_CPU_PASS_REF:
		return revpt_track_ref_range(clip_pfn, clip_pages, ctx->ref_type,
					     ctx->cpu_snapshot_pages);
	default:
		return -EINVAL;
	}
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
	if (!revpt_pa_overlap_enabled(pa, kvm_granule_size(level), &clip_pfn, &clip_pages))
		return 0;

	switch (ctx->pass) {
	case REVPT_CPU_PASS_OWNER:
		if (!revpt_hyp_leaf_is_owner_mapping(pte))
			return 0;
		return revpt_track_owner_range(clip_pfn, clip_pages,
					      OWN_HYP,
					      ctx->cpu_snapshot_pages);
	case REVPT_CPU_PASS_BORROW_ACCESS:
		if (!revpt_hyp_leaf_is_borrowed_mapping(pte))
			return 0;
		return revpt_track_borrow_range(clip_pfn, clip_pages,
					       ctx->borrow_access,
					       ctx->cpu_snapshot_pages);
	case REVPT_CPU_PASS_REF:
		return revpt_track_ref_range(clip_pfn, clip_pages,
					     REVPT_REF_HYP_CPU,
					     ctx->cpu_snapshot_pages);
	default:
		return -EINVAL;
	}
}

static int revpt_walk_cpu_tables_pass_locked(enum revpt_cpu_pass pass,
					      struct kvm_shadow_vm **locked_vms,
					      int nr_locked,
					      u64 *cpu_snapshot_pages)
{
	struct revpt_baseline_walk_ctx host_ctx = {
		.owner = OWN_HOST,
		.ref_type = REVPT_REF_HOST_CPU,
		.borrow_access = ACC_HOST_CPU,
		.pass = pass,
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
		.borrow_access = ACC_HYP_CPU,
		.pass = pass,
		.cpu_snapshot_pages = cpu_snapshot_pages,
	};
	struct kvm_pgtable_walker hyp_walker = {
		.cb = revpt_hyp_walk_cb,
		.arg = &hyp_ctx,
		.flags = KVM_PGTABLE_WALK_LEAF,
	};
	int i, ret;

	ret = kvm_pgtable_walk(&pkvm_pgtable, 0, BIT(pkvm_pgtable.ia_bits),
			       &hyp_walker);
	if (ret)
		return ret;

	ret = kvm_pgtable_walk(&host_kvm.pgt, 0, BIT(host_kvm.pgt.ia_bits),
			       &host_walker);
	if (ret)
		return ret;

	for (i = 0; i < nr_locked; i++) {
		struct revpt_baseline_walk_ctx guest_ctx = {
			.owner = OWN_ENCLAVE,
			.ref_type = REVPT_REF_ENCLAVE_CPU,
			.borrow_access = ACC_ENCLAVE_CPU,
			.pass = pass,
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
			return ret;
	}

	return 0;
}

int revpt_capture_cpu_baseline_locked(u64 *cpu_snapshot_pages)
{
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

	ret = revpt_walk_cpu_tables_pass_locked(REVPT_CPU_PASS_OWNER,
						locked_vms,
						nr_locked,
						cpu_snapshot_pages);
	if (ret)
		goto out_unlock;

	ret = revpt_walk_cpu_tables_pass_locked(REVPT_CPU_PASS_BORROW_ACCESS,
						locked_vms,
						nr_locked,
						cpu_snapshot_pages);
	if (ret)
		goto out_unlock;

	ret = revpt_walk_cpu_tables_pass_locked(REVPT_CPU_PASS_REF,
						locked_vms,
						nr_locked,
						cpu_snapshot_pages);

out_unlock:
	for (i = nr_locked - 1; i >= 0; i--)
		hyp_spin_unlock(&locked_vms[i]->lock);
	hyp_spin_unlock(&pkvm_pgd_lock);
	return ret;
}

static bool revpt_incremental_active(void)
{
	return revpt_test_cfg.configured && revpt_test_cfg.snapshot_valid;
}

static int revpt_clip_phys_range(phys_addr_t phys_start, u64 size,
				 u64 *clip_pfn, u64 *clip_pages)
{
	if (!revpt_incremental_active())
		return 0;

	if (!revpt_pa_overlap_enabled(phys_start, size, clip_pfn, clip_pages))
		return 0;

	return 1;
}

static int revpt_owner_to_cpu_ref(enum page_owner owner, enum revpt_ref_type *ref)
{
	switch (owner) {
	case OWN_HOST:
		*ref = REVPT_REF_HOST_CPU;
		return 0;
	case OWN_HYP:
		*ref = REVPT_REF_HYP_CPU;
		return 0;
	case OWN_ENCLAVE:
		*ref = REVPT_REF_ENCLAVE_CPU;
		return 0;
	default:
		return -EINVAL;
	}
}

static int revpt_owner_to_cpu_access(enum page_owner owner, u8 *access)
{
	switch (owner) {
	case OWN_HOST:
		*access = ACC_HOST_CPU;
		return 0;
	case OWN_HYP:
		*access = ACC_HYP_CPU;
		return 0;
	case OWN_ENCLAVE:
		*access = ACC_ENCLAVE_CPU;
		return 0;
	default:
		return -EINVAL;
	}
}

static u16 revpt_snapshot_cpu_ref(const struct pfn_info *info, enum revpt_ref_type type)
{
	switch (type) {
	case REVPT_REF_HOST_CPU:
		return info->host_refs;
	case REVPT_REF_ENCLAVE_CPU:
		return info->enclave_refs;
	case REVPT_REF_HYP_CPU:
		return info->hyp_refs;
	default:
		return 0;
	}
}

static int revpt_ref_update_phys_locked(phys_addr_t phys_start, u64 size,
					enum revpt_ref_type ref_type, bool inc)
{
	u64 clip_pfn, clip_pages, i;
	int active = revpt_clip_phys_range(phys_start, size, &clip_pfn, &clip_pages);

	if (active <= 0)
		return 0;

	for (i = 0; i < clip_pages; i++) {
		u64 pfn = clip_pfn + i;

		(void)revpt_set_flags(pfn, PFN_F_TRACKED | PFN_F_RAM, 0);
		if (inc)
			(void)revpt_ref_inc(pfn, ref_type);
		else
			(void)revpt_ref_dec(pfn, ref_type);
	}

	return 0;
}

int revpt_apply_share_locked(phys_addr_t phys_start, u64 nr_pages,
			     enum page_owner owner_comp,
			     enum page_owner borrower_comp)
{
	u64 clip_pfn, clip_pages, i;
	u8 borrower_access;
	enum revpt_ref_type borrower_ref;
	int active;

	if (revpt_owner_to_cpu_access(borrower_comp, &borrower_access))
		return -EINVAL;
	if (revpt_owner_to_cpu_ref(borrower_comp, &borrower_ref))
		return -EINVAL;
	if (owner_comp == OWN_FREE)
		return -EINVAL;

	active = revpt_clip_phys_range(phys_start, nr_pages << PAGE_SHIFT,
				       &clip_pfn, &clip_pages);
	if (active <= 0)
		return 0;

	for (i = 0; i < clip_pages; i++) {
		u64 pfn = clip_pfn + i;

		(void)revpt_set_flags(pfn, PFN_F_TRACKED | PFN_F_RAM, 0);
		(void)revpt_grant_access(pfn, borrower_access);
		(void)revpt_ref_inc(pfn, borrower_ref);
	}

	return 0;
}

int revpt_apply_unshare_locked(phys_addr_t phys_start, u64 nr_pages,
			       enum page_owner owner_comp,
			       enum page_owner borrower_comp)
{
	u64 clip_pfn, clip_pages, i;
	u8 borrower_access;
	enum revpt_ref_type borrower_ref;
	int active;

	if (revpt_owner_to_cpu_access(borrower_comp, &borrower_access))
		return -EINVAL;
	if (revpt_owner_to_cpu_ref(borrower_comp, &borrower_ref))
		return -EINVAL;
	if (owner_comp == OWN_FREE)
		return -EINVAL;

	active = revpt_clip_phys_range(phys_start, nr_pages << PAGE_SHIFT,
				       &clip_pfn, &clip_pages);
	if (active <= 0)
		return 0;

	for (i = 0; i < clip_pages; i++) {
		u64 pfn = clip_pfn + i;
		struct pfn_info info;

		(void)revpt_set_flags(pfn, PFN_F_TRACKED | PFN_F_RAM, 0);
		(void)revpt_ref_dec(pfn, borrower_ref);
		if (revpt_snapshot_pfn(pfn, &info))
			continue;
		if (!revpt_snapshot_cpu_ref(&info, borrower_ref))
			(void)revpt_revoke_access(pfn, borrower_access);
	}

	return 0;
}

int revpt_apply_donate_locked(phys_addr_t phys_start, u64 nr_pages,
			      enum page_owner from_comp,
			      enum page_owner to_comp)
{
	u64 clip_pfn, clip_pages, i;
	enum revpt_ref_type from_ref, to_ref;
	int active;

	if (revpt_owner_to_cpu_ref(from_comp, &from_ref))
		return -EINVAL;
	if (revpt_owner_to_cpu_ref(to_comp, &to_ref))
		return -EINVAL;

	active = revpt_clip_phys_range(phys_start, nr_pages << PAGE_SHIFT,
				       &clip_pfn, &clip_pages);
	if (active <= 0)
		return 0;

	for (i = 0; i < clip_pages; i++) {
		u64 pfn = clip_pfn + i;

		(void)revpt_set_flags(pfn, PFN_F_TRACKED | PFN_F_RAM, 0);
		(void)revpt_ref_dec(pfn, from_ref);
		(void)revpt_set_owner(pfn, to_comp);
		(void)revpt_ref_inc(pfn, to_ref);
	}

	return 0;
}

int revpt_apply_host_cpu_map_locked(phys_addr_t phys_start, u64 size)
{
	return revpt_ref_update_phys_locked(phys_start, size, REVPT_REF_HOST_CPU, true);
}

int revpt_apply_host_cpu_unmap_locked(phys_addr_t phys_start, u64 size)
{
	return revpt_ref_update_phys_locked(phys_start, size, REVPT_REF_HOST_CPU, false);
}

int revpt_apply_hyp_cpu_map_locked(phys_addr_t phys_start, u64 size)
{
	return revpt_ref_update_phys_locked(phys_start, size, REVPT_REF_HYP_CPU, true);
}

int revpt_apply_hyp_cpu_unmap_locked(phys_addr_t phys_start, u64 size)
{
	return revpt_ref_update_phys_locked(phys_start, size, REVPT_REF_HYP_CPU, false);
}

int revpt_apply_host_dma_map_locked(phys_addr_t phys_start, u64 size)
{
	return revpt_ref_update_phys_locked(phys_start, size, REVPT_REF_HOST_DMA, true);
}

int revpt_apply_host_dma_unmap_locked(phys_addr_t phys_start, u64 size)
{
	return revpt_ref_update_phys_locked(phys_start, size, REVPT_REF_HOST_DMA, false);
}
