// SPDX-License-Identifier: GPL-2.0
/*
 * PFN security ledger / reverse page tracking for pKVM-ASGARD experiments.
 *
 * This is NOT a full reverse page table. It is a dense per-PFN security oracle
 * over [0, PMEM_SIZE), tracking:
 *   - current owner
 *   - which principals are currently allowed to access
 *   - current CPU / device-side reference counts
 *   - sensitive-page constraints
 *
 * Design notes:
 *   - 4KiB granularity only
 *   - dense array for tracked PFNs
 *   - lock striping instead of one lock per PFN
 *   - refcounts are u16 with overflow / underflow checks
 *
 * IMPORTANT:
 *   - make_shared() only sets a hint flag; it does NOT grant access.
 *   - use revpt_grant_access()/revpt_revoke_access() to describe legal sharing.
 *   - owner transitions intentionally DO NOT clear stale refs; stale refs should
 *     be caught by check_oracle().
 */

#include <linux/bitops.h>
#include <linux/build_bug.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>
#include <asm/page.h>

enum page_owner {
	OWN_FREE = 0,
	OWN_HOST = 1,
	OWN_ENCLAVE = 2,
	OWN_HYP = 3,
};

enum revpt_flags {
	PFN_F_TRACKED     = BIT(0), /* this PFN is tracked by the oracle */
	PFN_F_RAM         = BIT(1), /* normal RAM */
	PFN_F_MMIO        = BIT(2), /* MMIO window */
	PFN_F_SENSITIVE   = BIT(3), /* hypervisor-only sensitive page */
	PFN_F_MMU_PT      = BIT(4), /* CPU MMU page-table page */
	PFN_F_IOMMU_PT    = BIT(5), /* IOMMU page-table page */
	PFN_F_SHARED_HINT = BIT(6), /* informational only */
};

enum revpt_access_bits {
	ACC_HOST_CPU    = BIT(0),
	ACC_HOST_DMA    = BIT(1),
	ACC_ENCLAVE_CPU = BIT(2),
	ACC_ENCLAVE_DMA = BIT(3), /* enclave-side device access, e.g. NPU DMA */
	ACC_HYP_CPU     = BIT(4),
};

#define ACC_NPU_DMA ACC_ENCLAVE_DMA

enum revpt_ref_type {
	REVPT_REF_HOST_CPU = 0,
	REVPT_REF_HOST_DMA,
	REVPT_REF_ENCLAVE_CPU,
	REVPT_REF_ENCLAVE_DMA,
	REVPT_REF_HYP_CPU,
};

enum revpt_violation_reason {
	REVPT_V_BAD_PFN                = BIT(0),
	REVPT_V_UNTRACKED_HAS_STATE    = BIT(1),
	REVPT_V_FREE_HAS_ACCESS        = BIT(2),
	REVPT_V_FREE_HAS_REFS          = BIT(3),
	REVPT_V_BAD_OWNER              = BIT(4),

	REVPT_V_SENSITIVE_BAD_OWNER    = BIT(5),
	REVPT_V_SENSITIVE_BAD_ALLOW    = BIT(6),
	REVPT_V_SENSITIVE_BAD_REFS     = BIT(7),

	REVPT_V_HOST_CPU_DISALLOWED    = BIT(8),
	REVPT_V_HOST_DMA_DISALLOWED    = BIT(9),
	REVPT_V_ENCL_CPU_DISALLOWED    = BIT(10),
	REVPT_V_ENCL_DMA_DISALLOWED    = BIT(11),
	REVPT_V_HYP_CPU_DISALLOWED     = BIT(12),

	REVPT_V_HOST_CPU_OVERFLOW      = BIT(13),
	REVPT_V_HOST_DMA_OVERFLOW      = BIT(14),
	REVPT_V_ENCL_CPU_OVERFLOW      = BIT(15),
	REVPT_V_ENCL_DMA_OVERFLOW      = BIT(16),
	REVPT_V_HYP_CPU_OVERFLOW       = BIT(17),

	REVPT_V_HOST_CPU_UNDERFLOW     = BIT(18),
	REVPT_V_HOST_DMA_UNDERFLOW     = BIT(19),
	REVPT_V_ENCL_CPU_UNDERFLOW     = BIT(20),
	REVPT_V_ENCL_DMA_UNDERFLOW     = BIT(21),
	REVPT_V_HYP_CPU_UNDERFLOW      = BIT(22),
};

#ifndef PMEM_SIZE
#define PMEM_SIZE (16ULL * 1024 * 1024 * 1024) /* 16 GB */
#endif

#define REV_PT_NR_PAGES    ((u64)PMEM_SIZE >> PAGE_SHIFT)
#define REV_PT_LOCK_STRIPES 4096U /* must be power of 2 */
#define MAX_VIOLATE_NUM    1024

static_assert((REV_PT_LOCK_STRIPES & (REV_PT_LOCK_STRIPES - 1)) == 0);

struct pfn_info {
	u8  owner;
	u8  allowed_mask;
	u16 flags;

	u16 host_refs;         /* host CPU / host stage-2 refs */
	u16 host_dev_refs;     /* host-controlled device / host DMA refs */
	u16 enclave_refs;      /* enclave CPU refs */
	u16 enclave_dev_refs;  /* enclave-controlled device refs, e.g. NPU DMA */
	u16 hyp_refs;          /* hypervisor refs */

	u16 generation;
};

static_assert(sizeof(struct pfn_info) == 16);

struct violate_info {
	u64 pfn;
	u32 reason;
	struct pfn_info info;
};

struct pfn_info rev_pt[REV_PT_NR_PAGES];
u32 violate_num = 0;
struct violate_info violate_list[MAX_VIOLATE_NUM];

static raw_spinlock_t revpt_locks[REV_PT_LOCK_STRIPES];
static DEFINE_RAW_SPINLOCK(revpt_init_lock);
static DEFINE_RAW_SPINLOCK(revpt_violate_lock);
static bool revpt_ready;

static inline bool revpt_pfn_valid(u64 pfn)
{
	return pfn < REV_PT_NR_PAGES;
}

static inline raw_spinlock_t *revpt_lock_for_pfn(u64 pfn)
{
	return &revpt_locks[pfn & (REV_PT_LOCK_STRIPES - 1)];
}

static void revpt_ensure_init(void)
{
	unsigned long irqflags;
	u32 i;

	if (READ_ONCE(revpt_ready))
		return;

	raw_spin_lock_irqsave(&revpt_init_lock, irqflags);
	if (!revpt_ready) {
		for (i = 0; i < REV_PT_LOCK_STRIPES; i++)
			raw_spin_lock_init(&revpt_locks[i]);

		WRITE_ONCE(revpt_ready, true);
	}
	raw_spin_unlock_irqrestore(&revpt_init_lock, irqflags);
}

int revpt_init(void)
{
	revpt_ensure_init();
	return 0;
}

void revpt_reset_all(void)
{
	unsigned long irqflags;

	revpt_ensure_init();
	memset(rev_pt, 0, sizeof(rev_pt));

	raw_spin_lock_irqsave(&revpt_violate_lock, irqflags);
	violate_num = 0;
	memset(violate_list, 0, sizeof(violate_list));
	raw_spin_unlock_irqrestore(&revpt_violate_lock, irqflags);
}

static inline u8 revpt_default_access_for_owner(u8 owner)
{
	switch (owner) {
	case OWN_HOST:
		return ACC_HOST_CPU | ACC_HOST_DMA;
	case OWN_ENCLAVE:
		/*
		 * Default enclave-owned page only grants enclave CPU access.
		 * Enclave-side device access (e.g. NPU DMA) must be granted explicitly.
		 */
		return ACC_ENCLAVE_CPU;
	case OWN_HYP:
		return ACC_HYP_CPU;
	case OWN_FREE:
	default:
		return 0;
	}
}

static inline void revpt_zero_refs(struct pfn_info *info)
{
	info->host_refs = 0;
	info->host_dev_refs = 0;
	info->enclave_refs = 0;
	info->enclave_dev_refs = 0;
	info->hyp_refs = 0;
}

static inline u8 revpt_actual_access_mask(const struct pfn_info *info)
{
	u8 mask = 0;

	if (info->host_refs)
		mask |= ACC_HOST_CPU;
	if (info->host_dev_refs)
		mask |= ACC_HOST_DMA;
	if (info->enclave_refs)
		mask |= ACC_ENCLAVE_CPU;
	if (info->enclave_dev_refs)
		mask |= ACC_ENCLAVE_DMA;
	if (info->hyp_refs)
		mask |= ACC_HYP_CPU;

	return mask;
}

static void revpt_record_violation(u64 pfn, const struct pfn_info *info, u32 reason)
{
	unsigned long irqflags;

	raw_spin_lock_irqsave(&revpt_violate_lock, irqflags);
	if (violate_num < MAX_VIOLATE_NUM) {
		violate_list[violate_num].pfn = pfn;
		violate_list[violate_num].reason = reason;
		violate_list[violate_num].info = *info;
		violate_num++;
	}
	raw_spin_unlock_irqrestore(&revpt_violate_lock, irqflags);
}

static inline u16 *revpt_ref_slot(struct pfn_info *info, enum revpt_ref_type type)
{
	switch (type) {
	case REVPT_REF_HOST_CPU:
		return &info->host_refs;
	case REVPT_REF_HOST_DMA:
		return &info->host_dev_refs;
	case REVPT_REF_ENCLAVE_CPU:
		return &info->enclave_refs;
	case REVPT_REF_ENCLAVE_DMA:
		return &info->enclave_dev_refs;
	case REVPT_REF_HYP_CPU:
		return &info->hyp_refs;
	default:
		return NULL;
	}
}

static inline u32 revpt_ref_overflow_reason(enum revpt_ref_type type)
{
	switch (type) {
	case REVPT_REF_HOST_CPU:
		return REVPT_V_HOST_CPU_OVERFLOW;
	case REVPT_REF_HOST_DMA:
		return REVPT_V_HOST_DMA_OVERFLOW;
	case REVPT_REF_ENCLAVE_CPU:
		return REVPT_V_ENCL_CPU_OVERFLOW;
	case REVPT_REF_ENCLAVE_DMA:
		return REVPT_V_ENCL_DMA_OVERFLOW;
	case REVPT_REF_HYP_CPU:
		return REVPT_V_HYP_CPU_OVERFLOW;
	default:
		return 0;
	}
}

static inline u32 revpt_ref_underflow_reason(enum revpt_ref_type type)
{
	switch (type) {
	case REVPT_REF_HOST_CPU:
		return REVPT_V_HOST_CPU_UNDERFLOW;
	case REVPT_REF_HOST_DMA:
		return REVPT_V_HOST_DMA_UNDERFLOW;
	case REVPT_REF_ENCLAVE_CPU:
		return REVPT_V_ENCL_CPU_UNDERFLOW;
	case REVPT_REF_ENCLAVE_DMA:
		return REVPT_V_ENCL_DMA_UNDERFLOW;
	case REVPT_REF_HYP_CPU:
		return REVPT_V_HYP_CPU_UNDERFLOW;
	default:
		return 0;
	}
}

static u32 __revpt_check_snapshot(u64 pfn, const struct pfn_info *info)
{
	u32 reason = 0;
	u8 actual_mask = revpt_actual_access_mask(info);
	u16 sensitive_flags = PFN_F_SENSITIVE | PFN_F_MMU_PT |
			      PFN_F_IOMMU_PT | PFN_F_MMIO;

	if (!revpt_pfn_valid(pfn))
		return REVPT_V_BAD_PFN;

	if (!(info->flags & PFN_F_TRACKED)) {
		if (info->owner != OWN_FREE ||
		    info->allowed_mask != 0 ||
		    actual_mask != 0)
			reason |= REVPT_V_UNTRACKED_HAS_STATE;
		return reason;
	}

	if (info->owner > OWN_HYP)
		reason |= REVPT_V_BAD_OWNER;

	if (info->owner == OWN_FREE) {
		if (info->allowed_mask)
			reason |= REVPT_V_FREE_HAS_ACCESS;
		if (actual_mask)
			reason |= REVPT_V_FREE_HAS_REFS;
	}

	if (info->flags & sensitive_flags) {
		if (info->owner != OWN_HYP)
			reason |= REVPT_V_SENSITIVE_BAD_OWNER;
		if (info->allowed_mask & ~ACC_HYP_CPU)
			reason |= REVPT_V_SENSITIVE_BAD_ALLOW;
		if (actual_mask & ~ACC_HYP_CPU)
			reason |= REVPT_V_SENSITIVE_BAD_REFS;
	}

	if ((actual_mask & ~info->allowed_mask) & ACC_HOST_CPU)
		reason |= REVPT_V_HOST_CPU_DISALLOWED;
	if ((actual_mask & ~info->allowed_mask) & ACC_HOST_DMA)
		reason |= REVPT_V_HOST_DMA_DISALLOWED;
	if ((actual_mask & ~info->allowed_mask) & ACC_ENCLAVE_CPU)
		reason |= REVPT_V_ENCL_CPU_DISALLOWED;
	if ((actual_mask & ~info->allowed_mask) & ACC_ENCLAVE_DMA)
		reason |= REVPT_V_ENCL_DMA_DISALLOWED;
	if ((actual_mask & ~info->allowed_mask) & ACC_HYP_CPU)
		reason |= REVPT_V_HYP_CPU_DISALLOWED;

	return reason;
}

u32 revpt_check_pfn(u64 pfn)
{
	unsigned long irqflags;
	struct pfn_info snapshot;
	u32 reason;

	revpt_ensure_init();

	if (!revpt_pfn_valid(pfn)) {
		snapshot = (struct pfn_info){ 0 };
		revpt_record_violation(pfn, &snapshot, REVPT_V_BAD_PFN);
		return REVPT_V_BAD_PFN;
	}

	raw_spin_lock_irqsave(revpt_lock_for_pfn(pfn), irqflags);
	snapshot = rev_pt[pfn];
	raw_spin_unlock_irqrestore(revpt_lock_for_pfn(pfn), irqflags);

	reason = __revpt_check_snapshot(pfn, &snapshot);
	if (reason)
		revpt_record_violation(pfn, &snapshot, reason);

	return reason;
}

u32 revpt_check_range(u64 start_pfn, u64 nr_pages)
{
	u64 i;
	u32 cnt = 0;

	revpt_ensure_init();

	if (!nr_pages)
		return 0;
	if (!revpt_pfn_valid(start_pfn) || nr_pages > REV_PT_NR_PAGES - start_pfn)
		return 1;

	for (i = 0; i < nr_pages; i++) {
		if (revpt_check_pfn(start_pfn + i))
			cnt++;
	}

	return cnt;
}

void check_oracle(int pfn)
{
	(void)revpt_check_pfn((u64)(unsigned int)pfn);
}

static int __revpt_update_owner(u64 pfn, enum page_owner owner)
{
	unsigned long irqflags;
	struct pfn_info *info;

	if (!revpt_pfn_valid(pfn))
		return -EINVAL;
	if (owner > OWN_HYP)
		return -EINVAL;

	revpt_ensure_init();
	info = &rev_pt[pfn];

	raw_spin_lock_irqsave(revpt_lock_for_pfn(pfn), irqflags);
	info->owner = owner;
	info->flags &= ~PFN_F_SHARED_HINT;
	info->allowed_mask = revpt_default_access_for_owner(owner);
	info->generation++;
	raw_spin_unlock_irqrestore(revpt_lock_for_pfn(pfn), irqflags);

	(void)revpt_check_pfn(pfn);
	return 0;
}

void reset_owner(u64 pfn, enum page_owner owner)
{
	(void)__revpt_update_owner(pfn, owner);
}

int revpt_set_owner(u64 pfn, enum page_owner owner)
{
	return __revpt_update_owner(pfn, owner);
}

int revpt_set_owner_range(u64 start_pfn, u64 nr_pages, enum page_owner owner)
{
	u64 i;

	if (!nr_pages)
		return 0;
	if (!revpt_pfn_valid(start_pfn) || nr_pages > REV_PT_NR_PAGES - start_pfn)
		return -EINVAL;

	for (i = 0; i < nr_pages; i++)
		(void)__revpt_update_owner(start_pfn + i, owner);

	return 0;
}

void make_exclusively_owned(u64 pfn)
{
	unsigned long irqflags;
	struct pfn_info *info;

	if (!revpt_pfn_valid(pfn))
		return;

	revpt_ensure_init();
	info = &rev_pt[pfn];

	raw_spin_lock_irqsave(revpt_lock_for_pfn(pfn), irqflags);
	info->flags &= ~PFN_F_SHARED_HINT;
	info->allowed_mask = revpt_default_access_for_owner(info->owner);
	info->generation++;
	raw_spin_unlock_irqrestore(revpt_lock_for_pfn(pfn), irqflags);

	(void)revpt_check_pfn(pfn);
}

void make_shared(u64 pfn)
{
	unsigned long irqflags;
	struct pfn_info *info;

	if (!revpt_pfn_valid(pfn))
		return;

	revpt_ensure_init();
	info = &rev_pt[pfn];

	raw_spin_lock_irqsave(revpt_lock_for_pfn(pfn), irqflags);
	info->flags |= PFN_F_SHARED_HINT;
	info->generation++;
	raw_spin_unlock_irqrestore(revpt_lock_for_pfn(pfn), irqflags);

	(void)revpt_check_pfn(pfn);
}

int revpt_grant_access(u64 pfn, u8 access_mask)
{
	unsigned long irqflags;
	struct pfn_info *info;

	if (!revpt_pfn_valid(pfn))
		return -EINVAL;

	revpt_ensure_init();
	info = &rev_pt[pfn];

	raw_spin_lock_irqsave(revpt_lock_for_pfn(pfn), irqflags);
	info->allowed_mask |= access_mask;
	if (access_mask & ~revpt_default_access_for_owner(info->owner))
		info->flags |= PFN_F_SHARED_HINT;
	info->generation++;
	raw_spin_unlock_irqrestore(revpt_lock_for_pfn(pfn), irqflags);

	(void)revpt_check_pfn(pfn);
	return 0;
}

int revpt_revoke_access(u64 pfn, u8 access_mask)
{
	unsigned long irqflags;
	struct pfn_info *info;

	if (!revpt_pfn_valid(pfn))
		return -EINVAL;

	revpt_ensure_init();
	info = &rev_pt[pfn];

	raw_spin_lock_irqsave(revpt_lock_for_pfn(pfn), irqflags);
	info->allowed_mask &= ~access_mask;

	if (info->allowed_mask == revpt_default_access_for_owner(info->owner))
		info->flags &= ~PFN_F_SHARED_HINT;

	info->generation++;
	raw_spin_unlock_irqrestore(revpt_lock_for_pfn(pfn), irqflags);

	(void)revpt_check_pfn(pfn);
	return 0;
}

int revpt_grant_access_range(u64 start_pfn, u64 nr_pages, u8 access_mask)
{
	u64 i;

	if (!nr_pages)
		return 0;
	if (!revpt_pfn_valid(start_pfn) || nr_pages > REV_PT_NR_PAGES - start_pfn)
		return -EINVAL;

	for (i = 0; i < nr_pages; i++)
		(void)revpt_grant_access(start_pfn + i, access_mask);

	return 0;
}

int revpt_revoke_access_range(u64 start_pfn, u64 nr_pages, u8 access_mask)
{
	u64 i;

	if (!nr_pages)
		return 0;
	if (!revpt_pfn_valid(start_pfn) || nr_pages > REV_PT_NR_PAGES - start_pfn)
		return -EINVAL;

	for (i = 0; i < nr_pages; i++)
		(void)revpt_revoke_access(start_pfn + i, access_mask);

	return 0;
}

int revpt_set_flags(u64 pfn, u16 set_mask, u16 clear_mask)
{
	unsigned long irqflags;
	struct pfn_info *info;

	if (!revpt_pfn_valid(pfn))
		return -EINVAL;

	revpt_ensure_init();
	info = &rev_pt[pfn];

	raw_spin_lock_irqsave(revpt_lock_for_pfn(pfn), irqflags);
	info->flags |= set_mask;
	info->flags &= ~clear_mask;
	info->generation++;
	raw_spin_unlock_irqrestore(revpt_lock_for_pfn(pfn), irqflags);

	(void)revpt_check_pfn(pfn);
	return 0;
}

int revpt_set_flags_range(u64 start_pfn, u64 nr_pages, u16 set_mask, u16 clear_mask)
{
	u64 i;

	if (!nr_pages)
		return 0;
	if (!revpt_pfn_valid(start_pfn) || nr_pages > REV_PT_NR_PAGES - start_pfn)
		return -EINVAL;

	for (i = 0; i < nr_pages; i++)
		(void)revpt_set_flags(start_pfn + i, set_mask, clear_mask);

	return 0;
}

int revpt_snapshot_pfn(u64 pfn, struct pfn_info *out)
{
	unsigned long irqflags;

	if (!out)
		return -EINVAL;
	if (!revpt_pfn_valid(pfn))
		return -EINVAL;

	revpt_ensure_init();

	raw_spin_lock_irqsave(revpt_lock_for_pfn(pfn), irqflags);
	*out = rev_pt[pfn];
	raw_spin_unlock_irqrestore(revpt_lock_for_pfn(pfn), irqflags);

	return 0;
}

static int __revpt_change_ref(u64 pfn, enum revpt_ref_type type, bool inc)
{
	unsigned long irqflags;
	struct pfn_info snapshot;
	struct pfn_info *info;
	u16 *slot;
	u32 reason = 0;

	if (!revpt_pfn_valid(pfn))
		return -EINVAL;

	revpt_ensure_init();
	info = &rev_pt[pfn];

	raw_spin_lock_irqsave(revpt_lock_for_pfn(pfn), irqflags);

	slot = revpt_ref_slot(info, type);
	if (!slot) {
		raw_spin_unlock_irqrestore(revpt_lock_for_pfn(pfn), irqflags);
		return -EINVAL;
	}

	if (inc) {
		if (*slot == U16_MAX) {
			reason = revpt_ref_overflow_reason(type);
		} else {
			(*slot)++;
			info->generation++;
		}
	} else {
		if (*slot == 0) {
			reason = revpt_ref_underflow_reason(type);
		} else {
			(*slot)--;
			info->generation++;
		}
	}

	snapshot = *info;
	raw_spin_unlock_irqrestore(revpt_lock_for_pfn(pfn), irqflags);

	if (reason)
		revpt_record_violation(pfn, &snapshot, reason);

	(void)revpt_check_pfn(pfn);
	return reason ? -ERANGE : 0;
}

int revpt_ref_inc(u64 pfn, enum revpt_ref_type type)
{
	return __revpt_change_ref(pfn, type, true);
}

int revpt_ref_dec(u64 pfn, enum revpt_ref_type type)
{
	return __revpt_change_ref(pfn, type, false);
}

int revpt_ref_inc_range(u64 start_pfn, u64 nr_pages, enum revpt_ref_type type)
{
	u64 i;
	int ret = 0;

	if (!nr_pages)
		return 0;
	if (!revpt_pfn_valid(start_pfn) || nr_pages > REV_PT_NR_PAGES - start_pfn)
		return -EINVAL;

	for (i = 0; i < nr_pages; i++) {
		ret = __revpt_change_ref(start_pfn + i, type, true);
		if (ret)
			return ret;
	}

	return 0;
}

int revpt_ref_dec_range(u64 start_pfn, u64 nr_pages, enum revpt_ref_type type)
{
	u64 i;
	int ret = 0;

	if (!nr_pages)
		return 0;
	if (!revpt_pfn_valid(start_pfn) || nr_pages > REV_PT_NR_PAGES - start_pfn)
		return -EINVAL;

	for (i = 0; i < nr_pages; i++) {
		ret = __revpt_change_ref(start_pfn + i, type, false);
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * Bootstrap helpers.
 *
 * These are meant for your one-shot initial state construction after boot /
 * after a pgtable walk. Unlike reset_owner(), bootstrap helpers zero refs and
 * write a known-good baseline state.
 */
static int __revpt_bootstrap_one(u64 pfn, u8 owner, u16 flags, u8 allowed_mask)
{
	unsigned long irqflags;
	struct pfn_info *info;

	if (!revpt_pfn_valid(pfn))
		return -EINVAL;

	revpt_ensure_init();
	info = &rev_pt[pfn];

	raw_spin_lock_irqsave(revpt_lock_for_pfn(pfn), irqflags);
	info->owner = owner;
	info->flags = flags | PFN_F_TRACKED;
	info->allowed_mask = allowed_mask;
	revpt_zero_refs(info);
	info->generation++;
	raw_spin_unlock_irqrestore(revpt_lock_for_pfn(pfn), irqflags);

	return 0;
}

int revpt_bootstrap_host_ram_range(u64 start_pfn, u64 nr_pages)
{
	u64 i;

	if (!nr_pages)
		return 0;
	if (!revpt_pfn_valid(start_pfn) || nr_pages > REV_PT_NR_PAGES - start_pfn)
		return -EINVAL;

	for (i = 0; i < nr_pages; i++) {
		(void)__revpt_bootstrap_one(start_pfn + i,
					    OWN_HOST,
					    PFN_F_RAM,
					    ACC_HOST_CPU | ACC_HOST_DMA);
	}
	return 0;
}

int revpt_bootstrap_free_ram_range(u64 start_pfn, u64 nr_pages)
{
	u64 i;

	if (!nr_pages)
		return 0;
	if (!revpt_pfn_valid(start_pfn) || nr_pages > REV_PT_NR_PAGES - start_pfn)
		return -EINVAL;

	for (i = 0; i < nr_pages; i++) {
		(void)__revpt_bootstrap_one(start_pfn + i,
					    OWN_FREE,
					    PFN_F_RAM,
					    0);
	}
	return 0;
}

int revpt_bootstrap_hyp_sensitive_range(u64 start_pfn, u64 nr_pages, u16 extra_flags)
{
	u64 i;

	if (!nr_pages)
		return 0;
	if (!revpt_pfn_valid(start_pfn) || nr_pages > REV_PT_NR_PAGES - start_pfn)
		return -EINVAL;

	for (i = 0; i < nr_pages; i++) {
		(void)__revpt_bootstrap_one(start_pfn + i,
					    OWN_HYP,
					    PFN_F_RAM | PFN_F_SENSITIVE | extra_flags,
					    ACC_HYP_CPU);
	}
	return 0;
}

int revpt_bootstrap_mmio_range(u64 start_pfn, u64 nr_pages)
{
	u64 i;

	if (!nr_pages)
		return 0;
	if (!revpt_pfn_valid(start_pfn) || nr_pages > REV_PT_NR_PAGES - start_pfn)
		return -EINVAL;

	for (i = 0; i < nr_pages; i++) {
		(void)__revpt_bootstrap_one(start_pfn + i,
					    OWN_HYP,
					    PFN_F_MMIO | PFN_F_SENSITIVE,
					    ACC_HYP_CPU);
	}
	return 0;
}

/*
 * Compatibility wrappers matching your original interface.
 * Semantics:
 *   host_refs         -> host CPU refs
 *   host_dev_refs     -> host DMA / host-controlled device refs
 *   enclave_refs      -> enclave CPU refs
 *   enclave_dev_refs  -> enclave-side device refs, e.g. NPU DMA
 *   hyp_refs          -> hypervisor refs
 */

void host_inc_ref(u64 pfn)
{
	(void)revpt_ref_inc(pfn, REVPT_REF_HOST_CPU);
}

void host_dec_ref(u64 pfn)
{
	(void)revpt_ref_dec(pfn, REVPT_REF_HOST_CPU);
}

void host_dev_inc_ref(u64 pfn)
{
	(void)revpt_ref_inc(pfn, REVPT_REF_HOST_DMA);
}

void host_dev_dec_ref(u64 pfn)
{
	(void)revpt_ref_dec(pfn, REVPT_REF_HOST_DMA);
}

void enclave_inc_ref(u64 pfn)
{
	(void)revpt_ref_inc(pfn, REVPT_REF_ENCLAVE_CPU);
}

void enclave_dec_ref(u64 pfn)
{
	(void)revpt_ref_dec(pfn, REVPT_REF_ENCLAVE_CPU);
}

void enclave_dev_inc_ref(u64 pfn)
{
	(void)revpt_ref_inc(pfn, REVPT_REF_ENCLAVE_DMA);
}

void enclave_dev_dec_ref(u64 pfn)
{
	(void)revpt_ref_dec(pfn, REVPT_REF_ENCLAVE_DMA);
}

void hyp_inc_ref(u64 pfn)
{
	(void)revpt_ref_inc(pfn, REVPT_REF_HYP_CPU);
}

void hyp_dec_ref(u64 pfn)
{
	(void)revpt_ref_dec(pfn, REVPT_REF_HYP_CPU);
}