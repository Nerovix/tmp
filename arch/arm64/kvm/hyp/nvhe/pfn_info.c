// SPDX-License-Identifier: GPL-2.0
/*
 * PFN 安全账本 / 反向页追踪实现。
 *
 * 设计说明：
 * - 仅按 4KiB 粒度追踪
 * - 采用稠密数组覆盖 [0, PMEM_SIZE)
 * - 使用锁分片（lock striping）降低竞争
 * - 引用计数为 u16，并做溢出/下溢检测
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/pkvm_asgard.h>

#include <nvhe/pfn_info.h>

static_assert((REV_PT_LOCK_STRIPES & (REV_PT_LOCK_STRIPES - 1)) == 0);

/* 全局账本和违规记录。 */
struct pfn_info rev_pt[REV_PT_NR_PAGES];
u32 violate_num;
struct violate_info violate_list[MAX_VIOLATE_NUM];

/* 锁与初始化状态。 */
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

/* 延迟初始化锁分片，允许在早期调用路径上安全重复进入。 */
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


void revpt_clear_violations(void)
{
	unsigned long irqflags;

	revpt_ensure_init();
	raw_spin_lock_irqsave(&revpt_violate_lock, irqflags);
	violate_num = 0;
	raw_spin_unlock_irqrestore(&revpt_violate_lock, irqflags);
}

void revpt_reset_range(u64 start_pfn, u64 nr_pages)
{
	u64 i;

	revpt_ensure_init();
	if (!nr_pages)
		return;
	if (!revpt_pfn_valid(start_pfn) || nr_pages > REV_PT_NR_PAGES - start_pfn)
		return;

	for (i = 0; i < nr_pages; i++) {
		u64 pfn = start_pfn + i;
		unsigned long irqflags;
		struct pfn_info *info = &rev_pt[pfn];
		u16 static_flags;

		raw_spin_lock_irqsave(revpt_lock_for_pfn(pfn), irqflags);
		static_flags = info->flags &
			(PFN_F_RAM | PFN_F_MMIO | PFN_F_SENSITIVE |
			 PFN_F_MMU_PT | PFN_F_IOMMU_PT);
		info->owner = OWN_FREE;
		info->allowed_mask = 0;
		info->flags = static_flags;
		info->host_refs = 0;
		info->host_dev_refs = 0;
		info->enclave_refs = 0;
		info->enclave_dev_refs = 0;
		info->hyp_refs = 0;
		info->generation++;
		raw_spin_unlock_irqrestore(revpt_lock_for_pfn(pfn), irqflags);
	}
}
/* 基于 owner 计算默认授权掩码。 */
static inline u8 revpt_default_access_for_owner(u8 owner)
{
	switch (owner) {
	case OWN_HOST:
		return ACC_HOST_CPU | ACC_HOST_DMA;
	case OWN_ENCLAVE:
		/* enclave 默认仅允许 enclave CPU 访问。 */
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

/* 从计数状态导出“实际正在访问”的主体集合。 */
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

/* 记录违规快照，便于离线追踪。 */
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

/* 对快照执行一致性检查，不直接持锁。 */
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

/* 更新 owner 时重置共享提示与默认授权，不主动清理旧引用。 */
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

/* 原子化修改单类引用计数，并记录溢出/下溢。 */
static int __revpt_change_ref(u64 pfn, enum revpt_ref_type type, bool inc)
{
	unsigned long irqflags;
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

	raw_spin_unlock_irqrestore(revpt_lock_for_pfn(pfn), irqflags);

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
 * 启动期基线写入：直接写成已知正确状态，并清零引用计数。
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



/* 导出违规快照给 host。调用方需保证 out 缓冲区可写。 */
int revpt_copy_violations(struct pkvm_asgard_violation *out, u32 cap, u32 *copied,
			 u32 *total)
{
	unsigned long irqflags;
	u32 i, cnt;

	if (!copied || !total)
		return -EINVAL;

	raw_spin_lock_irqsave(&revpt_violate_lock, irqflags);
	*total = violate_num;
	cnt = min(cap, violate_num);
	*copied = cnt;

	for (i = 0; i < cnt; i++) {
		out[i].pfn = violate_list[i].pfn;
		out[i].reason = violate_list[i].reason;
		out[i].reserved = 0;
		out[i].info.owner = violate_list[i].info.owner;
		out[i].info.allowed_mask = violate_list[i].info.allowed_mask;
		out[i].info.flags = violate_list[i].info.flags;
		out[i].info.host_refs = violate_list[i].info.host_refs;
		out[i].info.host_dev_refs = violate_list[i].info.host_dev_refs;
		out[i].info.enclave_refs = violate_list[i].info.enclave_refs;
		out[i].info.enclave_dev_refs = violate_list[i].info.enclave_dev_refs;
		out[i].info.hyp_refs = violate_list[i].info.hyp_refs;
		out[i].info.generation = violate_list[i].info.generation;
	}
	raw_spin_unlock_irqrestore(&revpt_violate_lock, irqflags);

	return 0;
}
