/* SPDX-License-Identifier: GPL-2.0 */
/*
 * PFN 安全账本 / 反向页追踪接口（pKVM-ASGARD 实验）。
 *
 * 该接口只负责声明数据结构和外部 API，具体实现见 pfn_info.c。
 */

#ifndef __ARM64_KVM_NVHE_PFN_INFO_H__
#define __ARM64_KVM_NVHE_PFN_INFO_H__

#include <linux/bitops.h>
#include <linux/build_bug.h>
#include <linux/types.h>
#include <asm/page.h>
#include <linux/pkvm_asgard.h>

/* 页当前所有者。 */
enum page_owner {
	OWN_FREE = 0,
	OWN_HOST = 1,
	OWN_ENCLAVE = 2,
	OWN_HYP = 3,
};

/* PFN 的属性标志位。 */
enum revpt_flags {
	PFN_F_TRACKED     = BIT(0), /* 该 PFN 被账本追踪 */
	PFN_F_RAM         = BIT(1), /* 普通内存页 */
	PFN_F_MMIO        = BIT(2), /* MMIO 窗口 */
	PFN_F_SENSITIVE   = BIT(3), /* 仅 Hypervisor 可持有的敏感页 */
	PFN_F_MMU_PT      = BIT(4), /* CPU MMU 页表页 */
	PFN_F_IOMMU_PT    = BIT(5), /* IOMMU 页表页 */
	PFN_F_SHARED_HINT = BIT(6), /* 仅提示：页面处于共享态 */
};

/* 访问权限位（逻辑授权）。 */
enum revpt_access_bits {
	ACC_HOST_CPU    = BIT(0),
	ACC_HOST_DMA    = BIT(1),
	ACC_ENCLAVE_CPU = BIT(2),
	ACC_ENCLAVE_DMA = BIT(3), /* enclave 侧设备访问，例如 NPU DMA */
	ACC_HYP_CPU     = BIT(4),
};

#define ACC_NPU_DMA ACC_ENCLAVE_DMA

/* 物理引用计数类型。 */
enum revpt_ref_type {
	REVPT_REF_HOST_CPU = 0,
	REVPT_REF_HOST_DMA,
	REVPT_REF_ENCLAVE_CPU,
	REVPT_REF_ENCLAVE_DMA,
	REVPT_REF_HYP_CPU,
};

/* 一致性检查失败的原因位。 */
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
#define PMEM_SIZE (16ULL * 1024 * 1024 * 1024) /* 默认 16GB 物理窗口 */
#endif

#define REV_PT_NR_PAGES     ((u64)PMEM_SIZE >> PAGE_SHIFT)
#define REV_PT_LOCK_STRIPES 4096U /* 必须是 2 的幂 */
#define MAX_VIOLATE_NUM     1024

/* 每个 PFN 的账本条目（紧凑 16B）。 */
struct pfn_info {
	u8  owner;
	u8  allowed_mask;
	u16 flags;

	u16 host_refs;         /* host CPU / host stage-2 引用 */
	u16 host_dev_refs;     /* host 控制设备 / host DMA 引用 */
	u16 enclave_refs;      /* enclave CPU 引用 */
	u16 enclave_dev_refs;  /* enclave 侧设备引用（例如 NPU DMA） */
	u16 hyp_refs;          /* hypervisor 引用 */

	u16 generation;        /* 条目版本号，每次更新递增 */
};

static_assert(sizeof(struct pfn_info) == 16);

/* 违规记录快照。 */
struct violate_info {
	u64 pfn;
	u32 reason;
	struct pfn_info info;
};

/*
 * 全局账本和违规列表。
 * 说明：保持为 extern 以兼容原始使用方式。
 */
extern struct pfn_info rev_pt[REV_PT_NR_PAGES];
extern u32 violate_num;
extern struct violate_info violate_list[MAX_VIOLATE_NUM];

/* 生命周期管理。 */
/* 初始化账本内部锁与状态，可重复调用。 */
int revpt_init(void);
/* 清空全部 PFN 条目和违规记录，恢复到初始状态。 */
void revpt_reset_all(void);

/* 一致性检查接口。 */
/* 检查单个 PFN 的账本一致性，返回违规原因位掩码（0 表示无违规）。 */
u32 revpt_check_pfn(u64 pfn);
/* 检查一段 PFN 范围，返回发生违规的页数。 */
u32 revpt_check_range(u64 start_pfn, u64 nr_pages);
/* 兼容旧接口：按 int PFN 触发一次单页一致性检查。 */
void check_oracle(int pfn);

/* 所有者和访问控制接口。 */
/* 兼容旧接口：更新页面 owner，并重置为该 owner 的默认授权。 */
void reset_owner(u64 pfn, enum page_owner owner);
/* 设置单页 owner，同时刷新默认授权并清除共享提示位。 */
int revpt_set_owner(u64 pfn, enum page_owner owner);
/* 批量设置 owner，逐页执行与 revpt_set_owner 相同的语义。 */
int revpt_set_owner_range(u64 start_pfn, u64 nr_pages, enum page_owner owner);
/* 将页面恢复为“独占”授权（仅保留 owner 默认访问权限）。 */
void make_exclusively_owned(u64 pfn);
/* 仅设置共享提示位，不授予任何新访问权限。 */
void make_shared(u64 pfn);
/* 为单页增加访问授权位；若超出 owner 默认授权，会标记共享提示位。 */
int revpt_grant_access(u64 pfn, u8 access_mask);
/* 撤销单页指定访问授权位；若回到默认授权，会清除共享提示位。 */
int revpt_revoke_access(u64 pfn, u8 access_mask);
/* 批量授予访问权限，逐页执行 revpt_grant_access。 */
int revpt_grant_access_range(u64 start_pfn, u64 nr_pages, u8 access_mask);
/* 批量撤销访问权限，逐页执行 revpt_revoke_access。 */
int revpt_revoke_access_range(u64 start_pfn, u64 nr_pages, u8 access_mask);

/* 标志位与快照接口。 */
/* 更新单页 flags：先置位 set_mask，再清位 clear_mask。 */
int revpt_set_flags(u64 pfn, u16 set_mask, u16 clear_mask);
/* 批量更新 flags，逐页执行 revpt_set_flags。 */
int revpt_set_flags_range(u64 start_pfn, u64 nr_pages, u16 set_mask, u16 clear_mask);
/* 拷贝单页当前账本条目到 out，用于调试或上层决策。 */
int revpt_snapshot_pfn(u64 pfn, struct pfn_info *out);

/* 引用计数接口。 */
/* 单页指定类型引用计数 +1，溢出返回 -ERANGE。 */
int revpt_ref_inc(u64 pfn, enum revpt_ref_type type);
/* 单页指定类型引用计数 -1，下溢返回 -ERANGE。 */
int revpt_ref_dec(u64 pfn, enum revpt_ref_type type);
/* 批量执行引用计数 +1，遇到错误立即返回。 */
int revpt_ref_inc_range(u64 start_pfn, u64 nr_pages, enum revpt_ref_type type);
/* 批量执行引用计数 -1，遇到错误立即返回。 */
int revpt_ref_dec_range(u64 start_pfn, u64 nr_pages, enum revpt_ref_type type);

/* 启动期一次性基线构建接口。 */
/* 启动期批量写入“Host RAM 已占用”基线状态（带 host 默认授权，计数清零）。 */
int revpt_bootstrap_host_ram_range(u64 start_pfn, u64 nr_pages);
/* 启动期批量写入“空闲 RAM”基线状态（无授权，计数清零）。 */
int revpt_bootstrap_free_ram_range(u64 start_pfn, u64 nr_pages);
/* 启动期批量写入“Hyp 敏感页”基线状态（仅 Hyp CPU 可访问）。 */
int revpt_bootstrap_hyp_sensitive_range(u64 start_pfn, u64 nr_pages, u16 extra_flags);
/* 启动期批量写入 MMIO 敏感窗口基线状态（owner=Hyp）。 */
int revpt_bootstrap_mmio_range(u64 start_pfn, u64 nr_pages);

/* 导出违规记录给 host。 */
int revpt_copy_violations(struct pkvm_asgard_violation *out, u32 cap, u32 *copied,
			 u32 *total);
/* 触发一次全量检查。 */
void revpt_force_rescan(void);

#endif /* __ARM64_KVM_NVHE_PFN_INFO_H__ */
