/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ARM64_KVM_NVHE_REVPT_BASELINE_H__
#define __ARM64_KVM_NVHE_REVPT_BASELINE_H__

#include <linux/types.h>
#include <asm/page.h>

struct revpt_test_cfg {
	bool active;
	u64 hpa_start;
	u64 hpa_size;
	u32 host_dma_domain;
};

extern struct revpt_test_cfg revpt_test_cfg;

bool revpt_pa_overlap_enabled(phys_addr_t pa, u64 size,
			      u64 *clip_pfn, u64 *clip_pages);

/*
 * 在 host 组件锁保护下执行：
 * - 锁住 hyp/host/guest 页表
 * - 遍历页表并重建 rev_pt 的 CPU 可达性基线
 */
int revpt_capture_cpu_baseline_locked(u64 *cpu_snapshot_pages);

#endif
