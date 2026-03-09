/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ARM64_KVM_NVHE_REVPT_BASELINE_H__
#define __ARM64_KVM_NVHE_REVPT_BASELINE_H__

/*
 * 在 host 组件锁保护下执行：
 * - 锁住 hyp/host/guest 页表
 * - 遍历页表并重建 rev_pt 的 CPU 可达性基线
 */
int revpt_capture_cpu_baseline_locked(void);

#endif
