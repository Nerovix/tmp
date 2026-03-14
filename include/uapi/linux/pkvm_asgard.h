/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_PKVM_ASGARD_H
#define _UAPI_LINUX_PKVM_ASGARD_H

#include <linux/ioctl.h>
#include <linux/types.h>

/* ASGARD 板端测试使用的 UAPI。 */

struct pkvm_asgard_pfn_info {
	__u8 owner;
	__u8 allowed_mask;
	__u16 flags;
	__u16 host_refs;
	__u16 host_dev_refs;
	__u16 enclave_refs;
	__u16 enclave_dev_refs;
	__u16 hyp_refs;
	__u16 generation;
};

struct pkvm_asgard_violation {
	__u64 pfn;
	__u32 reason;
	__u32 reserved;
	struct pkvm_asgard_pfn_info info;
};

struct pkvm_asgard_violation_query {
	__u64 user_buf;
	__u32 capacity;
	__u32 copied;
	__u32 total;
	__u32 reserved;
};

struct pkvm_asgard_test_cfg {
	__u64 hpa_start;
	__u64 hpa_size;
	__u32 host_dma_domain;
	__u32 reserved;
};

#define PKVM_ASGARD_IOC_MAGIC 'P'
#define PKVM_ASGARD_IOC_START_TEST 	_IOW(PKVM_ASGARD_IOC_MAGIC, 0x01, struct pkvm_asgard_test_cfg)
#define PKVM_ASGARD_IOC_SYNC_TEST _IO(PKVM_ASGARD_IOC_MAGIC, 0x02)
#define PKVM_ASGARD_IOC_GET_VIOLATIONS 	_IOWR(PKVM_ASGARD_IOC_MAGIC, 0x03, struct pkvm_asgard_violation_query)


#endif
