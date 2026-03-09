#ifndef __PKVM_ASGARD_UAPI_H
#define __PKVM_ASGARD_UAPI_H

#include <stdint.h>
#include <sys/ioctl.h>

struct pkvm_asgard_pfn_info {
	uint8_t owner;
	uint8_t allowed_mask;
	uint16_t flags;
	uint16_t host_refs;
	uint16_t host_dev_refs;
	uint16_t enclave_refs;
	uint16_t enclave_dev_refs;
	uint16_t hyp_refs;
	uint16_t generation;
};

struct pkvm_asgard_violation {
	uint64_t pfn;
	uint32_t reason;
	uint32_t reserved;
	struct pkvm_asgard_pfn_info info;
};

struct pkvm_asgard_violation_query {
	uint64_t user_buf;
	uint32_t capacity;
	uint32_t copied;
	uint32_t total;
	uint32_t reserved;
};

#define PKVM_ASGARD_IOC_MAGIC 'P'
#define PKVM_ASGARD_IOC_SET_HOST_DMA_DOMAIN \
	_IOW(PKVM_ASGARD_IOC_MAGIC, 0x01, uint32_t)
#define PKVM_ASGARD_IOC_RECHECK_LEDGER _IO(PKVM_ASGARD_IOC_MAGIC, 0x02)
#define PKVM_ASGARD_IOC_SYNC_LEDGER PKVM_ASGARD_IOC_RECHECK_LEDGER
#define PKVM_ASGARD_IOC_GET_VIOLATIONS \
	_IOWR(PKVM_ASGARD_IOC_MAGIC, 0x03, struct pkvm_asgard_violation_query)
#define PKVM_ASGARD_IOC_CAPTURE_BASELINE _IO(PKVM_ASGARD_IOC_MAGIC, 0x04)

#endif
