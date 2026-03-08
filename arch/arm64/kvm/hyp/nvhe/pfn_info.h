#include "asm-generic/int-ll64.h"
#include "linux/spinlock_types.h"
#include <linux/types.h>
#include <asm/page-def.h>

enum page_owner {
	OWN_HOST = 0,
	OWN_ENCLAVE = 1,
	OWN_HYP = 2,
};

#define PMEM_SIZE ((size_t)16 * 1024 * 1024 * 1024) /* 16 GB */

struct pfn_info {
	u8 owner;
	u8 is_shared;
	u16 host_refs;
	u16 host_dev_refs;
	u16 enclave_refs;
	u16 enclave_dev_refs;
	u16 hyp_refs;
	spinlock_t lock;
} rev_pt[PMEM_SIZE >> PAGE_SHIFT];

#define check_pfn_valid(pfn)                                                   \
	do {                                                                   \
		if (pfn >= PMEM_SIZE >> PAGE_SHIFT)                            \
			return;                                                \
	} while (0)

void reset_owner(u64 pfn,
		 enum page_owner owner) // change the owner to ...
{
	check_pfn_valid(pfn);
	rev_pt[pfn].owner = owner;
}

void make_exclusively_owned(u64 pfn) // mark the page is not shared
{
	check_pfn_valid(pfn);
	rev_pt[pfn].is_shared = 0;
}

void make_shared(u64 pfn) // mark the page is shared
{
	check_pfn_valid(pfn);
	rev_pt[pfn].is_shared = 1;
}

void host_inc_ref(u64 pfn)
{
	check_pfn_valid(pfn);
	rev_pt[pfn].host_refs++;
}

void host_dec_ref(u64 pfn)
{
	check_pfn_valid(pfn);
	rev_pt[pfn].host_refs--;
}

void host_dev_inc_ref(u64 pfn)
{
	check_pfn_valid(pfn);
	rev_pt[pfn].host_dev_refs++;
}

void host_dev_dec_ref(u64 pfn)
{
	check_pfn_valid(pfn);
	rev_pt[pfn].host_dev_refs--;
}

void enclave_inc_ref(u64 pfn)
{
	check_pfn_valid(pfn);
	rev_pt[pfn].enclave_refs++;
}

void enclave_dec_ref(u64 pfn)
{
	check_pfn_valid(pfn);
	rev_pt[pfn].enclave_refs--;
}

void enclave_dev_inc_ref(u64 pfn)
{
	check_pfn_valid(pfn);
	rev_pt[pfn].enclave_dev_refs++;
}

void enclave_dev_dec_ref(u64 pfn)
{
	check_pfn_valid(pfn);
	rev_pt[pfn].enclave_dev_refs--;
}

void hyp_inc_ref(u64 pfn)
{
	check_pfn_valid(pfn);
	rev_pt[pfn].hyp_refs++;
}

void hyp_dec_ref(u64 pfn)
{
	check_pfn_valid(pfn);
	rev_pt[pfn].hyp_refs--;
}

#define MAX_VIOLATE_NUM 1024
struct violate_info {
	u64 pfn;
	struct pfn_info info;
};

u32 violate_num = 0;
struct violate_info violate_list[MAX_VIOLATE_NUM];

void check_oracle(u64 pfn)
{
	const struct pfn_info *info;

	check_pfn_valid(pfn);
	info = &rev_pt[pfn];

	// shared?
	if (info->is_shared) {
		switch (info->owner) {
		case OWN_HOST:
			if (info->enclave_refs || info->enclave_dev_refs ||
			    info->hyp_refs)
				goto violation;
			break;
		case OWN_ENCLAVE:
			if (info->host_refs || info->host_dev_refs ||
			    info->hyp_refs)
				goto violation;
			break;
		case OWN_HYP:
			if (info->host_refs || info->host_dev_refs ||
			    info->enclave_refs || info->enclave_dev_refs)
				goto violation;
			break;
		default:
			goto violation;
		}
	}

	if (info->host_dev_refs && !info->host_refs) {
		goto violation;
	}

	if (info->enclave_dev_refs && !info->enclave_refs) {
		goto violation;
	}
	return;

violation:
	if (violate_num < MAX_VIOLATE_NUM) {
		violate_list[violate_num].pfn = pfn;
		violate_list[violate_num].info = *info;
		violate_num++;
	}
	return;
}
