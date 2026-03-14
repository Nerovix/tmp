#include <fcntl.h>
#include "pkvm_asgard_uapi.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static void print_reason(uint32_t r)
{
	printf("reason=0x%x", r);
	if (r & (1u << 1))
		printf(" UNTRACKED_HAS_STATE");
	if (r & (1u << 2))
		printf(" FREE_HAS_ACCESS");
	if (r & (1u << 3))
		printf(" FREE_HAS_REFS");
	if (r & (1u << 8))
		printf(" HOST_CPU_DISALLOWED");
	if (r & (1u << 9))
		printf(" HOST_DMA_DISALLOWED");
	if (r & (1u << 10))
		printf(" ENCL_CPU_DISALLOWED");
	if (r & (1u << 11))
		printf(" ENCL_DMA_DISALLOWED");
	if (r & (1u << 12))
		printf(" HYP_CPU_DISALLOWED");
	if (r & (1u << 5))
		printf(" SENSITIVE_BAD_OWNER");
	if (r & (1u << 7))
		printf(" SENSITIVE_BAD_REFS");
	putchar('\n');
}

int main(int argc, char **argv)
{
	struct pkvm_asgard_violation_query q = {0};
	struct pkvm_asgard_violation *buf;
	uint32_t cap = 128;
	int fd;
	uint32_t i;

	if (argc == 2)
		cap = (uint32_t)strtoul(argv[1], NULL, 0);
	buf = calloc(cap, sizeof(*buf));
	if (!buf)
		return 1;

	fd = open("/dev/pkvm_asgard", O_RDWR);
	if (fd < 0) {
		perror("open /dev/pkvm_asgard");
		free(buf);
		return 1;
	}

	q.user_buf = (uintptr_t)buf;
	q.capacity = cap;
	if (ioctl(fd, PKVM_ASGARD_IOC_GET_VIOLATIONS, &q) < 0) {
		perror("ioctl GET_VIOLATIONS");
		close(fd);
		free(buf);
		return 1;
	}

	printf("copied=%u total=%u\n", q.copied, q.total);
	for (i = 0; i < q.copied; i++) {
		printf("[%u] pfn=0x%llx owner=%u allowed=0x%x flags=0x%x host_refs=%u host_dev_refs=%u enclave_refs=%u enclave_dev_refs=%u hyp_refs=%u generation=%u ",
		       i, (unsigned long long)buf[i].pfn,
		       buf[i].info.owner,
		       buf[i].info.allowed_mask,
		       buf[i].info.flags,
		       buf[i].info.host_refs,
		       buf[i].info.host_dev_refs,
		       buf[i].info.enclave_refs,
		       buf[i].info.enclave_dev_refs,
		       buf[i].info.hyp_refs,
		       buf[i].info.generation);
		print_reason(buf[i].reason);
	}

	close(fd);
	free(buf);
	return 0;
}
