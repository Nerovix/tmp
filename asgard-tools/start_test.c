#include <fcntl.h>
#include "pkvm_asgard_uapi.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	struct pkvm_asgard_test_cfg cfg = {0};
	int fd;

	if (argc != 4) {
		fprintf(stderr, "usage: %s <hpa_start> <hpa_size> <host_dma_domain>\n", argv[0]);
		return 1;
	}

	cfg.hpa_start = strtoull(argv[1], NULL, 0);
	cfg.hpa_size = strtoull(argv[2], NULL, 0);
	cfg.host_dma_domain = (uint32_t)strtoul(argv[3], NULL, 0);

	fd = open("/dev/pkvm_asgard", O_RDWR);
	if (fd < 0) {
		perror("open /dev/pkvm_asgard");
		return 1;
	}

	if (ioctl(fd, PKVM_ASGARD_IOC_START_TEST, &cfg) < 0) {
		perror("ioctl START_TEST");
		close(fd);
		return 1;
	}

	printf("revpt START_TEST ok: hpa_start=0x%llx hpa_size=0x%llx host_dma_domain=%u\n",
	       (unsigned long long)cfg.hpa_start,
	       (unsigned long long)cfg.hpa_size,
	       cfg.host_dma_domain);
	close(fd);
	return 0;
}
