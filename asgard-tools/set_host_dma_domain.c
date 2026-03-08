#include <fcntl.h>
#include "pkvm_asgard_uapi.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* 用途：板端直接运行的最小测试工具。 */
int main(int argc, char **argv)
{
	uint32_t domain;
	int fd;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <domain_id>\n", argv[0]);
		return 1;
	}
	domain = (uint32_t)strtoul(argv[1], NULL, 0);
	fd = open("/dev/pkvm_asgard", O_RDWR);
	if (fd < 0) {
		perror("open /dev/pkvm_asgard");
		return 1;
	}
	if (ioctl(fd, PKVM_ASGARD_IOC_SET_HOST_DMA_DOMAIN, &domain) < 0) {
		perror("ioctl SET_HOST_DMA_DOMAIN");
		close(fd);
		return 1;
	}
	printf("host dma domain set to %u\n", domain);
	close(fd);
	return 0;
}
