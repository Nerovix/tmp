#include <fcntl.h>
#include "pkvm_asgard_uapi.h"
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* 用途：板端直接运行的最小测试工具。 */
int main(void)
{
	int fd = open("/dev/pkvm_asgard", O_RDWR);
	if (fd < 0) {
		perror("open /dev/pkvm_asgard");
		return 1;
	}
	if (ioctl(fd, PKVM_ASGARD_IOC_SYNC_LEDGER) < 0) {
		perror("ioctl SYNC_LEDGER");
		close(fd);
		return 1;
	}
	puts("revpt sync done");
	close(fd);
	return 0;
}
