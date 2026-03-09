#include <fcntl.h>
#include "pkvm_asgard_uapi.h"
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* 用途：命令 pkvm 锁定并遍历所有主体页表，重建 rev_pt 初始状态。 */
int main(void)
{
	int fd = open("/dev/pkvm_asgard", O_RDWR);
	if (fd < 0) {
		perror("open /dev/pkvm_asgard");
		return 1;
	}
	if (ioctl(fd, PKVM_ASGARD_IOC_CAPTURE_BASELINE) < 0) {
		perror("ioctl CAPTURE_BASELINE");
		close(fd);
		return 1;
	}
	puts("revpt baseline captured from pagetables");
	close(fd);
	return 0;
}
