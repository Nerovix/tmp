#include <fcntl.h>
#include "pkvm_asgard_uapi.h"
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* 用途：保留的全量复检工具（旧 sync 语义）。 */
int main(void)
{
	int fd = open("/dev/pkvm_asgard", O_RDWR);
	if (fd < 0) {
		perror("open /dev/pkvm_asgard");
		return 1;
	}
	if (ioctl(fd, PKVM_ASGARD_IOC_RECHECK_LEDGER) < 0) {
		perror("ioctl RECHECK_LEDGER");
		close(fd);
		return 1;
	}
	puts("revpt full recheck done");
	close(fd);
	return 0;
}
