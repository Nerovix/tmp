#include <fcntl.h>
#include "pkvm_asgard_uapi.h"
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main(void)
{
	int fd = open("/dev/pkvm_asgard", O_RDWR);

	if (fd < 0) {
		perror("open /dev/pkvm_asgard");
		return 1;
	}

	if (ioctl(fd, PKVM_ASGARD_IOC_SYNC_TEST) < 0) {
		perror("ioctl SYNC_TEST");
		close(fd);
		return 1;
	}

	puts("revpt SYNC_TEST done");
	close(fd);
	return 0;
}
