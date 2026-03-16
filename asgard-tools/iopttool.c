
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_view_stage2_pt
#define __NR_view_stage2_pt 441
#endif

#ifndef __NR_stage2_pt_count
#define __NR_stage2_pt_count 442
#endif

#ifndef __NR_get_shadow_handles
#define __NR_get_shadow_handles 443
#endif

#ifndef __NR_view_iopt
#define __NR_view_iopt 444
#endif

#ifndef __NR_ls_devices
#define __NR_ls_devices 445
#endif

#ifndef __NR_alloc_domain
#define __NR_alloc_domain 446
#endif

#ifndef __NR_iopt_map
#define __NR_iopt_map 447
#endif

#define cap (1 << 15)
unsigned long long pool[cap * 4];
int main(int argc, char *argv[]) {
  char dev_name[100];
  if (argc <= 1) {
    printf("Usage:\n\t%s <dev_name> <phys_l> <phys_r>\n\t%s ls\n\t%s alloc\n\t%s map <dev_name> "
           "<iova_hex(0x...)> <ipa_hex(0x...)>\n",
           argv[0], argv[0], argv[0], argv[0]);
    return 0;
  }
  strcpy(dev_name, argv[1]);

  if (strcmp(dev_name, "ls") == 0) {
    int ret = syscall(__NR_ls_devices);
    if (ret < 0) {
      printf("ls_dev failed: %d\n", ret);
      return -1;
    }
    printf("ls_dev success\n");
    printf("Devices and Domains are listed with printk. Use `dmesg | "
           "grep ls_dev` to see.\n");
    return 0;
  }
  if (strcmp(dev_name, "alloc") == 0) {
    int ret = syscall(__NR_alloc_domain);
    if (ret < 0) {
      printf("alloc_domain failed: %d\n", ret);
      return -1;
    }
    printf("Created a new domain: vdev_%d\n", ret);
    return 0;
  }
  if (strcmp(dev_name, "map") == 0) {
    if (argc != 5) {
      printf("Usage: %s map <dev_name> <iova_hex(0x...)> <ipa_hex(0x...)>\n",
             argv[0]);
      return -1;
    }
    strcpy(dev_name, argv[2]);
    unsigned long long iova, ipa;
    sscanf(argv[3], "0x%llx", &iova);
    sscanf(argv[4], "0x%llx", &ipa);
    int ret = syscall(__NR_iopt_map, dev_name, iova, ipa);
    if (ret < 0) {
      printf("iopt_map failed: %d\n", ret);
      return -1;
    }
    printf("iopt_map success\n");
    return 0;
  }
  {
    if(argc != 4) {
      printf("Usage: %s <dev_name> <phys_l> <phys_r>\n", argv[0]);
      return -1;
    }
    unsigned long long phys_l, phys_r;
    sscanf(argv[2], "0x%llx", &phys_l);
    sscanf(argv[3], "0x%llx", &phys_r);
    int ret = syscall(__NR_view_iopt, dev_name, phys_l, phys_r, pool);
    if (ret < 0) {
      printf("view_iopt failed: %d\n", ret);
      return -1;
    }
    printf("view_iopt returned %d entries\n", ret);
    int show = 20;
    if (ret < show)
      show = ret;
    printf("Showing first %d entries:\n", show);
    for (int i = 0; i < show; i++) {
      printf("IOVA: 0x%016llx, PA: 0x%016llx, PTE: 0x%016llx \n",
             pool[i + cap * 0], pool[i + cap * 1], pool[i + cap * 2]);
    }
  }
  return 0;
}
