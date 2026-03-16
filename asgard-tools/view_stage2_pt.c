#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>、
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

#define cap (1 << 15)
unsigned int shadow_handles[1 << 10];
unsigned long long pool[cap * 4];
int main(void) {

  int vm_num = syscall(__NR_get_shadow_handles, shadow_handles);
  printf("There are %d shadow VMs.\n", vm_num);
  for (int i = 0; i < vm_num; i++)
    printf("shadow handle[%d] = %u\n", i, shadow_handles[i]);
  printf("Input handle (0 for host): ");
  int vm_handle;
  scanf("%d", &vm_handle);
  int good = 0;
  if (vm_handle == 0 || vm_handle==-1)
    good = 1;
  for (int i = 0; i < vm_num; i++)
    if (shadow_handles[i] == vm_handle)
      good = 1;
  if (!good) {
    printf("Invalid handle %d\n", vm_handle);
    return -1;
  }
  printf("page cnt = %ld\n", syscall(__NR_stage2_pt_count,vm_handle));
  unsigned long long L = 0x00000000, R = 0x10000000000;
  char L_str[100], R_str[100];
  printf("L = ");
  scanf("%s", L_str);
  L=strtoull(L_str,NULL,0);
  printf("R = ");
  scanf("%s", R_str);
  R=strtoull(R_str,NULL,0);
  if(L==R){
    L=0;
    R=0x10000000000;
  }
  long long ret = syscall(__NR_view_stage2_pt, L, R, vm_handle, pool);
  printf("L = 0x%llx, R = 0x%llx\n", L, R);
  if (ret < 0) {
    printf("view_stage2_pt failed: %lld\n", ret);
    return -1;
  }
  printf("view_stage2_pt returned %lld entries\n", ret);
  int show = 20;
  if (ret < show)
    show = ret;
  printf("Showing first %d entries:\n", show);
  for (int i = 0; i < show; i++) {
    long long delta=(long long)pool[i + cap * 0]-(long long)pool[i + cap * 1];
    printf("IPA: 0x%016llx, PA: 0x%016llx, Level: %llu, Software Bits: ",
           pool[i + cap * 0], pool[i + cap * 1], pool[i + cap * 2]);
    for(int j=58;j>=55;j--){
      printf("%llu", pool[i + cap * 3] & (1ull << j) ? 1ull : 0ull);
    }

    printf(", PTE: 0x%016llx\n", pool[i + cap * 3]);
    // printf(", delta: %lld\n", delta);
  }

  

  return 0;
}
