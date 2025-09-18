/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Interface that each UART driver must implement.
 */

#ifndef __ARM64_KVM_NVHE_DEBUG_UART_DRIVER_H__
#define __ARM64_KVM_NVHE_DEBUG_UART_DRIVER_H__

#ifndef __ASSEMBLY__
static inline unsigned int __hyp_readw(void *ioaddr);
static inline void __hyp_writew(unsigned int val, void *ioaddr);
#endif /* __ASSEMBLY__ */

#endif	/* __ARM64_KVM_NVHE_DEBUG_UART_DRIVER_H__ */
