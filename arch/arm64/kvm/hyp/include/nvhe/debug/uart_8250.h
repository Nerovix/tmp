/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Stand-alone header for basic debug output on the PL011 UART.  To use it,
 * ensure that CONFIG_KVM_ARM_HYP_DEBUG_UART is enabled and that
 * CONFIG_KVM_ARM_HYP_DEBUG_UART_ADDR is the physical address of the PL011
 * UART that you want to use. Then just include this header and try not to
 * vomit at the state of the macros and functions it provides.
 *
 * The C functions only work when the MMU is enabled, but the assembly macros
 * should work pretty much everywhere.
 *
 * It's slow and racy, but you'll be fine. Patches unwelcome.
 */

#ifndef __ARM64_KVM_NVHE_DEBUG_UART_8250_H__
#define __ARM64_KVM_NVHE_DEBUG_UART_8250_H__

#include <nvhe/debug/uart_driver.h>

#define HYP_8250_UART_LSR	(5 << 2)
#define HYP_8250_UART_LSR_TEMT	6

#ifdef __ASSEMBLY__

.macro hyp_uart_wait_tx_ready, tmpnr
9992:	hyp_uart_base	x\tmpnr
	ldr		w\tmpnr, [x\tmpnr, HYP_8250_UART_LSR]
	tbz		w\tmpnr, HYP_8250_UART_LSR_TEMT, 9992b
.endm

.macro hyp_uart_wait_tx_flush, tmpnr
.endm

#else /* __ASSEMBLY__ */

static inline void __hyp_uart_wait_tx_ready(void *base)
{
	unsigned int val;

	do {
		val = __hyp_readw(base + HYP_8250_UART_LSR);
	} while (!(val & (1u << HYP_8250_UART_LSR_TEMT)));
}

static inline void __hyp_uart_wait_tx_flush(void *base) {}

#endif /* __ASSEMBLY__ */

#endif	/* __ARM64_KVM_NVHE_DEBUG_UART_8250_H__ */
