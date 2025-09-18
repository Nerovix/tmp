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

#ifndef __ARM64_KVM_NVHE_DEBUG_UART_PL011_H__
#define __ARM64_KVM_NVHE_DEBUG_UART_PL011_H__

#ifdef KVM_ARM_HYP_DEBUG_UART_DRIVER_PL011

#include <nvhe/debug/uart_driver.h>

#define HYP_PL011_UARTFR	0x18

#define HYP_PL011_UARTFR_BUSY	3
#define HYP_PL011_UARTFR_FULL	5

#ifdef __ASSEMBLY__

.macro hyp_uart_wait_tx_ready, tmpnr
9992:	hyp_uart_base	x\tmpnr
	ldr		w\tmpnr, [x\tmpnr, HYP_PL011_UARTFR]
	tbnz		w\tmpnr, HYP_PL011_UARTFR_FULL, 9992b
.endm

.macro hyp_uart_wait_tx_flush, tmpnr
9992:	hyp_uart_base	x\tmpnr
	ldr		w\tmpnr, [x\tmpnr, HYP_PL011_UARTFR]
	tbnz		w\tmpnr, HYP_PL011_UARTFR_BUSY, 9992b
.endm

#else /* __ASSEMBLY__ */

static inline void __hyp_uart_wait_tx_ready(void *base)
{
	unsigned int val;

	do {
		val = __hyp_readw(base + HYP_PL011_UARTFR);
	} while (val & (1U << HYP_PL011_UARTFR_FULL));
}

static inline void __hyp_uart_wait_tx_flush(void *base)
{
	unsigned int val;

	do {
		val = __hyp_readw(base + HYP_PL011_UARTFR);
	} while (val & (1U << HYP_PL011_UARTFR_BUSY));
}

#endif /* __ASSEMBLY__ */

#endif  /* KVM_ARM_HYP_DEBUG_UART_DRIVER_PL011 */
#endif	/* __ARM64_KVM_NVHE_DEBUG_UART_PL011_H__ */
