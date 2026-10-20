#pragma once

/* Keep addresses for different Qualcomm generations together. DIZI values
 * are from the rooted 2405CPCFBG live FDT, not from SM7150 documentation. */
#ifdef BOARD_DIZI
#define BOARD_NAME "dizi (POCO Pad SM7435)"
#define BOARD_FB_BASE 0xb8000000UL
#define BOARD_FB_W 1600
#define BOARD_FB_H 2560
#define BOARD_FB_STRIDE (1600 * 4)
#define BOARD_GICD 0x17200000UL
#define BOARD_GICR 0x17260000UL
#define BOARD_VTIMER_INTID 27
#define BOARD_PTIMER_INTID 30
/* ramoops@80D00000: two 256 KiB dmesg records, then the 512 KiB console,
 * then 1 MiB pmsg. The console (readable as console-ramoops-0) is here. */
#define BOARD_LOG_BASE 0x80d80000UL
#define BOARD_LOG_SIZE 0x80000UL
#define BOARD_APPS_SMMU 0x15000000UL
/* ruan-u-oss gcc-parrot.c; clock IDs agree with dizi's live USB FDT. */
#define BOARD_USB_GCC 0x00100000UL
#define BOARD_USB_GDSCR 0x49004
#define BOARD_USB_MASTER_CBCR 0x49018
#define BOARD_USB_IFACE_CBCR 0x49084
#define BOARD_USB_AGGRE_CBCR 0x49088
#define BOARD_USB_UTMI_CBCR 0x49024
#define BOARD_USB_SLEEP_CBCR 0x49020
#define BOARD_USB_DWC 0x0a600000UL
#define BOARD_USB_QSCRATCH 0x0a6f8800UL
#else
#define BOARD_NAME "sweet (Redmi Note 10 Pro SM7150)"
#define BOARD_FB_BASE 0x9c000000UL
#define BOARD_FB_W 1080
#define BOARD_FB_H 2400
#define BOARD_FB_STRIDE (1080 * 4)
#define BOARD_GICD 0x17a00000UL
#define BOARD_GICR 0x17a60000UL
#define BOARD_VTIMER_INTID 19
#define BOARD_PTIMER_INTID 18
#endif
