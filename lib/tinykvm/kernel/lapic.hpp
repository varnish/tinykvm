#pragma once
#define AMD64_MSR_APICBASE       0x1B
#define AMD64_MSR_XAPIC_ENABLE   0x800
#define AMD64_MSR_X2APIC_ENABLE  0xC00

#define AMD64_APIC_MODE_EXTINT   0x7
#define AMD64_APIC_MODE_NMI      0x4

typedef unsigned int __u32;

struct local_apic {

/*000*/	struct { __u32 __reserved[4]; } __reserved_01;

/*010*/	struct { __u32 __reserved[4]; } __reserved_02;

/*020*/	struct { /* APIC ID Register */
		__u32   __reserved_1	: 24,
			phys_apic_id	:  4,
			__reserved_2	:  4;
		__u32 __reserved[3];
	} id;

/*030*/	const
	struct { /* APIC Version Register */
		__u32   version		:  8,
			__reserved_1	:  8,
			max_lvt		:  8,
			__reserved_2	:  8;
		__u32 __reserved[3];
	} version;

/*040*/	struct { __u32 __reserved[4]; } __reserved_03;

/*050*/	struct { __u32 __reserved[4]; } __reserved_04;

/*060*/	struct { __u32 __reserved[4]; } __reserved_05;

/*070*/	struct { __u32 __reserved[4]; } __reserved_06;

/*080*/	struct { /* Task Priority Register */
		__u32   priority	:  8,
			__reserved_1	: 24;
		__u32 __reserved_2[3];
	} tpr;

/*090*/	const
	struct { /* Arbitration Priority Register */
		__u32   priority	:  8,
			__reserved_1	: 24;
		__u32 __reserved_2[3];
	} apr;

/*0A0*/	const
	struct { /* Processor Priority Register */
		__u32   priority	:  8,
			__reserved_1	: 24;
		__u32 __reserved_2[3];
	} ppr;

/*0B0*/	struct { /* End Of Interrupt Register */
		__u32   eoi;
		__u32 __reserved[3];
	} eoi;

/*0C0*/	struct { __u32 __reserved[4]; } __reserved_07;

/*0D0*/	struct { /* Logical Destination Register */
		__u32   __reserved_1	: 24,
			logical_dest	:  8;
		__u32 __reserved_2[3];
	} ldr;

/*0E0*/	struct { /* Destination Format Register */
		__u32   __reserved_1	: 28,
			model		:  4;
		__u32 __reserved_2[3];
	} dfr;

/*0F0*/	struct { /* Spurious Interrupt Vector Register */
		__u32	spurious_vector	:  8,
			apic_enabled	:  1,
			focus_cpu	:  1,
			__reserved_2	: 22;
		__u32 __reserved_3[3];
	} svr;

/*100*/	struct { /* In Service Register */
/*170*/		__u32 bitfield;
		__u32 __reserved[3];
	} isr [8];

/*180*/	struct { /* Trigger Mode Register */
/*1F0*/		__u32 bitfield;
		__u32 __reserved[3];
	} tmr [8];

/*200*/	struct { /* Interrupt Request Register */
/*270*/		__u32 bitfield;
		__u32 __reserved[3];
	} irr [8];

/*280*/	union { /* Error Status Register */
		struct {
			__u32   send_cs_error			:  1,
				receive_cs_error		:  1,
				send_accept_error		:  1,
				receive_accept_error		:  1,
				__reserved_1			:  1,
				send_illegal_vector		:  1,
				receive_illegal_vector		:  1,
				illegal_register_address	:  1,
				__reserved_2			: 24;
			__u32 __reserved_3[3];
		} error_bits;
		struct {
			__u32 errors;
			__u32 __reserved_3[3];
		} all_errors;
	} esr;

/*290*/	struct { __u32 __reserved[4]; } __reserved_08;

/*2A0*/	struct { __u32 __reserved[4]; } __reserved_09;

/*2B0*/	struct { __u32 __reserved[4]; } __reserved_10;

/*2C0*/	struct { __u32 __reserved[4]; } __reserved_11;

/*2D0*/	struct { __u32 __reserved[4]; } __reserved_12;

/*2E0*/	struct { __u32 __reserved[4]; } __reserved_13;

/*2F0*/	struct { __u32 __reserved[4]; } __reserved_14;

/*300*/	struct { /* Interrupt Command Register 1 */
		__u32   vector			:  8,
			delivery_mode		:  3,
			destination_mode	:  1,
			delivery_status		:  1,
			__reserved_1		:  1,
			level			:  1,
			trigger			:  1,
			__reserved_2		:  2,
			shorthand		:  2,
			__reserved_3		:  12;
		__u32 __reserved_4[3];
	} icr1;

/*310*/	struct { /* Interrupt Command Register 2 */
		union {
			__u32   __reserved_1	: 24,
				phys_dest	:  4,
				__reserved_2	:  4;
			__u32   __reserved_3	: 24,
				logical_dest	:  8;
		} dest;
		__u32 __reserved_4[3];
	} icr2;

/*320*/	struct { /* LVT - Timer */
		__u32   vector		:  8,
			__reserved_1	:  4,
			delivery_status	:  1,
			__reserved_2	:  3,
			mask		:  1,
			timer_mode	:  1,
			__reserved_3	: 14;
		__u32 __reserved_4[3];
	} lvt_timer;

/*330*/	struct { /* LVT - Thermal Sensor */
		__u32  vector		:  8,
			delivery_mode	:  3,
			__reserved_1	:  1,
			delivery_status	:  1,
			__reserved_2	:  3,
			mask		:  1,
			__reserved_3	: 15;
		__u32 __reserved_4[3];
	} lvt_thermal;

/*340*/	struct { /* LVT - Performance Counter */
		__u32   vector		:  8,
			delivery_mode	:  3,
			__reserved_1	:  1,
			delivery_status	:  1,
			__reserved_2	:  3,
			mask		:  1,
			__reserved_3	: 15;
		__u32 __reserved_4[3];
	} lvt_pc;

/*350*/	struct { /* LVT - LINT0 */
		__u32   vector		:  8,
			delivery_mode	:  3,
			__reserved_1	:  1,
			delivery_status	:  1,
			polarity	:  1,
			remote_irr	:  1,
			trigger		:  1,
			mask		:  1,
			__reserved_2	: 15;
		__u32 __reserved_3[3];
	} lvt_lint0;

/*360*/	struct { /* LVT - LINT1 */
		__u32   vector		:  8,
			delivery_mode	:  3,
			__reserved_1	:  1,
			delivery_status	:  1,
			polarity	:  1,
			remote_irr	:  1,
			trigger		:  1,
			mask		:  1,
			__reserved_2	: 15;
		__u32 __reserved_3[3];
	} lvt_lint1;

/*370*/	struct { /* LVT - Error */
		__u32   vector		:  8,
			__reserved_1	:  4,
			delivery_status	:  1,
			__reserved_2	:  3,
			mask		:  1,
			__reserved_3	: 15;
		__u32 __reserved_4[3];
	} lvt_error;

/*380*/	struct { /* Timer Initial Count Register */
		__u32   initial_count;
		__u32 __reserved_2[3];
	} timer_icr;

/*390*/	const
	struct { /* Timer Current Count Register */
		__u32   curr_count;
		__u32 __reserved_2[3];
	} timer_ccr;

/*3A0*/	struct { __u32 __reserved[4]; } __reserved_16;

/*3B0*/	struct { __u32 __reserved[4]; } __reserved_17;

/*3C0*/	struct { __u32 __reserved[4]; } __reserved_18;

/*3D0*/	struct { __u32 __reserved[4]; } __reserved_19;

/*3E0*/	struct { /* Timer Divide Configuration Register */
		__u32   divisor		:  4,
			__reserved_1	: 28;
		__u32 __reserved_2[3];
	} timer_dcr;

/*3F0*/	struct { __u32 __reserved[4]; } __reserved_20;

} __attribute__ ((packed));
