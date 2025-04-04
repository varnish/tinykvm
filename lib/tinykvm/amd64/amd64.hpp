#ifndef PAGE_SIZE
#define PAGE_SIZE  4096
#endif

/* CR0 bits */
#define CR0_PE 1u
#define CR0_MP (1U << 1)
#define CR0_EM (1U << 2)
#define CR0_TS (1U << 3)
#define CR0_ET (1U << 4)
#define CR0_NE (1U << 5)
#define CR0_WP (1U << 16)
#define CR0_AM (1U << 18)
#define CR0_NW (1U << 29)
#define CR0_CD (1U << 30)
#define CR0_PG (1U << 31)

/* CR4 bits */
#define CR4_VME 1
#define CR4_PVI (1U << 1)
#define CR4_TSD (1U << 2)
#define CR4_DE (1U << 3)
#define CR4_PSE (1U << 4)
#define CR4_PAE (1U << 5)
#define CR4_MCE (1U << 6)
#define CR4_PGE (1U << 7)
#define CR4_PCE (1U << 8)
#define CR4_OSFXSR (1U << 9)
#define CR4_OSXMMEXCPT (1U << 10)
#define CR4_UMIP (1U << 11)
#define CR4_VMXE (1U << 13)
#define CR4_SMXE (1U << 14)
#define CR4_FSGSBASE (1U << 16)
#define CR4_PCIDE (1U << 17)
#define CR4_OSXSAVE (1U << 18)
#define CR4_SMEP (1U << 20)
#define CR4_SMAP (1U << 21)
#define CR4_CET (1U << 23)

#define EFER_SCE 1
#define EFER_LME (1U << 8)
#define EFER_LMA (1U << 10)
#define EFER_NXE (1U << 11)

/* 64-bit page * entry bits */
#define PDE64_PRESENT 1UL
#define PDE64_RW (1UL << 1)
#define PDE64_USER (1UL << 2)
#define PDE64_WRITE_THROUGH (1UL << 3)
#define PDE64_CACHE_DISABLE (1UL << 4)
#define PDE64_ACCESSED (1UL << 5)
#define PDE64_DIRTY (1UL << 6)
#define PDE64_PS (1UL << 7)
#define PDE64_G (1UL << 8)
#define PDE64_NX (1UL << 63)

#define PDE64_PDPT_SIZE  (1ULL << 39)
#define PDE64_PD_SIZE  (1ULL << 30)
#define PDE64_PT_SIZE  (1ULL << 21)
#define PDE64_PTE_SIZE (1ULL << 12)


#define AMD64_MSR_STAR   0xC0000081
#define AMD64_MSR_LSTAR  0xC0000082

#define AMD64_MSR_FS_BASE 0xC0000100
#define AMD64_MSR_GS_BASE 0xC0000101
