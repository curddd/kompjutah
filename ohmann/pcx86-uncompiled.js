"use strict";

/**
 * @copyright https://www.pcjs.org/machines/shared/lib/defines.js (C) 2012-2021 Jeff Parsons
 */
         
/*
 * RS-232 DB-25 Pin Definitions, mapped to bits 1-25 in a 32-bit status value.
 *
 * SerialPorts in PCjs machines are considered DTE (Data Terminal Equipment), which means they should be "virtually"
 * connected to each other via a null-modem cable, which assumes the following cross-wiring:
 *
 *     G       1  <->  1        G       (Ground)
 *     TD      2  <->  3        RD      (Received Data)
 *     RD      3  <->  2        TD      (Transmitted Data)
 *     RTS     4  <->  5        CTS     (Clear To Send)
 *     CTS     5  <->  4        RTS     (Request To Send)
 *     DSR   6+8  <->  20       DTR     (Data Terminal Ready)
 *     SG      7  <->  7        SG      (Signal Ground)
 *     DTR    20  <->  6+8      DSR     (Data Set Ready + Carrier Detect)
 *     RI     22  <->  22       RI      (Ring Indicator)
 *
 * TODO: Move these definitions to a more appropriate shared file at some point.
 */
var RS232 = {
    RTS: {
        PIN:  4,
        MASK: 0x00000010
    },
    CTS: {
        PIN:  5,
        MASK: 0x00000020
    },
    DSR: {
        PIN:  6,
        MASK: 0x00000040
    },
    CD: {
        PIN:  8,
        MASK: 0x00000100
    },
    DTR: {
        PIN:  20,
        MASK: 0x00100000
    },
    RI: {
        PIN:  22,
        MASK: 0x00400000
    }
};


var X86 = {
    /*
     * CPU model numbers (supported)
     */
    MODEL_8086:     8086,
    MODEL_8088:     8088,
    MODEL_80186:    80186,
    MODEL_80188:    80188,
    MODEL_80286:    80286,
    MODEL_80386:    80386,

    /*
     * 80386 CPU stepping identifiers (supported)
     */
    STEPPING_80386_A0: (80386+0xA0),    // we have very little information about this stepping...
    STEPPING_80386_A1: (80386+0xA1),    // we know much more about the A1 stepping (see /blog/2015/02/23/README.md)
    STEPPING_80386_B0: (80386+0xB0),    // for now, the only B0 difference in PCx86 is support for XBTS and IBTS
    STEPPING_80386_B1: (80386+0xB1),    // our implementation of the B1 stepping also includes the infamous 32-bit multiplication bug
    STEPPING_80386_B2: (80386+0xB2),    // this is an imaginary stepping that simply means "B1 without the 32-bit multiplication bug" (ie, a B1 with the "double sigma" stamp)
    STEPPING_80386_C0: (80386+0xC0),    // this presumably fixed lots of B1 issues, but it seems to have been quickly superseded by the D0
    STEPPING_80386_D0: (80386+0xD0),    // we don't have any detailed information (eg, errata) for these later steppings
    STEPPING_80386_D1: (80386+0xD1),
    STEPPING_80386_D2: (80386+0xD2),

    /*
     * This constant is used to mark points in the code where the physical address being returned
     * is invalid and should not be used.
     *
     * This value is also used to indicate non-existent EA address calculations, which are usually
     * detected with "regEA === ADDR_INVALID" and "regEAWrite === ADDR_INVALID" tests.  Which means
     * that, technically, we should not use any signed 32-bit value, such as -1 (0xffffffff), since
     * that could also be a valid address on a 32-bit CPU.  So we also leave open the possibility of
     * using a non-numeric value such undefined or null, which is why all ADDR_INVALID tests should
     * use strict equality operators.
     *
     * WARNING: Like many of the properties defined here, ADDR_INVALID is a common constant, which the
     * Closure Compiler will happily inline (with or without @const annotations; in fact, I've yet to
     * see a @const annotation EVER improve automatic inlining).  However, if you don't make ABSOLUTELY
     * certain that this file is included BEFORE the first reference to any of these properties, that
     * automatic inlining will no longer occur.
     */
    ADDR_INVALID: -1,

    /*
     * Processor Exception Interrupts
     *
     * Of the following exceptions, all are designed to be restartable, except for 0x08 and 0x09 (and 0x0D
     * after an attempt to write to a read-only segment).
     *
     * Error codes are pushed onto the stack for 0x08 (always 0) and 0x0A through 0x0E.
     *
     * Priority: Instruction exception, TRAP, NMI, Processor Extension Segment Overrun, and finally INTR.
     *
     * All exceptions can also occur in real-mode, except where noted.  A GP_FAULT in real-mode can be triggered
     * by "any memory reference instruction that attempts to reference [a] 16-bit word at offset 0xFFFF".
     *
     * Interrupts beyond 0x10 (up through 0x1F) are reserved for future exceptions.
     *
     * Implementation Detail: For any opcode we know must generate a UD_FAULT interrupt, we invoke opInvalid(),
     * NOT opUndefined().  UD_FAULT is for INVALID opcodes, Intel's choice of term "undefined" notwithstanding.
     *
     * We reserve the term "undefined" for opcodes that require more investigation, and we invoke opUndefined()
     * ONLY until an opcode's behavior has finally been defined, at which point it becomes either valid or invalid.
     * The term "illegal" seems completely superfluous; we don't need a third way of describing invalid opcodes.
     *
     * The term "undocumented" should be limited to operations that are valid but Intel simply never documented.
     */
    EXCEPTION: {
        DE_EXC:     0x00,       // Divide Error Exception                   (#DE: fault, no error code)
        DB_EXC:     0x01,       // Debug (aka Single Step Trap) Exception   (#DB: fault or trap)
        NMI:        0x02,       // Non-Maskable Interrupt
        BP_TRAP:    0x03,       // Breakpoint Exception                     (#BP: trap)
        OF_TRAP:    0x04,       // INTO Overflow Exception                  (#OF: trap)
        BR_FAULT:   0x05,       // BOUND Error Exception                    (#BR: fault, no error code)
        UD_FAULT:   0x06,       // Invalid (aka Undefined/Illegal) Opcode   (#UD: fault, no error code)
        NM_FAULT:   0x07,       // No Math Unit Available; see ESC or WAIT  (#NM: fault, no error code)
        DF_FAULT:   0x08,       // Double Fault; see LIDT                   (#DF: fault, with error code)
        MP_FAULT:   0x09,       // Math Unit Protection Fault; see ESC      (#MP: fault, no error code)
        TS_FAULT:   0x0A,       // Invalid Task State Segment Fault         (#TS: fault, with error code; protected-mode only)
        NP_FAULT:   0x0B,       // Not Present Fault                        (#NP: fault, with error code; protected-mode only)
        SS_FAULT:   0x0C,       // Stack Fault                              (#SS: fault, with error code; protected-mode only)
        GP_FAULT:   0x0D,       // General Protection Fault                 (#GP: fault, with error code)
        PF_FAULT:   0x0E,       // Page Fault                               (#PF: fault, with error code)
        MF_FAULT:   0x10        // Math Fault; see ESC or WAIT              (#MF: fault, no error code)
    },
    /*
     * Processor Status flag definitions (stored in regPS)
     */
    PS: {
        CF:     0x0001,     // bit 0: Carry flag
        BIT1:   0x0002,     // bit 1: reserved, always set
        PF:     0x0004,     // bit 2: Parity flag
        BIT3:   0x0008,     // bit 3: reserved, always clear
        AF:     0x0010,     // bit 4: Auxiliary Carry flag (aka Arithmetic flag)
        BIT5:   0x0020,     // bit 5: reserved, always clear
        ZF:     0x0040,     // bit 6: Zero flag
        SF:     0x0080,     // bit 7: Sign flag
        TF:     0x0100,     // bit 8: Trap flag
        IF:     0x0200,     // bit 9: Interrupt flag
        DF:     0x0400,     // bit 10: Direction flag
        OF:     0x0800,     // bit 11: Overflow flag
        IOPL: {
         MASK:  0x3000,     // bits 12-13: I/O Privilege Level (always set on 8086/80186; clear on 80286 reset)
         SHIFT: 12
        },
        NT:     0x4000,     // bit 14: Nested Task flag (always set on 8086/80186; clear on 80286 reset)
        BIT15:  0x8000,     // bit 15: reserved (always set on 8086/80186; clear otherwise)
        RF:    0x10000,     // bit 16: Resume Flag (temporarily disables debug exceptions; 80386 only)
        VM:    0x20000      // bit 17: Virtual 8086 Mode (80386 only)
    },
    CR0: {
        /*
         * Machine Status Word (MSW) bit definitions
         */
        MSW: {
            PE:     0x0001, // protected-mode enabled
            MP:     0x0002, // monitor processor extension (ie, coprocessor)
            EM:     0x0004, // emulate processor extension
            TS:     0x0008, // task switch indicator
            ON:     0xFFF0, // on the 80286, these bits are always on (TODO: Verify)
            MASK:   0xFFFF  // these are the only (MSW) bits that the 80286 can access (within CR0)
        },
        ET: 0x00000010,     // coprocessor type (80287 or 80387); always 1 on post-80386 CPUs
        ON: 0x7FFFFFE0,     // CR0 bits that are always on
        PG: 0x80000000|0,   // 0: paging disabled
    },
    DR7: {                  // Debug Control Register
        L0:     0x00000001,
        G0:     0x00000002,
        L1:     0x00000004,
        G1:     0x00000008,
        L2:     0x00000010,
        G2:     0x00000020,
        L3:     0x00000040,
        G3:     0x00000080,
        ENABLE: 0x000000FF,
        LE:     0x00000100,
        GE:     0x00000200,
        RW0:    0x00030000, // 00: exec-only  01: write-only  10: undefined  11: read/write-only
        LEN0:   0x000C0000, // 00: one-byte,  01: two-byte,   10: undefined  11: four-byte
        RW1:    0x00300000, // 00: exec-only  01: write-only  10: undefined  11: read/write-only
        LEN1:   0x00C00000, // 00: one-byte,  01: two-byte,   10: undefined  11: four-byte
        RW2:    0x03000000, // 00: exec-only  01: write-only  10: undefined  11: read/write-only
        LEN2:   0x0C000000, // 00: one-byte,  01: two-byte,   10: undefined  11: four-byte
        RW3:    0x30000000, // 00: exec-only  01: write-only  10: undefined  11: read/write-only
        LEN3:   0xC0000000|0// 00: one-byte,  01: two-byte,   10: undefined  11: four-byte
    },
    DR6: {                  // Debug Status Register
        B0:     0x00000001,
        B1:     0x00000002,
        B2:     0x00000004,
        B3:     0x00000008,
        BD:     0x00002000, // set if the next instruction will read or write one of the eight debug registers and ICE-386 is also using them
        BS:     0x00004000, // set if the debug handler is entered due to the TF (trap flag) bit set in the EFLAGS register
        BT:     0x00008000  // set before entering the DEBUG handler if a task switch has occurred and the T-bit of the new TSS is set
    },
    SEL: {
        RPL:    0x0003,     // requested privilege level (0-3)
        LDT:    0x0004,     // table indicator (0: GDT, 1: LDT)
        MASK:   0xFFF8      // table offset
    },
    DESC: {                 // Descriptor Table Entry
        LIMIT: {            // LIMIT bits 0-15 (or OFFSET if this is an INTERRUPT or TRAP gate)
            OFFSET:     0x0
        },
        BASE: {             // BASE bits 0-15 (or SELECTOR if this is a TASK, INTERRUPT or TRAP gate)
            OFFSET:     0x2
        },
        ACC: {              // bit definitions for the access word (offset 0x4)
            OFFSET:     0x4,
            BASE1623:                       0x00FF,     // (not used if this a TASK, INTERRUPT or TRAP gate; bits 0-5 are parm count for CALL gates)
            TYPE: {
                OFFSET: 0x5,
                MASK:                       0x1F00,
                SEG:                        0x1000,
                NONSEG:                     0x0F00,
                /*
                 * The following bits apply only when SEG is set
                 */
                CODE:                       0x0800,     // set for CODE, clear for DATA
                ACCESSED:                   0x0100,     // set if accessed, clear if not accessed
                READABLE:                   0x0200,     // CODE: set if readable, clear if exec-only
                WRITABLE:                   0x0200,     // DATA: set if writable, clear if read-only
                CONFORMING:                 0x0400,     // CODE: set if conforming, clear if not
                EXPDOWN:                    0x0400,     // DATA: set if expand-down, clear if not
                /*
                 * Assorted bits that apply only within NONSEG values
                 */
                TSS_BUSY:                   0x0200,
                NONSEG_386:                 0x0800,     // 80386 and up
                /*
                 * The following are all the possible (valid) types (well, except for the variations
                 * of DATA and CODE where the ACCESSED bit (0x0100) may also be set)
                 */
                TSS286:                     0x0100,
                LDT:                        0x0200,
                TSS286_BUSY:                0x0300,
                GATE_CALL:                  0x0400,
                GATE_TASK:                  0x0500,
                GATE286_INT:                0x0600,
                GATE286_TRAP:               0x0700,
                TSS386:                     0x0900,     // 80386 and up
                TSS386_BUSY:                0x0B00,     // 80386 and up
                GATE386_CALL:               0x0C00,     // 80386 and up
                GATE386_INT:                0x0E00,     // 80386 and up
                GATE386_TRAP:               0x0F00,     // 80386 and up
                CODE_OR_DATA:               0x1E00,
                DATA_READONLY:              0x1000,
                DATA_WRITABLE:              0x1200,
                DATA_EXPDOWN:               0x1400,
                DATA_EXPDOWN_WRITABLE:      0x1600,
                CODE_EXECONLY:              0x1800,
                CODE_READABLE:              0x1A00,
                CODE_CONFORMING:            0x1C00,
                CODE_CONFORMING_READABLE:   0x1E00
            },
            DPL: {
                MASK:                       0x6000,
                SHIFT:                      13
            },
            PRESENT:                        0x8000,
            INVALID:    0   // use X86.DESC.ACC.INVALID for invalid ACC values
        },
        EXT: {              // descriptor extension word (reserved on the 80286; "must be zero")
            OFFSET:     0x6,
            LIMIT1619:                      0x000F,
            AVAIL:                          0x0010,     // NOTE: set in various descriptors in OS/2
            /*
             * The BIG bit is known as the D bit for code segments; when set, all addresses and operands
             * in that code segment are assumed to be 32-bit.
             *
             * The BIG bit is known as the B bit for data segments; when set, it indicates: 1) all pushes,
             * pops, calls and returns use ESP instead of SP, and 2) the upper bound of an expand-down segment
             * is 0xffffffff instead of 0xffff.
             */
            BIG:                            0x0040,     // clear if default operand/address size is 16-bit, set if 32-bit
            LIMITPAGES:                     0x0080,     // clear if limit granularity is bytes, set if limit granularity is 4Kb pages
            BASE2431:                       0xFF00
        },
        INVALID: 0          // use X86.DESC.INVALID for invalid DESC values
    },
    LADDR: {                // linear address
        PDE: {              // index of page directory entry
            MASK:   0xFFC00000|0,
            SHIFT:  20      // (addr & DIR.MASK) >>> DIR.SHIFT yields a page directory offset (ie, index * 4)
        },
        PTE: {              // index of page table entry
            MASK:   0x003FF000,
            SHIFT:  10      // (addr & PAGE.MASK) >>> PAGE.SHIFT yields a page table offset (ie, index * 4)
        },
        OFFSET:     0x00000FFF
    },
    PTE: {
        FRAME:      0xFFFFF000|0,
        DIRTY:      0x00000040,         // page has been modified
        ACCESSED:   0x00000020,         // page has been accessed
        USER:       0x00000004,         // set for user level (CPL 3), clear for supervisor level (CPL 0-2)
        READWRITE:  0x00000002,         // set for read/write, clear for read-only (affects CPL 3 only)
        PRESENT:    0x00000001          // set for present page, clear for not-present page
    },
    TSS286: {
        PREV_TSS:   0x00,
        CPL0_SP:    0x02,   // start of values altered by task switches
        CPL0_SS:    0x04,
        CPL1_SP:    0x06,
        CPL1_SS:    0x08,
        CPL2_SP:    0x0A,
        CPL2_SS:    0x0C,
        TASK_IP:    0x0E,
        TASK_PS:    0x10,
        TASK_AX:    0x12,
        TASK_CX:    0x14,
        TASK_DX:    0x16,
        TASK_BX:    0x18,
        TASK_SP:    0x1A,
        TASK_BP:    0x1C,
        TASK_SI:    0x1E,
        TASK_DI:    0x20,
        TASK_ES:    0x22,
        TASK_CS:    0x24,
        TASK_SS:    0x26,
        TASK_DS:    0x28,   // end of values altered by task switches
        TASK_LDT:   0x2A
    },
    TSS386: {
        PREV_TSS:   0x00,
        CPL0_ESP:   0x04,   // start of values altered by task switches
        CPL0_SS:    0x08,
        CPL1_ESP:   0x0c,
        CPL1_SS:    0x10,
        CPL2_ESP:   0x14,
        CPL2_SS:    0x18,
        TASK_CR3:   0x1C,   // (not in TSS286)
        TASK_EIP:   0x20,
        TASK_PS:    0x24,
        TASK_EAX:   0x28,
        TASK_ECX:   0x2C,
        TASK_EDX:   0x30,
        TASK_EBX:   0x34,
        TASK_ESP:   0x38,
        TASK_EBP:   0x3C,
        TASK_ESI:   0x40,
        TASK_EDI:   0x44,
        TASK_ES:    0x48,
        TASK_CS:    0x4C,
        TASK_SS:    0x50,
        TASK_DS:    0x54,
        TASK_FS:    0x58,   // (not in TSS286)
        TASK_GS:    0x5C,   // (not in TSS286) end of values altered by task switches
        TASK_LDT:   0x60,
        TASK_IOPM:  0x64    // (not in TSS286)
    },
    ERRCODE: {
        EXT:        0x0001,
        IDT:        0x0002,
        LDT:        0x0004,
        SELMASK:    0xFFFC
    },
    RESULT: {
        /*
         * Flags were originally computed using 16-bit result registers:
         *
         *      CF: resultZeroCarry & resultSize (ie, 0x100 or 0x10000)
         *      PF: resultParitySign & 0xff
         *      AF: (resultParitySign ^ resultAuxOverflow) & 0x0010
         *      ZF: resultZeroCarry & (resultSize - 1)
         *      SF: resultParitySign & (resultSize >> 1)
         *      OF: (resultParitySign ^ resultAuxOverflow ^ (resultParitySign >> 1)) & (resultSize >> 1)
         *
         * I386 support requires that we now rely on 32-bit result registers:
         *
         *      resultDst, resultSrc, resultArith, resultLogic and resultType
         *
         * and flags are now computed as follows:
         *
         *      CF: ((resultDst ^ ((resultDst ^ resultSrc) & (resultSrc ^ resultArith))) & resultType)
         *      PF: (resultLogic & 0xff)
         *      AF: ((resultArith ^ (resultDst ^ resultSrc)) & 0x0010)
         *      ZF: (resultLogic & ((resultType - 1) | resultType))
         *      SF: (resultLogic & resultType)
         *      OF: (((resultDst ^ resultArith) & (resultSrc ^ resultArith)) & resultType)
         *
         * where resultType contains both a size, which must be one of BYTE (0x80), WORD (0x8000),
         * or DWORD (0x80000000), along with bits for each of the arithmetic and/or logical flags that
         * are currently "cached" in the result registers (eg, X86.RESULT.CF for carry, X86.RESULT.OF
         * for overflow, etc).
         *
         * WARNING: Do not confuse these RESULT flag definitions with the PS flag definitions.  RESULT
         * flags are used only as "cached" flag indicators, packed into bits 0-5 of resultType; they do
         * not match the actual flag bit definitions within the Processor Status (PS) register.
         *
         * Arithmetic operations should call:
         *
         *      setArithResult(dst, src, value, type)
         * eg:
         *      setArithResult(dst, src, dst+src, X86.RESULT.BYTE | X86.RESULT.ALL)
         *
         * and logical operations should call:
         *
         *      setLogicResult(value, type [, carry [, overflow]])
         *
         * Since most logical operations clear both CF and OF, most calls to setLogicResult() can omit the
         * last two optional parameters.
         *
         * The type parameter of these methods indicates both the size of the result (BYTE, WORD or DWORD)
         * and which of the flags should now be considered "cached" by the result registers.  If the previous
         * resultType specifies any flags not present in the new type parameter, then those flags are
         * calculated and written to the appropriate regPS bit(s) *before* the result registers are updated.
         *
         * Arithmetic operations are assumed to represent an "added" result; if a "subtracted" result is
         * provided instead (eg, from CMP, DEC, SUB, etc), then setArithResult() must include a 5th parameter
         * (fSubtract); eg:
         *
         *      setArithResult(dst, src, dst-src, X86.RESULT.BYTE | X86.RESULT.ALL, true)
         *
         * TODO: Consider separating setArithResult() into two functions: setAddResult() and setSubResult().
         */
        BYTE:       0x80,       // result is byte value
        WORD:       0x8000,     // result is word value
        DWORD:      0x80000000|0,
        TYPE:       0x80008080|0,
        CF:         0x01,       // carry flag is cached
        PF:         0x02,       // parity flag is cached
        AF:         0x04,       // aux carry flag is cached
        ZF:         0x08,       // zero flag is cached
        SF:         0x10,       // sign flag is cached
        OF:         0x20,       // overflow flag is cached
        ALL:        0x3F,       // all result flags are cached
        LOGIC:      0x1A,       // all logical flags are cached; see setLogicResult()
        NOTCF:      0x3E        // all result flags EXCEPT carry are cached
    },
    /*
     * Bit values for opFlags, which are all reset to zero prior to each instruction
     */
    OPFLAG: {
        NOREAD:     0x0001,     // disable memory reads for the remainder of the current instruction
        NOWRITE:    0x0002,     // disable memory writes for the remainder of the current instruction
        NOINTR:     0x0004,     // a segreg has been set, or a prefix, or an STI (delay INTR acknowledgement)
        WRAP:       0x0008,     // a segment wrap-around has occurred (relevant to 8086/8088 only)
        SEG:        0x0010,     // segment override
        LOCK:       0x0020,     // lock prefix
        REPZ:       0x0040,     // repeat while Z (NOTE: this value MUST match PS.ZF; see opCMPSb/opCMPSw/opSCASb/opSCASw)
        REPNZ:      0x0080,     // repeat while NZ
        REPEAT:     0x0100,     // an instruction is being repeated (ie, some iteration AFTER the first)
        PUSHSP:     0x0200,     // the SP register is potentially being referenced by a PUSH SP opcode, adjustment may be required
        DATASIZE:   0x0400,     // data size override
        ADDRSIZE:   0x0800,     // address size override
        FAULT:      0x1000,     // a fault occurred during the current instruction
        DBEXC:      0x2000,     // a DB_EXC exception occurred during the current instruction
        IRET:       0x4000      // remembers if we arrived at the current instruction via IRET (used for 8086/8088 "feature" simulation)
    },
    /*
     * Bit values for intFlags
     */
    INTFLAG: {
        NONE:       0x00,
        INTR:       0x01,       // h/w interrupt requested
        TRAP:       0x02,       // trap (INT 0x01) requested
        HALT:       0x04,       // halt (HLT) requested
        DMA:        0x08,       // async DMA operation in progress
        DEBUGGER:   0x10        // debugger checks enabled
    },
    /*
     * Common opcodes (and/or any opcodes we need to refer to explicitly)
     */
    OPCODE: {
        ES:         0x26,       // opES()
        CS:         0x2E,       // opCS()
        SS:         0x36,       // opSS()
        DS:         0x3E,       // opDS()
        PUSHSP:     0x54,       // opPUSHSP()
        PUSHA:      0x60,       // opPUSHA()    (80186 and up)
        POPA:       0x61,       // opPOPA()     (80186 and up)
        BOUND:      0x62,       // opBOUND()    (80186 and up)
        ARPL:       0x63,       // opARPL()     (80286 and up)
        FS:         0x64,       // opFS()       (80386 and up)
        GS:         0x65,       // opGS()       (80386 and up)
        OS:         0x66,       // opOS()       (80386 and up)
        AS:         0x67,       // opAS()       (80386 and up)
        PUSHN:      0x68,       // opPUSHn()    (80186 and up)
        IMULN:      0x69,       // opIMULn()    (80186 and up)
        PUSH8:      0x6A,       // opPUSH8()    (80186 and up)
        IMUL8:      0x6B,       // opIMUL8()    (80186 and up)
        INSB:       0x6C,       // opINSb()     (80186 and up)
        INSW:       0x6D,       // opINSw()     (80186 and up)
        OUTSB:      0x6E,       // opOUTSb()    (80186 and up)
        OUTSW:      0x6F,       // opOUTSw()    (80186 and up)
        ENTER:      0xC8,       // opENTER()    (80186 and up)
        LEAVE:      0xC9,       // opLEAVE()    (80186 and up)
        CALLF:      0x9A,       // opCALLF()
        MOVSB:      0xA4,       // opMOVSb()
        MOVSW:      0xA5,       // opMOVSw()
        CMPSB:      0xA6,       // opCMPSb()
        CMPSW:      0xA7,       // opCMPSw()
        STOSB:      0xAA,       // opSTOSb()
        STOSW:      0xAB,       // opSTOSw()
        LODSB:      0xAC,       // opLODSb()
        LODSW:      0xAD,       // opLODSw()
        SCASB:      0xAE,       // opSCASb()
        SCASW:      0xAF,       // opSCASw()
        INT3:       0xCC,       // opINT3()
        INTN:       0xCD,       // opINTn()
        INTO:       0xCE,       // opINTO()
        IRET:       0xCF,       // opIRET()
        ESC0:       0xD8,       // opESC0()
        ESC1:       0xD9,       // opESC1()
        ESC2:       0xDA,       // opESC2()
        ESC3:       0xDB,       // opESC3()
        ESC4:       0xDC,       // opESC4()
        ESC5:       0xDD,       // opESC5()
        ESC6:       0xDE,       // opESC6()
        ESC7:       0xDF,       // opESC7()
        LOOPNZ:     0xE0,       // opLOOPNZ()
        LOOPZ:      0xE1,       // opLOOPZ()
        LOOP:       0xE2,       // opLOOP()
        CALL:       0xE8,       // opCALL()
        JMP:        0xE9,       // opJMP()      (2-byte displacement)
        JMPF:       0xEA,       // opJMPF()
        JMPS:       0xEB,       // opJMPs()     (1-byte displacement)
        LOCK:       0xF0,       // opLOCK()
        INT1:       0xF1,       // opINT1()
        REPNZ:      0xF2,       // opREPNZ()
        REPZ:       0xF3,       // opREPZ()
        CLI:        0xFA,       // opCLI()
        STI:        0xFB,       // opSTI()
        CLD:        0xFC,       // opCLD()
        STD:        0xFD,       // opSTD()
        GRP4W:      0xFF,
        CALLW:      0x10FF,     // GRP4W: fnCALLw()
        CALLFDW:    0x18FF,     // GRP4W: fnCALLFdw()
        CALLMASK:   0x38FF,     // mask 2-byte GRP4W opcodes with this before comparing to CALLW or CALLFDW
        UD2:        0x0B0F      // UD2 (invalid opcode "guaranteed" to generate UD_FAULT on all post-8086 processors)
    },
    /*
     * Floating Point Unit (FPU), aka Numeric Data Processor (NDP), aka Numeric Processor Extension (NPX), aka Coprocessor definitions
     */
    FPU: {
        MODEL_8087:     8087,
        MODEL_80287:    80287,
        MODEL_80287XL:  80387,  // internally, the 80287XL was an 80387SX, so generally, we treat this as MODEL_80387
        MODEL_80387:    80387,
        CONTROL: {              // FPU Control Word
            IM:     0x0001,     // bit 0: Invalid Operation Mask
            DM:     0x0002,     // bit 1: Denormalized Operand Mask
            ZM:     0x0004,     // bit 2: Zero Divide Mask
            OM:     0x0008,     // bit 3: Overflow Mask
            UM:     0x0010,     // bit 4: Underflow Mask
            PM:     0x0020,     // bit 5: Precision Mask
            EXC:    0x003F,     // all of the above exceptions
            IEM:    0x0080,     // bit 7: Interrupt Enable Mask (0 enables interrupts, 1 masks them; 8087 only)
            PC:     0x0300,     // bits 8-9: Precision Control
            RC: {               // bits 10-11: Rounding Control
              NEAR: 0x0000,
              DOWN: 0x0400,
              UP:   0x0800,
              CHOP: 0x0C00,
              MASK: 0x0C00
            },
            IC:     0x1000,     // bit 12: Infinity Control (0 for Projective, 1 for Affine)
            UNUSED: 0xE040,     // bits 6,13-15: unused
            INIT:   0x03BF      // X86.FPU.CONTROL.IM | X86.FPU.CONTROL.DM | X86.FPU.CONTROL.ZM | X86.FPU.CONTROL.OM | X86.FPU.CONTROL.UM | X86.FPU.CONTROL.PM | X86.FPU.CONTROL.IEM | X86.FPU.CONTROL.PC
        },
        STATUS: {               // FPU Status Word
            IE:     0x0001,     // bit 0: Invalid Operation
            DE:     0x0002,     // bit 1: Denormalized Operand
            ZE:     0x0004,     // bit 2: Zero Divide
            OE:     0x0008,     // bit 3: Overflow
            UE:     0x0010,     // bit 4: Underflow
            PE:     0x0020,     // bit 5: Precision
            SF:     0x0040,     // bit 6: Stack Fault (80387 and later; triggers an Invalid Operation exception)
            EXC:    0x007F,     // all of the above exceptions
            ES:     0x0080,     // bit 7: Error/Exception Status/Summary (Interrupt Request on 8087)
            C0:     0x0100,     // bit 8: Condition Code 0
            C1:     0x0200,     // bit 9: Condition Code 1
            C2:     0x0400,     // bit 10: Condition Code 2
            ST:     0x3800,     // bits 11-13: Stack Top
            ST_SHIFT: 11,
            C3:     0x4000,     // bit 14: Condition Code 3
            CC:     0x4700,     // all condition code bits
            BUSY:   0x8000      // bit 15: Busy
        },
        TAGS: {
            VALID:  0x0,
            ZERO:   0x1,
            SPECIAL:0x2,
            EMPTY:  0x3,
            MASK:   0x3
        }
        /*
            C3 C2 C1 C0     Condition Code (CC) values following an Examine

            0  0  0  0      Valid, positive unnormalized (+Unnormal)
            0  0  0  1      Invalid, positive, exponent=0 (+NaN)
            0  0  1  0      Valid, negative, unnormalized (-Unnormal)
            0  0  1  1      Invalid, negative, exponent=0 (-NaN)
            0  1  0  0      Valid, positive, normalized (+Normal)
            0  1  0  1      Infinity, positive (+Infinity)
            0  1  1  0      Valid, negative, normalized (-Normal)
            0  1  1  1      Infinity, negative (-Infinity)
            1  0  0  0      Zero, positive (+0)
            1  0  0  1      Empty
            1  0  1  0      Zero, negative (-0)
            1  0  1  1      Empty
            1  1  0  0      Invalid, positive, exponent=0 (+Denormal)
            1  1  0  1      Empty
            1  1  1  0      Invalid, negative, exponent=0 (-Denormal)
            1  1  1  1      Empty

                            Condition Code (CC) values following an FCOM or FTST

            0  0  ?  0      ST > source operand (FCOM); ST > 0 (FTST)
            0  0  ?  1      ST < source operand (FCOM); ST < 0 (FTST)
            1  0  ?  0      ST = source operand (FCOM); ST = 0 (FTST)
            1  1  ?  1      ST is not comparable

                            Condition Code (CC) values following a Remainder

            Q1 0  Q0 Q2     Complete reduction (he three low bits of the quotient stored in C0, C3, and C1)
            ?  1  ?  ?      Incomplete reduction
         */
    },
    CYCLES_8088: {
        nWordCyclePenalty:          4,      // NOTE: accurate for the 8088/80188 only (on the 8086/80186, it applies to odd addresses only)
        nEACyclesBase:              5,      // base or index only (BX, BP, SI or DI)
        nEACyclesDisp:              6,      // displacement only
        nEACyclesBaseIndex:         7,      // base + index (BP+DI and BX+SI)
        nEACyclesBaseIndexExtra:    8,      // base + index (BP+SI and BX+DI require an extra cycle)
        nEACyclesBaseDisp:          9,      // base or index + displacement
        nEACyclesBaseIndexDisp:     11,     // base + index + displacement (BP+DI+n and BX+SI+n)
        nEACyclesBaseIndexDispExtra:12,     // base + index + displacement (BP+SI+n and BX+DI+n require an extra cycle)
        nOpCyclesAAA:               4,      // AAA, AAS, DAA, DAS, TEST acc,imm
        nOpCyclesAAD:               60,
        nOpCyclesAAM:               83,
        nOpCyclesArithRR:           3,      // ADC, ADD, AND, OR, SBB, SUB, XOR and CMP reg,reg cycle time
        nOpCyclesArithRM:           9,      // ADC, ADD, AND, OR, SBB, SUB, and XOR reg,mem (and CMP mem,reg) cycle time
        nOpCyclesArithMR:           16,     // ADC, ADD, AND, OR, SBB, SUB, and XOR mem,reg cycle time
        nOpCyclesArithMID:          1,      // ADC, ADD, AND, OR, SBB, SUB, XOR and CMP mem,imm cycle delta
        nOpCyclesCall:              19,
        nOpCyclesCallF:             28,
        nOpCyclesCallWR:            16,
        nOpCyclesCallWM:            21,
        nOpCyclesCallDM:            37,
        nOpCyclesCLI:               2,
        nOpCyclesCompareRM:         9,      // CMP reg,mem cycle time (same as nOpCyclesArithRM on an 8086 but not on a 80286)
        nOpCyclesCWD:               5,
        nOpCyclesBound:             33,     // N/A if 8086/8088, 33-35 if 80186/80188 (TODO: Determine what the range means for an 80186/80188)
        nOpCyclesInP:               10,
        nOpCyclesInDX:              8,
        nOpCyclesIncR:              3,      // INC reg, DEC reg
        nOpCyclesIncM:              15,     // INC mem, DEC mem
        nOpCyclesInt:               51,
        nOpCyclesInt3D:             1,
        nOpCyclesIntOD:             2,
        nOpCyclesIntOFall:          4,
        nOpCyclesIRet:              32,
        nOpCyclesJmp:               15,
        nOpCyclesJmpF:              15,
        nOpCyclesJmpC:              16,
        nOpCyclesJmpCFall:          4,
        nOpCyclesJmpWR:             11,
        nOpCyclesJmpWM:             18,
        nOpCyclesJmpDM:             24,
        nOpCyclesLAHF:              4,      // LAHF, SAHF, MOV reg,imm
        nOpCyclesLEA:               2,
        nOpCyclesLS:                16,     // LDS, LES
        nOpCyclesLoop:              17,     // LOOP, LOOPNZ
        nOpCyclesLoopZ:             18,     // LOOPZ, JCXZ
        nOpCyclesLoopNZ:            19,     // LOOPNZ
        nOpCyclesLoopFall:          5,      // LOOP
        nOpCyclesLoopZFall:         6,      // LOOPZ, JCXZ
        nOpCyclesMovRR:             2,
        nOpCyclesMovRM:             8,
        nOpCyclesMovMR:             9,
        nOpCyclesMovRI:             10,
        nOpCyclesMovMI:             10,
        nOpCyclesMovAM:             10,
        nOpCyclesMovMA:             10,
        nOpCyclesDivBR:             80,     // range of 80-90
        nOpCyclesDivWR:             124,    // range of 144-162 (lowered to produce a Norton SI performance index of 1.0)
        nOpCyclesDivBM:             86,     // range of 86-96
        nOpCyclesDivWM:             134,    // range of 154-172 (lowered to produce a Norton SI performance index of 1.0)
        nOpCyclesIDivBR:            101,    // range of 101-112
        nOpCyclesIDivWR:            145,    // range of 165-184 (lowered to produce a Norton SI performance index of 1.0)
        nOpCyclesIDivBM:            107,    // range of 107-118
        nOpCyclesIDivWM:            151,    // range of 171-190 (lowered to produce a Norton SI performance index of 1.0)
        nOpCyclesMulBR:             70,     // range of 70-77
        nOpCyclesMulWR:             93,     // range of 113-118 (lowered to produce a Norton SI performance index of 1.0)
        nOpCyclesMulBM:             76,     // range of 76-83
        nOpCyclesMulWM:             104,    // range of 124-139 (lowered to produce a Norton SI performance index of 1.0)
        nOpCyclesIMulBR:            80,     // range of 80-98
        nOpCyclesIMulWR:            108,    // range of 128-154 (lowered to produce a Norton SI performance index of 1.0)
        nOpCyclesIMulBM:            86,     // range of 86-104
        nOpCyclesIMulWM:            114,    // range of 134-160 (lowered to produce a Norton SI performance index of 1.0)
        nOpCyclesNegR:              3,      // NEG reg, NOT reg
        nOpCyclesNegM:              16,     // NEG mem, NOT mem
        nOpCyclesOutP:              10,
        nOpCyclesOutDX:             8,
        nOpCyclesPopAll:            51,     // N/A if 8086/8088, 51 if 80186, 83 if 80188 (TODO: Verify)
        nOpCyclesPopReg:            8,
        nOpCyclesPopMem:            17,
        nOpCyclesPushAll:           36,     // N/A if 8086/8088, 36 if 80186, 68 if 80188 (TODO: Verify)
        nOpCyclesPushReg:           11,     // NOTE: "The 8086 Book" claims this is 10, but it's an outlier....
        nOpCyclesPushMem:           16,
        nOpCyclesPushSeg:           10,
        nOpCyclesPrefix:            2,
        nOpCyclesCmpS:              18,
        nOpCyclesCmpSr0:            9-2,    // reduced by nOpCyclesPrefix
        nOpCyclesCmpSrn:            17-2,   // reduced by nOpCyclesPrefix
        nOpCyclesLodS:              12,
        nOpCyclesLodSr0:            9-2,    // reduced by nOpCyclesPrefix
        nOpCyclesLodSrn:            13-2,   // reduced by nOpCyclesPrefix
        nOpCyclesMovS:              18,
        nOpCyclesMovSr0:            9-2,    // reduced by nOpCyclesPrefix
        nOpCyclesMovSrn:            17-2,   // reduced by nOpCyclesPrefix
        nOpCyclesScaS:              15,
        nOpCyclesScaSr0:            9-2,    // reduced by nOpCyclesPrefix
        nOpCyclesScaSrn:            15-2,   // reduced by nOpCyclesPrefix
        nOpCyclesStoS:              11,
        nOpCyclesStoSr0:            9-2,    // reduced by nOpCyclesPrefix
        nOpCyclesStoSrn:            10-2,   // reduced by nOpCyclesPrefix
        nOpCyclesRet:               8,
        nOpCyclesRetn:              12,
        nOpCyclesRetF:              18,
        nOpCyclesRetFn:             17,
        nOpCyclesShift1M:           15,     // ROL/ROR/RCL/RCR/SHL/SHR/SAR reg,1
        nOpCyclesShiftCR:           8,      // ROL/ROR/RCL/RCR/SHL/SHR/SAR reg,CL
        nOpCyclesShiftCM:           20,     // ROL/ROR/RCL/RCR/SHL/SHR/SAR mem,CL
        nOpCyclesShiftCS:           2,      // this is the left-shift value used to convert the count to the cycle cost
        nOpCyclesTestRR:            3,
        nOpCyclesTestRM:            9,
        nOpCyclesTestRI:            5,
        nOpCyclesTestMI:            11,
        nOpCyclesXchgRR:            4,
        nOpCyclesXchgRM:            17,
        nOpCyclesXLAT:              11
    },
    CYCLES_80286: {
        nWordCyclePenalty:          0,
        nEACyclesBase:              0,
        nEACyclesDisp:              0,
        nEACyclesBaseIndex:         0,
        nEACyclesBaseIndexExtra:    0,
        nEACyclesBaseDisp:          0,
        nEACyclesBaseIndexDisp:     1,
        nEACyclesBaseIndexDispExtra:1,
        nOpCyclesAAA:               3,
        nOpCyclesAAD:               14,
        nOpCyclesAAM:               16,
        nOpCyclesArithRR:           2,
        nOpCyclesArithRM:           7,
        nOpCyclesArithMR:           7,
        nOpCyclesArithMID:          0,
        nOpCyclesCall:              7,      // on the 80286, this ALSO includes the number of bytes in the target instruction
        nOpCyclesCallF:             13,     // on the 80286, this ALSO includes the number of bytes in the target instruction
        nOpCyclesCallWR:            7,      // on the 80286, this ALSO includes the number of bytes in the target instruction
        nOpCyclesCallWM:            11,     // on the 80286, this ALSO includes the number of bytes in the target instruction
        nOpCyclesCallDM:            16,     // on the 80286, this ALSO includes the number of bytes in the target instruction
        nOpCyclesCLI:               3,
        nOpCyclesCompareRM:         6,
        nOpCyclesCWD:               2,
        nOpCyclesBound:             13,
        nOpCyclesInP:               5,
        nOpCyclesInDX:              5,
        nOpCyclesIncR:              2,
        nOpCyclesIncM:              7,
        nOpCyclesInt:               23,     // on the 80286, this ALSO includes the number of bytes in the target instruction
        nOpCyclesInt3D:             0,
        nOpCyclesIntOD:             1,
        nOpCyclesIntOFall:          3,
        nOpCyclesIRet:              17,     // on the 80286, this ALSO includes the number of bytes in the target instruction
        nOpCyclesJmp:               7,      // on the 80286, this ALSO includes the number of bytes in the target instruction
        nOpCyclesJmpF:              11,     // on the 80286, this ALSO includes the number of bytes in the target instruction
        nOpCyclesJmpC:              7,      // on the 80286, this ALSO includes the number of bytes in the target instruction
        nOpCyclesJmpCFall:          3,
        nOpCyclesJmpWR:             7,      // on the 80286, this ALSO includes the number of bytes in the target instruction
        nOpCyclesJmpWM:             11,     // on the 80286, this ALSO includes the number of bytes in the target instruction
        nOpCyclesJmpDM:             15,     // on the 80286, this ALSO includes the number of bytes in the target instruction
        nOpCyclesLAHF:              2,
        nOpCyclesLEA:               3,
        nOpCyclesLS:                7,
        nOpCyclesLoop:              8,      // on the 80286, this ALSO includes the number of bytes in the target instruction
        nOpCyclesLoopZ:             8,      // on the 80286, this ALSO includes the number of bytes in the target instruction
        nOpCyclesLoopNZ:            8,      // on the 80286, this ALSO includes the number of bytes in the target instruction
        nOpCyclesLoopFall:          4,
        nOpCyclesLoopZFall:         4,
        nOpCyclesMovRR:             2,      // this is actually the same as the 8086...
        nOpCyclesMovRM:             3,
        nOpCyclesMovMR:             5,
        nOpCyclesMovRI:             2,
        nOpCyclesMovMI:             3,
        nOpCyclesMovAM:             5,      // this is actually slower than the MOD/RM form of MOV AX,mem (see nOpCyclesMovRM)
        nOpCyclesMovMA:             3,
        nOpCyclesDivBR:             14,
        nOpCyclesDivWR:             22,
        nOpCyclesDivBM:             17,
        nOpCyclesDivWM:             25,
        nOpCyclesIDivBR:            17,
        nOpCyclesIDivWR:            25,
        nOpCyclesIDivBM:            20,
        nOpCyclesIDivWM:            28,
        nOpCyclesMulBR:             13,
        nOpCyclesMulWR:             21,
        nOpCyclesMulBM:             16,
        nOpCyclesMulWM:             24,
        nOpCyclesIMulBR:            13,
        nOpCyclesIMulWR:            21,
        nOpCyclesIMulBM:            16,
        nOpCyclesIMulWM:            24,
        nOpCyclesNegR:              2,
        nOpCyclesNegM:              7,
        nOpCyclesOutP:              5,
        nOpCyclesOutDX:             5,
        nOpCyclesPopAll:            19,
        nOpCyclesPopReg:            5,
        nOpCyclesPopMem:            5,
        nOpCyclesPushAll:           17,
        nOpCyclesPushReg:           3,
        nOpCyclesPushMem:           5,
        nOpCyclesPushSeg:           3,
        nOpCyclesPrefix:            0,
        nOpCyclesCmpS:              8,
        nOpCyclesCmpSr0:            5,
        nOpCyclesCmpSrn:            9,
        nOpCyclesLodS:              5,
        nOpCyclesLodSr0:            5,
        nOpCyclesLodSrn:            4,
        nOpCyclesMovS:              5,
        nOpCyclesMovSr0:            5,
        nOpCyclesMovSrn:            4,
        nOpCyclesScaS:              7,
        nOpCyclesScaSr0:            5,
        nOpCyclesScaSrn:            8,
        nOpCyclesStoS:              3,
        nOpCyclesStoSr0:            4,
        nOpCyclesStoSrn:            3,
        nOpCyclesRet:               11,     // on the 80286, this ALSO includes the number of bytes in the target instruction
        nOpCyclesRetn:              11,     // on the 80286, this ALSO includes the number of bytes in the target instruction
        nOpCyclesRetF:              15,     // on the 80286, this ALSO includes the number of bytes in the target instruction
        nOpCyclesRetFn:             15,     // on the 80286, this ALSO includes the number of bytes in the target instruction
        nOpCyclesShift1M:           7,
        nOpCyclesShiftCR:           5,
        nOpCyclesShiftCM:           8,
        nOpCyclesShiftCS:           0,
        nOpCyclesTestRR:            2,
        nOpCyclesTestRM:            6,
        nOpCyclesTestRI:            3,
        nOpCyclesTestMI:            6,
        nOpCyclesXchgRR:            3,
        nOpCyclesXchgRM:            5,
        nOpCyclesXLAT:              5
    },
    /*
     * TODO: All 80386 cycle counts are based on 80286 counts until I have time to hand-generate an 80386-specific table;
     * the values below are used by selected 32-bit opcode handlers only.
     */
    CYCLES_80386: {
        nEACyclesBase:              0,
        nEACyclesDisp:              0,
        nEACyclesBaseIndex:         0,
        nEACyclesBaseIndexExtra:    0,
        nEACyclesBaseDisp:          0,
        nEACyclesBaseIndexDisp:     1,
        nEACyclesBaseIndexDispExtra:1
    }
};

/*
 * These PS flags are always stored directly in regPS for the 8086/8088, hence the
 * "direct" designation; other processors must adjust these bits accordingly.  The final
 * adjusted value is stored in PS_DIRECT (ie, 80286 and up also include PS.IOPL.MASK and
 * PS.NT in PS_DIRECT).
 */
X86.PS_DIRECT_8086 = (X86.PS.TF | X86.PS.IF | X86.PS.DF);

/*
 * These are the default "always set" PS bits for the 8086/8088; other processors must
 * adjust these bits accordingly.  The final adjusted value is stored in PS_SET.
 */
X86.PS_SET_8086 = (X86.PS.BIT1 | X86.PS.IOPL.MASK | X86.PS.NT | X86.PS.BIT15);

/*
 * These PS arithmetic and logical flags may be "cached" across several result registers;
 * whether or not they're currently cached depends on the RESULT bits in resultType.
 */
X86.PS_CACHED = (X86.PS.CF | X86.PS.PF | X86.PS.AF | X86.PS.ZF | X86.PS.SF | X86.PS.OF);

/*
 * PS_SAHF is a subset of the arithmetic flags, and refers only to those flags that the
 * SAHF and LAHF "8080 legacy" opcodes affect.
 */
X86.PS_SAHF = (X86.PS.CF | X86.PS.PF | X86.PS.AF | X86.PS.ZF | X86.PS.SF);

/*
 * Before we zero opFlags, we first see if any of the following PREFIX bits were set.  If any were set,
 * they are OR'ed into opPrefixes; otherwise, opPrefixes is zeroed as well.  This gives prefix-conscious
 * instructions like LODS, MOVS, STOS, CMPS, etc, a way of determining which prefixes, if any, immediately
 * preceded them.
 */
X86.OPFLAG_PREFIXES = (X86.OPFLAG.SEG | X86.OPFLAG.LOCK | X86.OPFLAG.REPZ | X86.OPFLAG.REPNZ | X86.OPFLAG.DATASIZE | X86.OPFLAG.ADDRSIZE);


/**
 * @copyright https://www.pcjs.org/machines/pcx86/lib/interrupts.js (C) 2012-2021 Jeff Parsons
 */

var Interrupts = {
    /*
     * The original ROM BIOS defined vectors 0x08-0x1F with a table at F000:FEF3 (VECTOR_TABLE).
     */
    VIDEO:      0x10,
    EQUIPMENT:  0x11,
    MEM_SIZE:   0x12,
    DISK:       0x13,
    SERIAL:     0x14,
    CASSETTE:   0x15,
    KEYBOARD:   0x16,
    PARALLEL:   0x17,
    BASIC:      0x18,               // normally F600:0000
    BOOTSTRAP:  0x19,
    TIMER:      0x1A,
    KBD_BREAK:  0x1B,
    TMR_BREAK:  0x1C,               // invoked by the BIOS timer interrupt handler (normally vector 0x08)
    VID_PARMS:  0x1D,
    DSK_PARMS:  0x1E,
    /*
     * For characters 0x00-0x7F, the original ROM BIOS used a built-in table at F000:FA6E (CRT_CHAR_GEN),
     * since the MDA/CGA font ROM was not CPU-addressable, but presumably there wasn't enough room in the
     * ROM BIOS for all 256 characters, so if software wanted to draw any characters 0x80-0xFF in graphics
     * mode, it was up to software to provide the font data and set the VID_EXT vector to point to it.
     */
    VID_EXT:    0x1F,               // graphics characters 0x80-0xFF (aka EXT_PTR)
    DOS:        0x21,
    DOS_IDLE:   0x28,
    DOS_NETBIOS:0x2A,
    MOUSE:      0x33,
    ALT_DISK:   0x40,               // HDC ROM saves original FDC vector here
    HD0_PARMS:  0x41,               // parameter table for hard drive 0
    VID_PLANAR: 0x42,               // EGA ROM saves original VIDEO ("planar ROM") vector here
    EGA_GRX:    0x43,               // EGA ROM provides a complete set of mode-appropriate font data here (0000:010C)
    HD1_PARMS:  0x46,               // parameter table for hard drive 1
    HD_PARMS: {
        MAX_CYL:    0x00,           // maximum cylinders (2 bytes)
        MAX_HEADS:  0x02,           // maximum heads (1 byte)
        WP_CYL:     0x05,           // write precompensation cylinder (2 bytes)
        MAX_ECC:    0x07,           // max ECC burst (1 byte)
        DRIVE_CTRL: 0x08,           // drive control (1 byte)
        PARK_CYL:   0x0C,           // landing zone cylinder (2 bytes)
        SEC_TRACK:  0x0E            // sectors per track (1 byte)
    },
    ALT_VIDEO:  0x6D,               // VGA ROM saves original VIDEO vector here (one wonders what was wrong with VID_PLANAR)
    WINCB: {
        VECTOR:     0x30            // Windows PM call-back interface (aka Transfer Space Fault)
    },
   
  
};



//TODO MEMORY UINT8ARR HUGE




/**
 * @copyright https://www.pcjs.org/machines/pcx86/lib/fpux86.js (C) 2012-2021 Jeff Parsons
 */


/*
 * Operand Type Reference
 *
 *      ST(0), ST           stack top; the register currently at the top of the stack
 *      ST(i)               register in the stack i (0<=i<=7) stack elements from the top
 *      SR (short-real)     short real (32 bits) number in memory; exponent bias is 127 (0x7f)
 *      LR (long-real)      long real (64 bits) number in memory; exponent bias is 1023 (0x3ff)
 *      TR (temp-real)      temporary real (80 bits) number in memory; exponent bias is 16383 (0x3fff)
 *      PD (packed-decimal) packed decimal integer (18 digits, 10 bytes) in memory
 *      WI (word-integer)   word binary integer (16 bits) in memory
 *      SI (short-integer)  short binary integer (32 bits) in memory
 *      LI (long-integer)   long binary integer (64 bits) in memory
 *      NN (nn-bytes)       memory area nn bytes long
 *
 * FPU Coprocessor Trivia
 *
 *      Microsoft C 4.00 libraries executed software interrupts in the range 0x34-0x3B immediately after
 *      FPU operations, to assist with floating-point emulation when no coprocessor was present, since
 *      processors prior to the 80286 had no mechanism for generating a fault when an unsupported FPU
 *      instruction was executed.
 *
 *      In short, INT 0x34 through INT 0x3B was used after ESC opcodes 0xD8 through 0xDF, INT 0x3C was
 *      used for FPU instructions containing a segment override, and INT 0x3D was used for FWAIT.
 *
 *      A sample piece of code is available in x86ops.js, because it also highlights the Microsoft C 4.00
 *      library's dependency on the 8086/8088 behavior of "PUSH SP" (see the opPUSHSP_8086() function).
 */



const FPUx86 = {}


FPUx86.F2XM1 = function()
{
    this.setST(0, Math.pow(2, this.getST(0)) - 1);
};

/**
 * FABS()
 *
 * @this {FPUx86}
 */
FPUx86.FABS = function()
{
    /*
     * TODO: This could be implemented more efficiently by simply clearing the sign bit of ST(0).
     */
    this.setST(0, Math.abs(this.getST(0)));
};

/**
 * FADDlr()
 *
 * @this {FPUx86}
 */
FPUx86.FADDlr = function()
{
    this.setST(0, this.doAdd(this.getST(0), this.getLRFromEA()));
};

/**
 * FADDsr()
 *
 * Encoding 0xD8,reg=0x00 ("FADD short-real"): ST(0) <- ST(0) + REAL32
 *
 * @this {FPUx86}
 */
FPUx86.FADDsr = function()
{
    this.setST(0, this.doAdd(this.getST(0), this.getSRFromEA()));
};

/**
 * FADDst()
 *
 * @this {FPUx86}
 */
FPUx86.FADDst = function()
{
    this.setST(0, this.doAdd(this.getST(0), this.getST(this.iStack)));
};

/**
 * FADDsti()
 *
 * @this {FPUx86}
 */
FPUx86.FADDsti = function()
{
    this.setST(this.iStack, this.doAdd(this.getST(this.iStack), this.getST(0)));
};

/**
 * FADDPsti()
 *
 * @this {FPUx86}
 */
FPUx86.FADDPsti = function()
{
    if (this.setST(this.iStack, this.doAdd(this.getST(this.iStack), this.getST(0)))) this.popValue();
};

/**
 * FBLDpd()
 *
 * @this {FPUx86}
 */
FPUx86.FBLDpd = function()
{
    let a = this.getTRFromEA();
    /*
     * a[0] contains the 8 least-significant BCD digits, a[1] contains the next 8, and a[2] contains
     * the next 2 (bit 15 of a[2] is the sign bit, and bits 8-14 of a[2] are unused).
     */
    let v = this.decodeBCD(a[0], 8) + this.decodeBCD(a[1], 8) * 100000000 + this.decodeBCD(a[2], 2) * 10000000000000000;
    if (a[2] & 0x8000) v = -v;
    this.pushValue(v);
};

/**
 * FBSTPpd()
 *
 * @this {FPUx86}
 */
FPUx86.FBSTPpd = function()
{
    /*
     * TODO: Verify the operation of FBSTP (eg, does it signal an exception if abs(value) >= 1000000000000000000?)
     */
    let v = this.roundValue(this.popValue());
    if (v != null) {
        /*
         * intTmpTR[0] will contain the 8 least-significant BCD digits, intTmpTR[1] will contain the next 8,
         * and intTmpTR[2] will contain the next 2 (bit 15 of intTmpTR[2] will be the sign bit, and bits 8-14 of
         * intTmpTR[2] will be unused).
         */
        this.intTmpTR[0] = this.encodeBCD(v, 8);
        this.intTmpTR[1] = this.encodeBCD(v / 100000000, 8);
        this.intTmpTR[2] = this.encodeBCD(v / 10000000000000000, 2);
        if (v < 0) this.intTmpTR[2] |= 0x8000;
        this.setEAFromTR();
    }
};

/**
 * FCHS()
 *
 * @this {FPUx86}
 */
FPUx86.FCHS = function()
{
    /*
     * TODO: This could be implemented more efficiently by simply inverting the sign bit of ST(0).
     */
    this.setST(0, -this.getST(0));
};

/**
 * FCLEX()
 *
 * NOTE: Although we explicitly clear the BUSY bit, there shouldn't be any code setting it, because
 * we're never "busy" (all floating-point operations are performed synchronously).  Conversely, there's
 * no need to explicitly clear the ES bit, because clearStatus() will call checkException(), which
 * updates ES and clears/sets FPU interrupt status as appropriate.
 *
 * @this {FPUx86}
 */
FPUx86.FCLEX = function()
{
    this.clearStatus(X86.FPU.STATUS.EXC | X86.FPU.STATUS.BUSY);
};

/**
 * FCOMlr()
 *
 * Encoding 0xDC,mod<3,reg=2 ("FCOM long-real"): Evaluate ST(0) - REAL64
 *
 * @this {FPUx86}
 */
FPUx86.FCOMlr = function()
{
    this.doCompare(this.getST(0), this.getLRFromEA());
};

/**
 * FCOMsr()
 *
 * Encoding 0xD8,mod<3,reg=2 ("FCOM short-real"): Evaluate ST(0) - REAL32
 *
 * @this {FPUx86}
 */
FPUx86.FCOMsr = function()
{
    this.doCompare(this.getST(0), this.getSRFromEA());
};

/**
 * FCOMst()
 *
 * Encoding 0xD8,mod=3,reg=2 ("FCOM ST(i)"): Evaluate ST(0) - ST(i)
 *
 * @this {FPUx86}
 */
FPUx86.FCOMst = function()
{
    this.doCompare(this.getST(0), this.getST(this.iStack));
};

/**
 * FCOM8087()
 *
 * NOTE: This is used with encoding(s) (0xDC,0xD0-0xD7) that were valid for the 8087 and 80287
 * but may no longer be valid as of the 80387.
 *
 * TODO: Determine if this form subtracted the operands in the same order, or if it requires an FCOMsti(),
 * which, like the other *sti() functions, uses ST(0) as the second operand rather than the first.
 *
 * @this {FPUx86}
 */
FPUx86.FCOM8087 = function()
{
    this.opObsolete();
    FPUx86.FCOMst.call(this);
};

/**
 * FCOMPlr()
 *
 * Encoding 0xDC,mod<3,reg=3 ("FCOM long-real"): Evaluate ST(0) - REAL64, POP
 *
 * @this {FPUx86}
 */
FPUx86.FCOMPlr = function()
{
    if (this.doCompare(this.getST(0), this.getLRFromEA())) this.popValue();
};

/**
 * FCOMPsr()
 *
 * Encoding 0xD8,mod<3,reg=3 ("FCOM short-real"): Evaluate ST(0) - REAL32, POP
 *
 * @this {FPUx86}
 */
FPUx86.FCOMPsr = function()
{
    if (this.doCompare(this.getST(0), this.getSRFromEA())) this.popValue();
};

/**
 * FCOMPst()
 *
 * Encoding 0xD8,mod=3,reg=3 ("FCOMP ST(i)"): Evaluate ST(0) - ST(i), POP
 *
 * @this {FPUx86}
 */
FPUx86.FCOMPst = function()
{
    if (this.doCompare(this.getST(0), this.getST(this.iStack))) this.popValue();
};

/**
 * FCOMP8087()
 *
 * NOTE: This is used with encodings (0xDC,0xD8-0xDF and 0xDE,0xD0-0xD7) that were valid for the 8087
 * and 80287 but may no longer be valid as of the 80387.
 *
 * TODO: Determine if this form subtracted the operands in the same order, or if it requires an FCOMPsti(),
 * which, like the other *sti() functions, uses ST(0) as the second operand rather than the first.
 *
 * @this {FPUx86}
 */
FPUx86.FCOMP8087 = function()
{
    this.opObsolete();
    FPUx86.FCOMPst.call(this);
};

/**
 * FCOMPP()
 *
 * @this {FPUx86}
 */
FPUx86.FCOMPP = function()
{
    if (this.doCompare(this.getST(0), this.getST(1)) && this.popValue() != null) this.popValue();
};

/**
 * FDECSTP()
 *
 * @this {FPUx86}
 */
FPUx86.FDECSTP = function()
{
    this.iST = (this.iST - 1) & 0x7;
    this.regStatus &= ~X86.FPU.STATUS.C1;
};

/**
 * FDISI8087()
 *
 * @this {FPUx86}
 */
FPUx86.FDISI8087 = function()
{
    if (this.isModel(X86.FPU.MODEL_8087)) {
        this.regControl |= X86.FPU.CONTROL.IEM;
    }
};

/**
 * FDIVlr()
 *
 * @this {FPUx86}
 */
FPUx86.FDIVlr = function()
{
    this.setST(0, this.doDivide(this.getST(0), this.getLRFromEA()));
};

/**
 * FDIVsr()
 *
 * @this {FPUx86}
 */
FPUx86.FDIVsr = function()
{
    this.setST(0, this.doDivide(this.getST(0), this.getSRFromEA()));
};

/**
 * FDIVst()
 *
 * Encoding 0xD8,0xF0-0xF7 ("FDIV ST,ST(i)"): ST(0) <- ST(0) / ST(i)
 *
 * @this {FPUx86}
 */
FPUx86.FDIVst = function()
{
    this.setST(0, this.doDivide(this.getST(0), this.getST(this.iStack)));
};

/**
 * FDIVsti()
 *
 * Encoding 0xDC,0xF8-0xFF ("FDIV ST(i),ST"): ST(i) <- ST(i) / ST(0)
 *
 * @this {FPUx86}
 */
FPUx86.FDIVsti = function()
{
    this.setST(this.iStack, this.doDivide(this.getST(this.iStack), this.getST(0)));
};

/**
 * FDIVPsti()
 *
 * Encoding 0xDE,0xF8-0xFF ("FDIVP ST(i),ST"): ST(i) <- ST(i) / ST(0), POP
 *
 * @this {FPUx86}
 */
FPUx86.FDIVPsti = function()
{
    if (this.setST(this.iStack, this.doDivide(this.getST(this.iStack), this.getST(0)))) this.popValue();
};

/**
 * FDIVRlr()
 *
 * @this {FPUx86}
 */
FPUx86.FDIVRlr = function()
{
    this.setST(0, this.doDivide(this.getLRFromEA(), this.getST(0)));
};

/**
 * FDIVRsr()
 *
 * @this {FPUx86}
 */
FPUx86.FDIVRsr = function()
{
    this.setST(0, this.doDivide(this.getSRFromEA(), this.getST(0)));
};

/**
 * FDIVRst()
 *
 * Encoding 0xD8,0xF8-0xFF ("FDIVR ST,ST(i)"): ST(0) <- ST(i) / ST(0)
 *
 * @this {FPUx86}
 */
FPUx86.FDIVRst = function()
{
    this.setST(0, this.doDivide(this.getST(this.iStack), this.getST(0)));
};

/**
 * FDIVRsti()
 *
 * Encoding 0xDC,0xF0-0xF7 ("FDIVR ST(i),ST"): ST(i) <- ST(0) / ST(i)
 *
 * @this {FPUx86}
 */
FPUx86.FDIVRsti = function()
{
    this.setST(this.iStack, this.doDivide(this.getST(0), this.getST(this.iStack)));
};

/**
 * FDIVRPsti()
 *
 * Encoding 0xDE,0xF0-0xE7 ("FDIVRP ST(i),ST"): ST(i) <- ST(0) / ST(i), POP
 *
 * @this {FPUx86}
 */
FPUx86.FDIVRPsti = function()
{
    if (this.setST(this.iStack, this.doDivide(this.getST(0), this.getST(this.iStack)))) this.popValue();
};

/**
 * FENI8087()
 *
 * @this {FPUx86}
 */
FPUx86.FENI8087 = function()
{
    if (this.isModel(X86.FPU.MODEL_8087)) {
        this.regControl &= ~X86.FPU.CONTROL.IEM;
    }
};

/**
 * FFREEsti()
 *
 * @this {FPUx86}
 */
FPUx86.FFREEsti = function()
{
    this.setTag(this.iST, X86.FPU.TAGS.EMPTY);
};

/**
 * FFREEP8087()
 *
 * NOTE: This is used with an encoding (0xDF,0xC0-0xC7) that was valid for the 8087 and 80287
 * but may no longer be valid as of the 80387.  Also, if the older documentation is to be believed,
 * this instruction has no modern counterpart, as FFREE doesn't pop the stack.
 *
 * @this {FPUx86}
 */
FPUx86.FFREEP8087 = function()
{
    this.opObsolete();
    FPUx86.FFREEsti.call(this);
    this.popValue();
};

/**
 * FIADD16()
 *
 * @this {FPUx86}
 */
FPUx86.FIADD16 = function()
{
    this.setST(0, this.doAdd(this.getST(0), this.getWIFromEA()));
};

/**
 * FIADD32()
 *
 * @this {FPUx86}
 */
FPUx86.FIADD32 = function()
{
    this.setST(0, this.doAdd(this.getST(0), this.getSIFromEA()));
};

/**
 * FICOM16()
 *
 * @this {FPUx86}
 */
FPUx86.FICOM16 = function()
{
    this.doCompare(this.getST(0), this.getWIFromEA());
};

/**
 * FICOM32()
 *
 * @this {FPUx86}
 */
FPUx86.FICOM32 = function()
{
    this.doCompare(this.getST(0), this.getSIFromEA());
};

/**
 * FICOMP16()
 *
 * @this {FPUx86}
 */
FPUx86.FICOMP16 = function()
{
    if (this.doCompare(this.getST(0), this.getWIFromEA())) this.popValue();
};

/**
 * FICOMP32()
 *
 * @this {FPUx86}
 */
FPUx86.FICOMP32 = function()
{
    if (this.doCompare(this.getST(0), this.getSIFromEA())) this.popValue();
};

/**
 * FIDIV16()
 *
 * @this {FPUx86}
 */
FPUx86.FIDIV16 = function()
{
    this.setST(0, this.doDivide(this.getST(0), this.getWIFromEA()));
};

/**
 * FIDIV32()
 *
 * @this {FPUx86}
 */
FPUx86.FIDIV32 = function()
{
    this.setST(0, this.doDivide(this.getST(0), this.getSIFromEA()));
};

/**
 * FIDIVR16()
 *
 * @this {FPUx86}
 */
FPUx86.FIDIVR16 = function()
{
    this.setST(0, this.doDivide(this.getWIFromEA(), this.getST(0)));
};

/**
 * FIDIVR32()
 *
 * @this {FPUx86}
 */
FPUx86.FIDIVR32 = function()
{
    this.setST(0, this.doDivide(this.getSIFromEA(), this.getST(0)));
};

/**
 * FILD16()
 *
 * @this {FPUx86}
 */
FPUx86.FILD16 = function()
{
    this.pushValue(this.getWIFromEA());
};

/**
 * FILD32()
 *
 * @this {FPUx86}
 */
FPUx86.FILD32 = function()
{
    this.pushValue(this.getSIFromEA());
};

/**
 * FILD64()
 *
 * @this {FPUx86}
 */
FPUx86.FILD64 = function()
{
    this.pushValue(this.getLIFromEA());
};

/**
 * FIMUL16()
 *
 * @this {FPUx86}
 */
FPUx86.FIMUL16 = function()
{
    this.setST(0, this.doMultiply(this.getST(0), this.getWIFromEA()));
};

/**
 * FIMUL32()
 *
 * @this {FPUx86}
 */
FPUx86.FIMUL32 = function()
{
    this.setST(0, this.doMultiply(this.getST(0), this.getSIFromEA()));
};

/**
 * FINCSTP()
 *
 * @this {FPUx86}
 */
FPUx86.FINCSTP = function()
{
    this.iST = (this.iST + 1) & 0x7;
    this.regStatus &= ~X86.FPU.STATUS.C1;
};

/**
 * FINIT()
 *
 * @this {FPUx86}
 */
FPUx86.FINIT = function()
{
    this.resetFPU();
};

/**
 * FIST16()
 *
 * @this {FPUx86}
 */
FPUx86.FIST16 = function()
{
    if (this.getWI(0)) this.setEAFromWI();
};

/**
 * FIST32()
 *
 * @this {FPUx86}
 */
FPUx86.FIST32 = function()
{
    if (this.getSI(0)) this.setEAFromSI();
};

/**
 * FISTP16()
 *
 * @this {FPUx86}
 */
FPUx86.FISTP16 = function()
{
    if (this.getWI(0)) {
        this.setEAFromWI();
        this.popValue();
    }
};

/**
 * FISTP32()
 *
 * @this {FPUx86}
 */
FPUx86.FISTP32 = function()
{
    if (this.getSI(0)) {
        this.setEAFromSI();
        this.popValue();
    }
};

/**
 * FISTP64()
 *
 * @this {FPUx86}
 */
FPUx86.FISTP64 = function()
{
    if (this.getLI(0)) {
        this.setEAFromLI();
        this.popValue();
    }
};

/**
 * FISUB16()
 *
 * @this {FPUx86}
 */
FPUx86.FISUB16 = function()
{
    this.setST(0, this.doSubtract(this.getST(0), this.getWIFromEA()));
};

/**
 * FISUB32()
 *
 * @this {FPUx86}
 */
FPUx86.FISUB32 = function()
{
    this.setST(0, this.doSubtract(this.getST(0), this.getSIFromEA()));
};

/**
 * FISUBR16()
 *
 * @this {FPUx86}
 */
FPUx86.FISUBR16 = function()
{
    this.setST(0, this.doSubtract(this.getWIFromEA(), this.getST(0)));
};

/**
 * FISUBR32()
 *
 * @this {FPUx86}
 */
FPUx86.FISUBR32 = function()
{
    this.setST(0, this.doSubtract(this.getSIFromEA(), this.getST(0)));
};

/**
 * FLDlr()
 *
 * The FLD instruction loads the source operand, converts it to temporary real format (if required),
 * and pushes the resulting value onto the floating-point stack.
 *
 * The load operation is accomplished by decrementing the top-of-stack pointer (TOP) and copying the
 * source operand to the new stack top. If the source operand is a float ing-point register, the index of
 * the register is taken before TOP is changed. The source operand may also be a short real, long real,
 * or temporary real memory operand. Short real and long real operands are converted automatically.
 *
 * Note that coding the instruction FLD ST(0) duplicates the value at the stack top.
 *
 * On the 8087 and 80287, the FLD real80 instruction will raise the denormal exception if the memory
 * operand is a denormal. The 80287XL and later coprocessors will not, since the operation is not arithmetic.
 *
 * On the 8087 and 80287, a denormal will be converted to an unnormal by FLD; on the 80287XL and later
 * coprocessors, the number will be converted to temporary real. If the next instruction is an FXTRACT or FXAM,
 * the 8087/80827 and 80287XL/80387/ 80486 results will be different.
 *
 * On the 8087 and 80287, the FLD real32 and FLD real64 instructions will not raise an exception when loading
 * a signaling NaN; on the 80287XL and later coprocessors, loading a signaling NaN raises the invalid operation
 * exception.
 *
 * @this {FPUx86}
 */
FPUx86.FLDlr = function()
{
    this.pushValue(this.getLRFromEA());
};

/**
 * FLDsr()
 *
 * @this {FPUx86}
 */
FPUx86.FLDsr = function()
{
    this.pushValue(this.getSRFromEA());
};

/**
 * FLDsti()
 *
 * @this {FPUx86}
 */
FPUx86.FLDsti = function()
{
    this.pushValue(this.getST(this.iStack));
};

/**
 * FLDtr()
 *
 * @this {FPUx86}
 */
FPUx86.FLDtr = function()
{
    this.pushValue(this.getLRFromTR(this.getTRFromEA()));
};

/**
 * FLDCW()
 *
 * @this {FPUx86}
 */
FPUx86.FLDCW = function()
{

    this.setControl(this.cpu.getShort(this.cpu.regEA));
};

/**
 * FLDENV()
 *
 * @this {FPUx86}
 */
FPUx86.FLDENV = function()
{

    this.loadEnv(this.cpu.regEA);
};

/**
 * FLD1()
 *
 * The FLD1 instruction loads the constant +1.0 from the NPX's constant ROM and pushes the value onto the
 * floating-point stack.
 *
 * The constant is stored internally in temporary real format and is simply moved to the stack.
 *
 * See also: FLDLG2, FLDLN2, FLDL2E, FLDL2T, FLDPI, and FLD1.
 *
 * @this {FPUx86}
 */
FPUx86.FLD1 = function()
{
    this.pushValue(1.0);
};

/**
 * FLDL2T()
 *
 * The FLDL2T instruction loads the constant log2(10) from the NPX's constant ROM and pushes the value onto the
 * floating-point stack.
 *
 * The constant is stored internally in temporary real format and is simply moved to the stack.
 *
 * On the 8087 and 80287, rounding control is not in effect for the loading of this constant.  On the 80287XL and
 * later coprocessors, rounding control is in effect.  If RC is set for chop (round toward 0), round down (toward
 * -infinity), or round to nearest or even, the result will be the same as on the 8087 and 80287.  If RC is set for
 * round up (toward +infinity), the result will differ by one in the least significant bit of the mantissa.
 *
 * See also: FLDLG2, FLDLN2, FLDL2E, FLDPI, FLD1, and FLDZ.
 *
 * @this {FPUx86}
 */
FPUx86.FLDL2T = function()
{
    this.pushValue(FPUx86.regL2T);
};

/**
 * FLDL2E()
 *
 * The FLDL2E instruction loads the constant log2(e) from the NPX's constant ROM and pushes the value onto the
 * floating-point stack.
 *
 * The constant is stored internally in temporary real format and is simply moved to the stack.
 *
 * On the 8087 and 80287, rounding control is not in effect for the loading of this constant.  On the 80287XL and
 * later coprocessors, rounding control is in effect.  If RC is set for chop (round toward 0) or round down (toward
 * -infinity), the result is the same as on the 8087 and 80827.  If RC is set for round to nearest or even, or round
 * up (toward +infinity), the result will differ by one in the least significant bit of the mantissa.
 *
 * See also: FLDLG2, FLDLN2, FLDL2T, FLDPI, FLD1, and FLDZ.
 *
 * @this {FPUx86}
 */
FPUx86.FLDL2E = function()
{
    this.pushValue(FPUx86.regL2E);
};

/**
 * FLDPI()
 *
 * The FLDPI instruction loads the constant Pi from the NPX's constant ROM and pushes the value onto the
 * floating-point stack.
 *
 * The constant is stored internally in temporary real format and is simply moved to the stack.
 *
 * On the 8087 and 80287, rounding control is not in effect for the loading of these constants.  On the 80287XL and
 * later coprocessors, rounding control is in effect.  If RC is set for chop (round toward 0) or round down (toward
 * -infinity), the result is the same as on the 8087 and 80827.  If RC is set for round to nearest or even, or round
 * up (toward +infinity), the result will differ by one in the least significant bit of the mantissa.
 *
 * See also: FLDLG2, FLDLN2, FLDL2E, FLDL2T, FLD1, and FLDZ.
 *
 * @this {FPUx86}
 */
FPUx86.FLDPI = function()
{
    this.pushValue(FPUx86.regPI);
};

/**
 * FLDLG2()
 *
 * The FLDLG2 instruction loads the constant log10(2) from the NPX's constant ROM and pushes the value onto the
 * floating-point stack.
 *
 * The constant is stored internally in temporary real format and is simply moved to the stack.
 *
 * On the 8087 and 80287, rounding control is not in effect for the loading of this constant.  On the 80287XL and
 * later coprocessors, rounding control is in effect.  If RC is set for chop (round toward 0) or round down (toward
 * -infinity), the result is the same as on the 8087 and 80827.  If RC is set for round to nearest or even, or round
 * up (toward +infinity), the result will differ by one in the least significant bit of the mantissa.
 *
 * See also: FLDLN2, FLDL2E, FLDL2T, FLDPI, FLD1, and FLDZ.
 *
 * @this {FPUx86}
 */
FPUx86.FLDLG2 = function()
{
    this.pushValue(FPUx86.regLG2);
};

/**
 * FLDLN2()
 *
 * The FLDLN2 instruction loads the constant loge(2) from the NPX's constant ROM and pushes the value onto the
 * floating-point stack.
 *
 * The constant is stored internally in temporary real format and is simply moved to the stack.
 *
 * On the 8087 and 80287, rounding control is not in effect for the loading of this constant.  On the 80287XL and
 * later coprocessors, rounding control is in effect.  If RC is set for chop (round toward 0) or round down (toward
 * -infinity), the result will be the same as on the 8087 and 80827.  If RC is set for round to nearest or even, or
 * round up (toward +infinity), the result will differ by one in the least significant bit of the mantissa.
 *
 * See also: FLDLG2, FLDL2E, FLDL2T, FLDPI, FLD1, and FLDZ.
 *
 * @this {FPUx86}
 */
FPUx86.FLDLN2 = function()
{
    this.pushValue(FPUx86.regLN2);
};

/**
 * FLDZ()
 *
 * The FLDZ instruction loads the constant +0.0 from the NPX's constant ROM and pushes the value onto the
 * floating-point stack.
 *
 * The constant is stored internally in temporary real format and is simply moved to the stack.
 *
 * See also: FLDLG2, FLDLN2, FLDL2E, FLDL2T, FLDPI, and FLD1.
 *
 * @this {FPUx86}
 */
FPUx86.FLDZ = function()
{
    this.pushValue(0.0);
};

/**
 * FMULlr()
 *
 * @this {FPUx86}
 */
FPUx86.FMULlr = function()
{
    this.setST(0, this.doMultiply(this.getST(0), this.getLRFromEA()));
};

/**
 * FMULsr()
 *
 * Encoding 0xD8,reg=0x01 ("FMUL short-real"): ST(0) <- ST(0) * REAL32
 *
 * @this {FPUx86}
 */
FPUx86.FMULsr = function()
{
    this.setST(0, this.doMultiply(this.getST(0), this.getSRFromEA()));
};

/**
 * FMULst()
 *
 * @this {FPUx86}
 */
FPUx86.FMULst = function()
{
    this.setST(0, this.doMultiply(this.getST(0), this.getST(this.iStack)));
};

/**
 * FMULsti()
 *
 * @this {FPUx86}
 */
FPUx86.FMULsti = function()
{
    this.setST(this.iStack, this.doMultiply(this.getST(this.iStack), this.getST(0)));
};

/**
 * FMULPsti()
 *
 * @this {FPUx86}
 */
FPUx86.FMULPsti = function()
{
    if (this.setST(this.iStack, this.doMultiply(this.getST(this.iStack), this.getST(0)))) this.popValue();
};

/**
 * FNOP()
 *
 * @this {FPUx86}
 */
FPUx86.FNOP = function()
{
};

/**
 * FPATAN()
 *
 * FPATAN calculates the partial arctangent of ST(0) divided by ST(1):
 *
 *      ST(1) = tan^-1( ST(1) / ST(0) )
 *
 * On the 8087 and 80287, the arguments must satisfy the inequality 0 <= ST(1) < ST(0) < +infinity.
 * On the 80287XL and later coprocessors, the range of the operands is unrestricted.  The result is
 * returned to ST(1), and the stack is popped, destroying both operands and leaving the result in ST(0).
 *
 * @this {FPUx86}
 */
FPUx86.FPATAN = function()
{
    if (this.setST(1, Math.atan2(this.getST(1), this.getST(0)))) this.popValue();
};

/**
 * FPTAN()
 *
 * FPTAN calculates the partial tangent of ST(0):
 *
 *      y / x = tan( ST(0) )
 *
 * The result of the operation is a ratio.  y replaces the argument on the stack, and x is pushed onto the stack,
 * where it becomes the new ST(0).
 *
 * On the 8087 and 80287, the FPTAN function assumes that its argument is valid and in-range.  No argument checking
 * is performed.  The value of ST(0) must satisfy the inequality -pi/4 <= ST(0) <= pi/4.  In the case of an invalid
 * argument, the result is undefined and no error is signaled.
 *
 * On the 80287XL and later coprocessors, if value of ST(0) satisfies the condition -2^63 < ST(0) < 2^63, it will
 * automatically be reduced to within range.  If the operand is outside this range, however, C2 is set to 1 to indicate
 * that the function is incomplete, and ST(0) is left unchanged.
 *
 * The 80287XL, 80387, and 80486 always push a value of +1.0 for x. The value of x pushed by the 8087 and 80287 may be
 * any real number.  In either case, the ratio is the same. The cotangent can be calculated by executing FDIVR immediately
 * after FPTAN.  The following code will leave the 8087 and 80287 in the same state as the later coprocessors:
 *
 *      FDIV
 *      FLD1
 *
 * ST(7) must be empty before this instruction is executed to avoid an invalid operation exception.  If the invalid
 * operation exception is masked, the 8087 and 80287 leave the original operand unchanged, but push it to ST(1).  On the
 * 80287XL and later coprocessors, both ST(0) and ST(1) will contain quiet NaNs.  On the 80287XL and later coprocessors,
 * if condition code bit C2 is 0 and the precision exception is raised, then C1=1 if the last bit was rounded up. C1 is
 * undefined for the 8087 and 80287.
 *
 * @this {FPUx86}
 */
FPUx86.FPTAN = function()
{
    if (this.setST(0, Math.tan(this.getST(0)))) this.pushValue(1.0);
};

/**
 * FPREM()
 *
 * FPREM performs modulo division of ST(0) by ST(1) and returns the result to ST(0).
 *
 * The FPREM instruction is used to reduce the real operand in ST(0) to a value whose magnitude is less than the
 * magnitude of ST(1).  FPREM produces an exact result, so the precision exception is never raised and the rounding
 * control has no effect.  The sign of the remainder is the same as the sign of the original operand.
 *
 * The remaindering operation is performed by iterative scaled subtractions and can reduce the exponent of ST(0) by
 * no more than 63 in one execution.  If the remainder is less than ST(1) (the modulus), the function is complete and
 * C2 in the status word is cleared.
 *
 * If the modulo function is incomplete, C2 is set to 1, and the result in ST(0) is termed the partial remainder.
 * C2 can be inspected by storing the status word and re-executing the instruction until C2 is clear. Alternately,
 * ST(0) can be compared to ST(1).  If ST(0) > ST(1), then FPREM must be executed again.  If ST(0) = ST(1), then the
 * remainder is 0.
 *
 * FPREM is important for reducing arguments to the periodic transcendental functions such as FPTAN.  Because FPREM
 * produces an exact result, no round-off error is introduced into the calculation.
 *
 * When reduction is complete, the three least-significant bits of the quotient are stored in the condition code bits
 * C3, C1, and C0, respectively.  When arguments to the tangent function are reduced by pi/4, this result can be used
 * to identify the octant that contained the original angle.
 *
 * The FPREM function operates differently than specified by the IEEE 754 standard when rounding the quotient to form
 * a partial remainder (see the algorithm).  The FPREM1 function (80287XL and up) is provided for compatibility with
 * that standard.
 *
 * The FPREM instruction can also be used to normalize ST(0).  If ST(0) is unnormal and ST(1) is greater than ST(0),
 * FPREM will normalize ST(0).  On the 8087 and 80287, operation on a denormal operand raises the invalid operation
 * exception.  Underflow is not possible.  On the 80287XL and later coprocessors, operation on a denormal is supported
 * and an underflow exception can occur.
 *
 * ALGORITHM:
 *
 *      t = EXPONENT(ST) - EXPONENT(ST(1))
 *      IF (t < 64) THEN
 *          q = R0UND(ST(0) / ST(1), CHOP)
 *          ST(0) = ST(0) - (ST(1) * q)
 *          C2 = 0
 *          C0 = BIT 2 of q
 *          C1 = BIT 1 of q
 *          C3 = BIT 0 of q
 *      ELSE
 *          n = a number between 32 and 63
 *          q = ROUND((ST(0) / ST(1)) / 2^(t-n), CHOP)
 *          ST(0) = ST(0) - (ST(1) * q * 2^(t-n))
 *          C2 = 1
 *      ENDIF
 *
 * TODO: Determine the extent to which the JavaScript MOD operator differs from the above algorithm.
 *
 * ERRATA: On the 8087 and 80287, the condition code bits C3, C1, and C0 are incorrect when performing a reduction of
 * 64^n + m, where n >= 1, and m=1 or m=2.  A bug fix should be implemented in software.
 *
 * @this {FPUx86}
 */
FPUx86.FPREM = function()
{
    this.setST(0, this.getST(0) % this.getST(1));
};

/**
 * FRSTOR()
 *
 * @this {FPUx86}
 */
FPUx86.FRSTOR = function()
{
    let cpu = this.cpu;
    let addr = this.loadEnv(cpu.regEA);
    let a = this.intTmpTR;
    for (let i = 0; i < this.regStack.length; i++) {
        a[0] = cpu.getLong(addr);
        a[1] = cpu.getLong(addr += 4);
        a[2] = cpu.getShort(addr += 4);
        this.setTR(i, a);
        addr += 2;
    }
};

/**
 * FRNDINT()
 *
 * @this {FPUx86}
 */
FPUx86.FRNDINT = function()
{
    this.setST(0, this.roundValue(this.getST(0), FPUx86.MAX_INT64));
};

/**
 * FSAVE()
 *
 * @this {FPUx86}
 */
FPUx86.FSAVE = function()
{
    let cpu = this.cpu;
    let addr = this.saveEnv(cpu.regEA);
    for (let i = 0; i < this.regStack.length; i++) {
        let a = this.getTR(i, true);
        cpu.setLong(addr, a[0]);
        cpu.setLong(addr += 4, a[1]);
        cpu.setShort(addr += 4, a[2]);
        addr += 2;
    }
    this.resetFPU();
};

/**
 * FSCALE()
 *
 * FSCALE interprets the value in ST(1) as an integer and adds this number to the exponent of the number in ST(0).
 *
 * The FSCALE instruction provides a means of quickly performing multiplication or division by powers of two.
 * This operation is often required when scaling array indexes.
 *
 * On the 8087 and 80287, FSCALE assumes that the scale factor in ST(1) is an integer that satisfies the inequality
 * -2^15 <= ST(1) < +2^15.  If ST(1) is not an integer value, the value is chopped to the next smallest integer in
 * magnitude (chopped toward zero).  If the value is out of range or 0 < ST(1) < 1, FSCALE produces an undefined
 * result and doesn't signal an exception.  Typically, the value in ST(0) is unchanged but should not be depended on.
 *
 * On the 80287XL and later coprocessors, there is no limit on the range of the scale factor in ST(1). The value in
 * ST(1) is still chopped toward zero.  If ST(1) is 0, ST(0) is unchanged.
 *
 * @this {FPUx86}
 */
FPUx86.FSCALE = function()
{
    let x = this.getST(0);
    let y = this.getST(1);
    if (x != null && y != null) this.setST(0, x * Math.pow(2, this.truncateValue(y)));
};

/**
 * FSETPM287()
 *
 * @this {FPUx86}
 */
FPUx86.FSETPM287 = function()
{
    if (this.isModel(X86.FPU.MODEL_80287)) {
        this.opUnimplemented();
    }
};

/**
 * FSINCOS387()
 *
 * @this {FPUx86}
 */
FPUx86.FSINCOS387 = function()
{
    if (this.isAtLeastModel(X86.FPU.MODEL_80287XL)) {
        this.opUnimplemented();
    }
};

/**
 * FSQRT()
 *
 * @this {FPUx86}
 */
FPUx86.FSQRT = function()
{
    this.setST(0, this.doSquareRoot(this.getST(0)));
};

/**
 * FSTlr()
 *
 * @this {FPUx86}
 */
FPUx86.FSTlr = function()
{
    if (this.getLR(0)) this.setEAFromLR();
};

/**
 * FSTsr()
 *
 * @this {FPUx86}
 */
FPUx86.FSTsr = function()
{
    if (this.getSR(0)) this.setEAFromSR();
};

/**
 * FSTsti()
 *
 * @this {FPUx86}
 */
FPUx86.FSTsti = function()
{
    this.setST(this.iStack, this.getST(0));
};

/**
 * FSTENV()
 *
 * @this {FPUx86}
 */
FPUx86.FSTENV = function()
{

    this.saveEnv(this.cpu.regEA);
    this.regControl |= X86.FPU.CONTROL.EXC;     // mask all exceptions (but do not set IEM)
};

/**
 * FSTPlr()
 *
 * @this {FPUx86}
 */
FPUx86.FSTPlr = function()
{
    if (this.getLR(0)) {
        this.setEAFromLR();
        this.popValue();
    }
};

/**
 * FSTPsr()
 *
 * @this {FPUx86}
 */
FPUx86.FSTPsr = function()
{
    if (this.getSR(0)) {
        this.setEAFromSR();
        this.popValue();
    }
};

/**
 * FSTPsti()
 *
 * @this {FPUx86}
 */
FPUx86.FSTPsti = function()
{
    if (this.setST(this.iStack, this.getST(0))) this.popValue();
};

/**
 * FSTP8087()
 *
 * NOTE: This is used with encodings (0xD9,0xD8-0xDF and 0xDF,0xD0-0xDF) that were valid for the 8087 and 80287
 * but may no longer be valid as of the 80387.
 *
 * @this {FPUx86}
 */
FPUx86.FSTP8087 = function()
{
    this.opObsolete();
    FPUx86.FSTPsti.call(this);
};

/**
 * FSTPtr()
 *
 * @this {FPUx86}
 */
FPUx86.FSTPtr = function()
{
    if (this.getTR(0)) {
        this.setEAFromTR();
        this.popValue();
    }
};

/**
 * FSTCW()
 *
 * @this {FPUx86}
 */
FPUx86.FSTCW = function()
{

    this.cpu.setShort(this.cpu.regEA, this.regControl);
};

/**
 * FSTSW()
 *
 * @this {FPUx86}
 */
FPUx86.FSTSW = function()
{

    this.cpu.setShort(this.cpu.regEA, this.getStatus());
};

/**
 * FSTSWAX287()
 *
 * @this {FPUx86}
 */
FPUx86.FSTSWAX287 = function()
{
    if (this.isAtLeastModel(X86.FPU.MODEL_80287)) {
        this.cpu.regEAX = (this.cpu.regEAX & ~0xffff) | this.getStatus();
    }
};

/**
 * FSUBlr()
 *
 * @this {FPUx86}
 */
FPUx86.FSUBlr = function()
{
    this.setST(0, this.doSubtract(this.getST(0), this.getLRFromEA()));
};

/**
 * FSUBsr()
 *
 * @this {FPUx86}
 */
FPUx86.FSUBsr = function()
{
    this.setST(0, this.doSubtract(this.getST(0), this.getSRFromEA()));
};

/**
 * FSUBst()
 *
 * Encoding 0xD8,0xE0-0xE7 ("FSUB ST,ST(i)"): ST(0) <- ST(0) - ST(i)
 *
 * @this {FPUx86}
 */
FPUx86.FSUBst = function()
{
    this.setST(0, this.doSubtract(this.getST(0), this.getST(this.iStack)));
};

/**
 * FSUBsti()
 *
 * Encoding 0xDC,0xE8-0xEF ("FSUB ST(i),ST"): ST(i) <- ST(i) - ST(0)
 *
 * @this {FPUx86}
 */
FPUx86.FSUBsti = function()
{
    this.setST(this.iStack, this.doSubtract(this.getST(this.iStack), this.getST(0)));
};

/**
 * FSUBPsti()
 *
 * Encoding 0xDE,0xE8-0xEF ("FSUBP ST(i),ST"): ST(i) <- ST(i) - ST(0), POP
 *
 * @this {FPUx86}
 */
FPUx86.FSUBPsti = function()
{
    if (this.setST(this.iStack, this.doSubtract(this.getST(this.iStack), this.getST(0)))) this.popValue();
};

/**
 * FSUBRlr()
 *
 * @this {FPUx86}
 */
FPUx86.FSUBRlr = function()
{
    this.setST(0, this.doSubtract(this.getLRFromEA(), this.getST(0)));
};

/**
 * FSUBRsr()
 *
 * @this {FPUx86}
 */
FPUx86.FSUBRsr = function()
{
    this.setST(0, this.doSubtract(this.getSRFromEA(), this.getST(0)));
};

/**
 * FSUBRst()
 *
 * Encoding 0xD8,0xE8-0xEF ("FSUBR ST,ST(i)"): ST(0) <- ST(i) - ST(0)
 *
 * @this {FPUx86}
 */
FPUx86.FSUBRst = function()
{
    this.setST(0, this.doSubtract(this.getST(this.iStack), this.getST(0)));
};

/**
 * FSUBRsti()
 *
 * Encoding 0xDC,0xE0-0xE7 ("FSUBR ST(i),ST"): ST(i) <- ST(0) - ST(i)
 *
 * @this {FPUx86}
 */
FPUx86.FSUBRsti = function()
{
    this.setST(this.iStack, this.doSubtract(this.getST(0), this.getST(this.iStack)));
};

/**
 * FSUBRPsti()
 *
 * Encoding 0xDE,0xE0-0xE7 ("FSUBRP ST(i),ST"): ST(i) <- ST(0) - ST(i), POP
 *
 * @this {FPUx86}
 */
FPUx86.FSUBRPsti = function()
{
    if (this.setST(this.iStack, this.doSubtract(this.getST(0), this.getST(this.iStack)))) this.popValue();
};

/**
 * FTST()
 *
 * @this {FPUx86}
 */
FPUx86.FTST = function()
{
    this.doCompare(this.getST(0), 0);
};

/**
 * FXAM()
 *
 * @this {FPUx86}
 */
FPUx86.FXAM = function()
{
    this.regStatus &= ~X86.FPU.STATUS.CC;

    if (this.getSTSign(0)) {
        this.regStatus |= X86.FPU.STATUS.C1;
    }
    if (this.getTag(this.iST) == X86.FPU.TAGS.EMPTY) {
        this.regStatus |= X86.FPU.STATUS.C0 | X86.FPU.STATUS.C3;
    }
    else {
        let v = this.getST(0);
        if (isNaN(v)) {
            this.regStatus |= X86.FPU.STATUS.C0;
        }
        else if (v === 0) {                                 // this equals -0, too (WTF, strict equality?)
            this.regStatus |= X86.FPU.STATUS.C3;
        }
        else if (v === Infinity || v === -Infinity) {       // these are so divergent that even non-strict equality doesn't consider them equal
            this.regStatus |= X86.FPU.STATUS.C0 | X86.FPU.STATUS.C2;
        }
        else {
            this.regStatus |= X86.FPU.STATUS.C2;
        }
    }
};

/**
 * FXCHsti()
 *
 * @this {FPUx86}
 */
FPUx86.FXCHsti = function()
{
    let tmp = this.getST(0);
    this.setST(0, this.getST(this.iStack));
    this.setST(this.iStack, tmp);
};

/**
 * FXCH8087()
 *
 * NOTE: This is used with encodings (0xDD,0xC8-0xCF and 0xDF,0xC8-0xCF) that were valid for the 8087 and 80287
 * but may no longer be valid as of the 80387.
 *
 * @this {FPUx86}
 */
FPUx86.FXCH8087 = function()
{
    this.opObsolete();
    FPUx86.FXCHsti.call(this);
};

/**
 * FXTRACT()
 *
 * FXTRACT splits the value encoded in ST(0) into two separate numbers representing the actual value of the
 * fraction (mantissa) and exponent fields.
 *
 * The FXTRACT instruction is used to decompose the two fields of the temporary real number in ST(0).  The exponent
 * replaces the value in ST(0), then the fraction is pushed onto the stack.  When execution is complete, ST(0)
 * contains the original fraction, expressed as a real number with a true exponent of 0 (0x3FFF in biased form),
 * and ST(1) contains the value of the original operand's true (unbiased) exponent expressed as a real number.
 *
 * If ST(0) is 0, the 8087 and 80287 will leave zeros in both ST(0) and ST(1); both zeros will have the same sign as
 * the original operand.  If ST(0) is +infinity, the invalid operation exception is raised.
 *
 * On the 80287XL and later coprocessors, if ST(0) is 0, the zero-divide exception is reported and ST(1) is set to
 * -infinity.  If ST(0) is +infinity, no exception is reported.
 *
 * The FXTRACT instruction may be thought of as the complement to the FSCALE instruction, which combines a separate
 * fraction and exponent into a single value.
 *
 * ALGORITHM:
 *
 *      IF (ST(0) = 0) THEN
 *          DEC TOP
 *          ST(0) = ST(1)
 *      ELSE
 *          temp = ST(0)
 *          ST(0) = EXPONENT(ST(0))     ; stored as true exponent
 *          DEC TOP
 *          ST(0) = FRACTION(ST(0))
 *      ENDIF
 *
 * @this {FPUx86}
 */
FPUx86.FXTRACT = function()
{
    let v = this.getST(0);
    if (v != null) {
        this.regTmpLR[0] = v;
        this.setST(0, ((this.intTmpLR[1] >> 20) & 0x7ff) - 0x3ff);
        this.intTmpLR[1] = (this.intTmpLR[1] | 0x3ff00000) & ~0x40000000;
        this.pushValue(this.regTmpLR[0]);
    }
};

/**
 * FYL2X()
 *
 * FYL2X (y log base 2 of x) calculates:
 *
 *      ST(1) = ST(1) * log2(ST(0))
 *
 * The operands must satisfy the inequalities 0 < ST(0) < +infinity and -infinity < ST(1) < +infinity.  FYL2X pops
 * the stack and returns the result to the new ST(0).  Both original operands are destroyed.
 *
 * The FYL2X function is designed to optimize the calculation of a log to a base, n, other than two.  In such a case,
 * the following multiplication is required; ie:
 *
 *      logn(x) = logn(2) * log2(x)
 *
 * @this {FPUx86}
 */
FPUx86.FYL2X = function()
{
    if (this.setST(1, this.getST(1) * Math.log(this.getST(0)) / Math.LN2)) this.popValue();
};

/**
 * FYL2XP1()
 *
 * FYL2XP1 (y log base 2 of x plus 1) calculates:
 *
 *      ST(1) = ST(1) * log2(ST(0) + 1)
 *
 * The operands must satisfy the inequalities -(1-sqrt(2)/2) < ST(0) < (1-sqrt(2)/2) and -infinity < ST(1) < +infinity.
 * FYL2XP1 pops the stack and returns the result to the new ST(0).  Both original operands are destroyed.
 *
 * The FYL2XP1 function provides greater accuracy than FYL2X in computing the log of a number that is very close to 1.
 *
 * FYL2XP1 is typically used when computing compound interest, for example, which requires the calculation of a logarithm
 * of 1.0 + n where 0 < n < 0.29.  If 1.0 was added to n, significant digits might be lost.  By using FYL2XP1, the result
 * will be as accurate as n to within three units of temporary real precision.
 *
 * @this {FPUx86}
 */
FPUx86.FYL2XP1 = function()
{
    if (this.setST(1, this.getST(1) * Math.log(this.getST(0) + 1.0) / Math.LN2)) this.popValue();
};

/*
 * Class constants
 *
 * TODO: When loading any of the following 5 constants, the 80287XL and newer coprocessors apply rounding control.
 */

/** @const */
FPUx86.regL2T = Math.log(10) / Math.LN2;        // log2(10) (use Math.log2() if we ever switch to ES6)

/** @const */
FPUx86.regL2E = Math.LOG2E;                     // log2(e)

/** @const */
FPUx86.regPI  = Math.PI;                        // pi

/** @const */
FPUx86.regLG2 = Math.log(2) / Math.LN10;        // log10(2) (use Math.log10() if we ever switch to ES6)

/** @const */
FPUx86.regLN2 = Math.LN2;                       // log(2)

/** @const */
FPUx86.MAX_INT16 = 0x8000;

/** @const */
FPUx86.MAX_INT32 = 0x80000000;

/** @const */
FPUx86.MAX_INT64 = Math.pow(2, 63);


/*
 * FPU operation lookup table (be sure to keep the following table in sync with Debugger.aaaOpFPUDescs).
 *
 * The second lookup value corresponds to bits in the ModRegRM byte that follows the ESC byte (0xD8-0xDF).
 *
 * Here's a little cheat-sheet for how the 2nd lookup values relate to ModRegRM values; see opFPU() for details.
 *
 *      Lookup  ModRegRM value(s)
 *      ------  -------------------------------
 *      0x00:   0x00-0x07, 0x40-0x47, 0x80-0x87
 *      0x01:   0x08-0x0F, 0x48-0x4F, 0x88-0x8F
 *      0x02:   0x10-0x17, 0x50-0x57, 0x90-0x97
 *      0x03:   0x18-0x1F, 0x58-0x5F, 0x98-0x9F
 *      0x04:   0x20-0x27, 0x60-0x67, 0xA0-0xA7
 *      0x05:   0x28-0x2F, 0x68-0x6F, 0xA8-0xAF
 *      0x06:   0x30-0x37, 0x70-0x77, 0xB0-0xB7
 *      0x07:   0x38-0x3F, 0x78-0x7F, 0xB8-0xBF
 *      0x30:   0xC0-0xC7
 *      0x31:   0xC8-0xCF
 *      0x32:   0xD0-0xD7
 *      0x33:   0xD8-0xDF
 *      0x34:   0xE0-0xE7
 *      0x35:   0xE8-0xEF
 *      0x36:   0xF0-0xF7
 *      0x37:   0xF8-0xFF
 *
 * ESC bytes 0xD9 and 0xDB use the RM field to further describe the operation when the ModRegRM value >= 0xE0.
 * In those cases, we shift the Reg value into the high nibble and the RM value into the low nibble, resulting in
 * the following lookup values (which look a lot like hex-encoded octal):
 *
 *      0x40:   0xE0
 *      0x41:   0xE1
 *      ...     ...
 *      0x46:   0xE6
 *      0x47:   0xE7
 *
 *      0x50:   0xE8
 *      0x51:   0xE9
 *      ...     ...
 *      0x56:   0xEE
 *      0x57:   0xEF
 *
 *      0x60:   0xF0
 *      0x61:   0xF1
 *      ...     ...
 *      0x66:   0xF6
 *      0x67:   0xF7
 *
 *      0x70:   0xF8
 *      0x71:   0xF9
 *      ...     ...
 *      0x76:   0xFE
 *      0x77:   0xFF
 */
FPUx86.aaOps = {
    0xD8: {
        0x00: FPUx86.FADDsr,    0x01: FPUx86.FMULsr,    0x02: FPUx86.FCOMsr,    0x03: FPUx86.FCOMPsr,
        0x04: FPUx86.FSUBsr,    0x05: FPUx86.FSUBRsr,   0x06: FPUx86.FDIVsr,    0x07: FPUx86.FDIVsr,
        0x30: FPUx86.FADDst,    0x31: FPUx86.FMULst,    0x32: FPUx86.FCOMst,    0x33: FPUx86.FCOMPst,
        0x34: FPUx86.FSUBst,    0x35: FPUx86.FSUBRst,   0x36: FPUx86.FDIVst,    0x37: FPUx86.FDIVRst
    },
    0xD9: {
        0x00: FPUx86.FLDsr,                             0x02: FPUx86.FSTsr,     0x03: FPUx86.FSTPsr,
        0x04: FPUx86.FLDENV,    0x05: FPUx86.FLDCW,     0x06: FPUx86.FSTENV,    0x07: FPUx86.FSTCW,
        0x30: FPUx86.FLDsti,    0x31: FPUx86.FXCHsti,   0x32: FPUx86.FNOP,      0x33: FPUx86.FSTP8087,
        0x40: FPUx86.FCHS,      0x41: FPUx86.FABS,
        0x44: FPUx86.FTST,      0x45: FPUx86.FXAM,
        0x50: FPUx86.FLD1,      0x51: FPUx86.FLDL2T,    0x52: FPUx86.FLDL2E,    0x53: FPUx86.FLDPI,
        0x54: FPUx86.FLDLG2,    0x55: FPUx86.FLDLN2,    0x56: FPUx86.FLDZ,
        0x60: FPUx86.F2XM1,     0x61: FPUx86.FYL2X,     0x62: FPUx86.FPTAN,     0x63: FPUx86.FPATAN,
        0x64: FPUx86.FXTRACT,                           0x66: FPUx86.FDECSTP,   0x67: FPUx86.FINCSTP,
        0x70: FPUx86.FPREM,     0x71: FPUx86.FYL2XP1,   0x72: FPUx86.FSQRT,
        0x74: FPUx86.FRNDINT,   0x75: FPUx86.FSCALE
    },
    0xDA: {
        0x00: FPUx86.FIADD32,   0x01: FPUx86.FIMUL32,   0x02: FPUx86.FICOM32,   0x03: FPUx86.FICOMP32,
        0x04: FPUx86.FISUB32,   0x05: FPUx86.FISUBR32,  0x06: FPUx86.FIDIV32,   0x07: FPUx86.FIDIVR32
    },
    0xDB: {
        0x00: FPUx86.FILD32,    0x02: FPUx86.FIST32,    0x03: FPUx86.FISTP32,
                                0x05: FPUx86.FLDtr,                             0x07: FPUx86.FSTPtr,
        0x40: FPUx86.FENI8087,  0x41: FPUx86.FDISI8087, 0x42: FPUx86.FCLEX,     0x43: FPUx86.FINIT,
        0x44: FPUx86.FSETPM287,
        0x73: FPUx86.FSINCOS387
    },
    0xDC: {
        0x00: FPUx86.FADDlr,    0x01: FPUx86.FMULlr,    0x02: FPUx86.FCOMlr,    0x03: FPUx86.FCOMPlr,
        0x04: FPUx86.FSUBlr,    0x05: FPUx86.FSUBRlr,   0x06: FPUx86.FDIVlr,    0x07: FPUx86.FDIVRlr,
        0x30: FPUx86.FADDsti,   0x31: FPUx86.FMULsti,   0x32: FPUx86.FCOM8087,  0x33: FPUx86.FCOMP8087,
        /*
         * Intel's original 8087 datasheet had these forms of SUB and SUBR (and DIV and DIVR) swapped.
         */
        0x34: FPUx86.FSUBRsti,  0x35: FPUx86.FSUBsti,   0x36: FPUx86.FDIVRsti,  0x37: FPUx86.FDIVsti
    },
    0xDD: {
        0x00: FPUx86.FLDlr,                             0x02: FPUx86.FSTlr,     0x03: FPUx86.FSTPlr,
        0x04: FPUx86.FRSTOR,                            0x06: FPUx86.FSAVE,     0x07: FPUx86.FSTSW,
        0x30: FPUx86.FFREEsti,  0x31: FPUx86.FXCH8087,  0x32: FPUx86.FSTsti,    0x33: FPUx86.FSTPsti
    },
    0xDE: {
        0x00: FPUx86.FIADD16,   0x01: FPUx86.FIMUL16,   0x02: FPUx86.FICOM16,   0x03: FPUx86.FICOMP16,
        0x04: FPUx86.FISUB16,   0x05: FPUx86.FISUBR16,  0x06: FPUx86.FIDIV16,   0x07: FPUx86.FIDIVR16,
        0x30: FPUx86.FADDPsti,  0x31: FPUx86.FMULPsti,  0x32: FPUx86.FCOMP8087, 0x33: FPUx86.FCOMPP,
        /*
         * Intel's original 8087 datasheet had these forms of SUBP and SUBRP (and DIVP and DIVRP) swapped.
         */
        0x34: FPUx86.FSUBRPsti, 0x35: FPUx86.FSUBPsti,  0x36: FPUx86.FDIVRPsti, 0x37: FPUx86.FDIVPsti
    },
    0xDF: {
        0x00: FPUx86.FILD16,                            0x02: FPUx86.FIST16,    0x03: FPUx86.FISTP16,
        0x04: FPUx86.FBLDpd,    0x05: FPUx86.FILD64,    0x06: FPUx86.FBSTPpd,   0x07: FPUx86.FISTP64,
        0x30: FPUx86.FFREEP8087,0x31: FPUx86.FXCH8087,  0x32: FPUx86.FSTP8087,  0x33: FPUx86.FSTP8087,
        0x34: FPUx86.FSTSWAX287
    }
};

/*
 * An array of FPUx86 functions documented as preserving the "exception" registers.
 */
FPUx86.afnPreserveExceptions = [
    FPUx86.FCLEX,   FPUx86.FINIT,   FPUx86.FLDCW,   FPUx86.FLDENV,  FPUx86.FRSTOR,
    FPUx86.FSAVE,   FPUx86.FSTCW,   FPUx86.FSTENV,  FPUx86.FSTSW,   FPUx86.FSTSWAX287
];





/**
 * @copyright https://www.pcjs.org/machines/pcx86/lib/x86func.js (C) 2012-2021 Jeff Parsons
 */


/**
 * fnADCb(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnADCb = function(dst, src)
{
    let b = (dst + src + this.getCarry())|0;
    this.setArithResult(dst, src, b, X86.RESULT.BYTE | X86.RESULT.ALL);
    this.nStepCycles -= (this.regEAWrite === X86.ADDR_INVALID? (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesArithRR : this.cycleCounts.nOpCyclesArithRM) : this.cycleCounts.nOpCyclesArithMR);
    return b & 0xff;
};

/**
 * fnADCw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnADCw = function(dst, src)
{
    let w = (dst + src + this.getCarry())|0;
    this.setArithResult(dst, src, w, this.typeData | X86.RESULT.ALL);
    this.nStepCycles -= (this.regEAWrite === X86.ADDR_INVALID? (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesArithRR : this.cycleCounts.nOpCyclesArithRM) : this.cycleCounts.nOpCyclesArithMR);
    return w & this.maskData;
};

/**
 * fnADDb(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnADDb = function(dst, src)
{
    let b = (dst + src)|0;
    this.setArithResult(dst, src, b, X86.RESULT.BYTE | X86.RESULT.ALL);
    this.nStepCycles -= (this.regEAWrite === X86.ADDR_INVALID? (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesArithRR : this.cycleCounts.nOpCyclesArithRM) : this.cycleCounts.nOpCyclesArithMR);
    return b & 0xff;
};

/**
 * fnADDw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnADDw = function(dst, src)
{
    let w = (dst + src)|0;
    this.setArithResult(dst, src, w, this.typeData | X86.RESULT.ALL);
    this.nStepCycles -= (this.regEAWrite === X86.ADDR_INVALID? (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesArithRR : this.cycleCounts.nOpCyclesArithRM) : this.cycleCounts.nOpCyclesArithMR);
    return w & this.maskData;
};

/**
 * fnANDb(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnANDb = function(dst, src)
{
    let b = dst & src;
    this.setLogicResult(b, X86.RESULT.BYTE);
    this.nStepCycles -= (this.regEAWrite === X86.ADDR_INVALID? (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesArithRR : this.cycleCounts.nOpCyclesArithRM) : this.cycleCounts.nOpCyclesArithMR);
    return b;
};

/**
 * fnANDw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnANDw = function(dst, src)
{
    this.nStepCycles -= (this.regEAWrite === X86.ADDR_INVALID? (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesArithRR : this.cycleCounts.nOpCyclesArithRM) : this.cycleCounts.nOpCyclesArithMR);
    return this.setLogicResult(dst & src, this.typeData) & this.maskData;
};

/**
 * fnARPL(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnARPL = function(dst, src)
{
    this.nStepCycles -= (10 + (this.regEA === X86.ADDR_INVALID? 0 : 1));
    if ((dst & X86.SEL.RPL) < (src & X86.SEL.RPL)) {
        dst = (dst & ~X86.SEL.RPL) | (src & X86.SEL.RPL);
        this.setZF();
        return dst;
    }
    this.clearZF();
    return dst;
};

/**
 * fnBOUND(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnBOUND = function(dst, src)
{
    if (this.regEA === X86.ADDR_INVALID) {
        /*
         * Generate UD_FAULT (INT 0x06: Invalid Opcode) if src is not a memory operand.
         */
        X86.opInvalid.call(this);
        return dst;
    }
    /*
     * Note that BOUND performs signed comparisons, so we must transform all arguments into signed values.
     */
    let wIndex = dst;
    let wLower = this.getWord(this.regEA);
    let wUpper = this.getWord(this.regEA + this.sizeData);
    if (this.sizeData == 2) {
        wIndex = (dst << 16) >> 16;
        wLower = (wLower << 16) >> 16;
        wUpper = (wUpper << 16) >> 16;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesBound;
    if (wIndex < wLower || wIndex > wUpper) {
        /*
         * The INT 0x05 handler must be called with CS:IP pointing to the BOUND instruction.
         *
         * TODO: Determine the cycle cost when a BOUND exception is triggered, over and above nCyclesBound,
         * and then call X86.helpFault(X86.EXCEPTION.BR_FAULT, null, nCycles).
         */
        X86.helpFault.call(this, X86.EXCEPTION.BR_FAULT);
    }
    this.opFlags |= X86.OPFLAG.NOWRITE;
    return dst;
};

/**
 * fnBSF(dst, src)
 *
 * Scan src starting at bit 0.  If a set bit is found, the bit index is stored in dst and ZF is cleared;
 * otherwise, ZF is set and dst is unchanged.
 *
 * NOTES: Early versions of the 80386 manuals misstated how ZF was set/cleared.  Also, Intel insists that
 * dst is undefined whenever ZF is set, but in fact, the 80386 leaves dst unchanged when that happens;
 * unfortunately, some early 80486s would always modify dst, so it is unsafe to rely on dst when ZF is set.
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnBSF = function(dst, src)
{
    let n = 0;
    if (!src) {
        this.setZF();
    } else {
        this.clearZF();
        let bit = 0x1;
        while (bit & this.maskData) {
            if (src & bit) {
                dst = n;
                break;
            }
            bit <<= 1;
            n++;                // TODO: Determine if n should be incremented before the bailout for an accurate cycle count
        }
    }
    this.nStepCycles -= 11 + n * 3;
    return dst;
};

/**
 * fnBSR(dst, src)
 *
 * Scan src starting from the highest bit.  If a set bit is found, the bit index is stored in dst and ZF is
 * cleared; otherwise, ZF is set and dst is unchanged.
 *
 * NOTES: Early versions of the 80386 manuals misstated how ZF was set/cleared.  Also, Intel insists that
 * dst is undefined whenever ZF is set, but in fact, the 80386 leaves dst unchanged when that happens;
 * unfortunately, some early 80486s would always modify dst, so it is unsafe to rely on dst when ZF is set.
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnBSR = function(dst, src)
{
    let n = 0;
    if (!src) {
        this.setZF();
    } else {
        this.clearZF();
        let i = (this.sizeData == 2? 15 : 31), bit = 1 << i;
        while (bit) {
            if (src & bit) {
                dst = i;
                break;
            }
            bit >>>= 1;
            n++; i--;           // TODO: Determine if n should be incremented before the bailout for an accurate cycle count
        }

    }
    this.nStepCycles -= 11 + n * 3;
    return dst;
};

/**
 * fnBT(dst, src)
 *
 * In this form of BT, src is an immediate operand (OR dst is register operand); immediate operands
 * are supposed to be masked with either 0xf or 0x1f for 16-bit or 32-bit operands, respectively.
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnBT = function(dst, src)
{
    let bit = 1 << (src & (this.sizeData == 2? 0xf : 0x1f));
    if (dst & bit) this.setCF(); else this.clearCF();
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? 3 : 6);
    this.opFlags |= X86.OPFLAG.NOWRITE;
    return dst;
};

/**
 * fnBTC(dst, src)
 *
 * In this form of BTC, src is an immediate operand (OR dst is register operand); immediate operands
 * are supposed to be masked with either 0xf or 0x1f for 16-bit or 32-bit operands, respectively.
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnBTC = function(dst, src)
{
    let bit = 1 << (src & (this.sizeData == 2? 0xf : 0x1f));
    if (dst & bit) this.setCF(); else this.clearCF();
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? 6 : 8);
    return dst ^ bit;
};

/**
 * fnBTR(dst, src)
 *
 * In this form of BTR, src is an immediate operand (OR dst is register operand); immediate operands
 * are supposed to be masked with either 0xf or 0x1f for 16-bit or 32-bit operands, respectively.
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnBTR = function(dst, src)
{
    let bit = 1 << (src & (this.sizeData == 2? 0xf : 0x1f));
    if (dst & bit) this.setCF(); else this.clearCF();
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? 6 : 8);
    return dst & ~bit;
};

/**
 * fnBTS(dst, src)
 *
 * In this form of BTS, src is an immediate operand (OR dst is register operand); immediate operands
 * are supposed to be masked with either 0xf or 0x1f for 16-bit or 32-bit operands, respectively.
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnBTS = function(dst, src)
{
    let bit = 1 << (src & (this.sizeData == 2? 0xf : 0x1f));
    if (dst & bit) this.setCF(); else this.clearCF();
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? 6 : 8);
    return dst | bit;
};

/**
 * fnBTMem(dst, src)
 *
 * In this form of BT, src is a register operand, which is NOT truncated if dst is a memory operand;
 * however, if dst is also a register operand, then we defer to the simpler function, fnBT().
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnBTMem = function(dst, src)
{
    if (this.regEA === X86.ADDR_INVALID) {
        return X86.fnBT.call(this, dst, src);
    }
    /*
     * TODO: Consider a worker function that performs the following block of code for: BT, BTC, BTR, and BTS.
     * It's somewhat inconvenient, because it needs to provide two results: an updated src AND an updated dst.
     *
     * src is usually positive BUT can also be negative (as the IA32 spec says: "The offset operand then selects
     * a bit position within the range −231 to 231 − 1 for a register offset and 0 to 31 for an immediate offset.")
     */
    let max = this.sizeData << 3;
    if (src >= max || src < -max) {
        /*
         * Now we need to divide src by 16 or 32, according to the OPERAND size, which means shifting it right
         * by either 4 or 5 bits.  That gives us a short or long INDEX, which we then multiply by the OPERAND size
         * to obtain to the corresponding short or long OFFSET that we must add to the original EA offset.
         */
        let i = src >> (this.sizeData == 2? 4 : 5);
        dst = this.getEAWord(this.segEA, this.offEA + i * this.sizeData);
    }
    /*
     * Now we convert src from a bit index to a bit mask.
     */
    src = 1 << (src & (this.sizeData == 2? 0xf : 0x1f));
    if (dst & src) this.setCF(); else this.clearCF();

    this.nStepCycles -= 6;
    this.opFlags |= X86.OPFLAG.NOWRITE;
    return dst;
};

/**
 * fnBTCMem(dst, src)
 *
 * In this form of BTC, src is a register operand, which is NOT truncated if dst is a memory operand;
 * however, if dst is also a register operand, then we defer to the simpler function, fnBTC().
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnBTCMem = function(dst, src)
{
    if (this.regEA === X86.ADDR_INVALID) {
        return X86.fnBTC.call(this, dst, src);
    }
    /*
     * src is usually positive BUT can also be negative (as the IA32 spec says: "The offset operand then selects
     * a bit position within the range −231 to 231 − 1 for a register offset and 0 to 31 for an immediate offset.")
     */
    let max = this.sizeData << 3;
    if (src >= max || src < -max) {
        /*
         * Now we need to divide src by 16 or 32, according to the OPERAND size, which means shifting it right
         * by either 4 or 5 bits.  That gives us a short or long INDEX, which we then multiply by the OPERAND size
         * to obtain to the corresponding short or long OFFSET that we must add to the original EA offset.
         */
        let i = src >> (this.sizeData == 2? 4 : 5);
        dst = this.getEAWord(this.segEA, this.offEA + i * this.sizeData);
    }
    /*
     * Now we convert src from a bit index to a bit mask.
     */
    src = 1 << (src & (this.sizeData == 2? 0xf : 0x1f));
    if (dst & src) this.setCF(); else this.clearCF();

    this.nStepCycles -= 8;
    return dst ^ src;
};

/**
 * fnBTRMem(dst, src)
 *
 * In this form of BTR, src is a register operand, which is NOT truncated if dst is a memory operand;
 * however, if dst is also a register operand, then we defer to the simpler function, fnBTR().
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnBTRMem = function(dst, src)
{
    if (this.regEA === X86.ADDR_INVALID) {
        return X86.fnBTR.call(this, dst, src);
    }
    /*
     * src is usually positive BUT can also be negative (as the IA32 spec says: "The offset operand then selects
     * a bit position within the range −231 to 231 − 1 for a register offset and 0 to 31 for an immediate offset.")
     */
    let max = this.sizeData << 3;
    if (src >= max || src < -max) {
        /*
         * Now we need to divide src by 16 or 32, according to the OPERAND size, which means shifting it right
         * by either 4 or 5 bits.  That gives us a short or long INDEX, which we then multiply by the OPERAND size
         * to obtain to the corresponding short or long OFFSET that we must add to the original EA offset.
         */
        let i = src >> (this.sizeData == 2? 4 : 5);
        dst = this.getEAWord(this.segEA, this.offEA + i * this.sizeData);
    }
    /*
     * Now we convert src from a bit index to a bit mask.
     */
    src = 1 << (src & (this.sizeData == 2? 0xf : 0x1f));
    if (dst & src) this.setCF(); else this.clearCF();

    this.nStepCycles -= 8;
    return dst & ~src;
};

/**
 * fnBTSMem(dst, src)
 *
 * In this form of BTS, src is a register operand, which is NOT truncated if dst is a memory operand;
 * however, if dst is also a register operand, then we defer to the simpler function, fnBTS().
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnBTSMem = function(dst, src)
{
    if (this.regEA === X86.ADDR_INVALID) {
        return X86.fnBTS.call(this, dst, src);
    }
    /*
     * src is usually positive BUT can also be negative (as the IA32 spec says: "The offset operand then selects
     * a bit position within the range −231 to 231 − 1 for a register offset and 0 to 31 for an immediate offset.")
     */
    let max = this.sizeData << 3;
    if (src >= max || src < -max) {
        /*
         * Now we need to divide src by 16 or 32, according to the OPERAND size, which means shifting it right
         * by either 4 or 5 bits.  That gives us a short or long INDEX, which we then multiply by the OPERAND size
         * to obtain to the corresponding short or long OFFSET that we must add to the original EA offset.
         */
        let i = src >> (this.sizeData == 2? 4 : 5);
        dst = this.getEAWord(this.segEA, this.offEA + i * this.sizeData);
    }
    /*
     * Now we convert src from a bit index to a bit mask.
     */
    src = 1 << (src & (this.sizeData == 2? 0xf : 0x1f));
    if (dst & src) this.setCF(); else this.clearCF();

    this.nStepCycles -= 8;
    return dst | src;
};

/**
 * fnCALLw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null)
 * @return {number}
 */
X86.fnCALLw = function(dst, src)
{
    this.pushWord(this.getIP());
    this.setIP(dst);
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesCallWR : this.cycleCounts.nOpCyclesCallWM);
    this.opFlags |= X86.OPFLAG.NOWRITE;
    return dst;
};

/**
 * fnCALLFdw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null)
 * @return {number}
 */
X86.fnCALLFdw = function(dst, src)
{
    if (this.regEA === X86.ADDR_INVALID) {
        return X86.fnGRPUndefined.call(this, dst, src);
    }
    /*
     * Originally, we would snapshot regLSP into opLSP because helpCALLF() could trigger a segment fault,
     * but additionally, the stack segment could trigger either a segment fault or a page fault; indeed,
     * any operation that performs multiple stack modifications must take this precaution and snapshot regLSP.
     */
    this.opLSP = this.regLSP;

    X86.helpCALLF.call(this, dst, this.getShort(this.regEA + this.sizeData));
    this.nStepCycles -= this.cycleCounts.nOpCyclesCallDM;
    this.opFlags |= X86.OPFLAG.NOWRITE;

    this.opLSP = X86.ADDR_INVALID;
    return dst;
};

/**
 * fnCMPb(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number} dst unchanged
 */
X86.fnCMPb = function(dst, src)
{
    let b = (dst - src)|0;
    this.setArithResult(dst, src, b, X86.RESULT.BYTE | X86.RESULT.ALL, true);
    this.nStepCycles -= (this.regEAWrite === X86.ADDR_INVALID? (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesArithRR : this.cycleCounts.nOpCyclesCompareRM) : this.cycleCounts.nOpCyclesArithRM);
    this.opFlags |= X86.OPFLAG.NOWRITE;
    return dst;
};

/**
 * fnCMPw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number} dst unchanged
 */
X86.fnCMPw = function(dst, src)
{
    let w = (dst - src)|0;
    this.setArithResult(dst, src, w, this.typeData | X86.RESULT.ALL, true);
    this.nStepCycles -= (this.regEAWrite === X86.ADDR_INVALID? (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesArithRR : this.cycleCounts.nOpCyclesCompareRM) : this.cycleCounts.nOpCyclesArithRM);
    this.opFlags |= X86.OPFLAG.NOWRITE;
    return dst;
};

/**
 * fnDECb(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null)
 * @return {number}
 */
X86.fnDECb = function(dst, src)
{
    let b = (dst - 1)|0;
    this.setArithResult(dst, 1, b, X86.RESULT.BYTE | X86.RESULT.NOTCF, true);
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesIncR : this.cycleCounts.nOpCyclesIncM);
    return b & 0xff;
};

/**
 * fnDECw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null)
 * @return {number}
 */
X86.fnDECw = function(dst, src)
{
    let w = (dst - 1)|0;
    this.setArithResult(dst, 1, w, this.typeData | X86.RESULT.NOTCF, true);
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesIncR : this.cycleCounts.nOpCyclesIncM);
    return w & this.maskData;
};

/**
 * fnDIVb(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst (the divisor)
 * @param {number} src (null; AX is the implied src)
 * @return {number} (we return dst unchanged, since it's actually AX that's modified)
 */
X86.fnDIVb = function(dst, src)
{
    /*
     * Detect zero divisor
     */
    if (!dst) {
        X86.helpDIVOverflow.call(this);
        return dst;
    }

    /*
     * Detect too-small divisor (quotient overflow)
     */
    let result = ((src = this.regEAX & 0xffff) / dst);
    if (result > 0xff) {
        X86.helpDIVOverflow.call(this);
        return dst;
    }

    this.regMDLo = (result & 0xff) | (((src % dst) & 0xff) << 8);
    this.fMDSet = true;

    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesDivBR : this.cycleCounts.nOpCyclesDivBM);
    this.opFlags |= X86.OPFLAG.NOWRITE;
    return dst;
};

/**
 * fnDIVw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst (the divisor)
 * @param {number} src (null; DX:AX or EDX:EAX is the implied src)
 * @return {number} (we return dst unchanged, since it's actually DX:AX that's modified)
 */
X86.fnDIVw = function(dst, src)
{
    if (this.sizeData == 2) {
        /*
         * Detect zero divisor
         */
        if (!dst) {
            X86.helpDIVOverflow.call(this);
            return dst;
        }
        /*
         * Detect too-small divisor (quotient overflow)
         *
         * WARNING: We CANNOT simply do "src = (this.regEDX << 16) | this.regEAX", because if bit 15 of DX
         * is set, JavaScript will create a negative 32-bit number.  So we instead use non-bitwise operators
         * to force JavaScript to create a floating-point value that won't suffer from 32-bit-math side-effects.
         */
        src = (this.regEDX & 0xffff) * 0x10000 + (this.regEAX & 0xffff);
        let result = (src / dst);
        if (result >= 0x10000) {
            X86.helpDIVOverflow.call(this);
            return dst;
        }
        this.regMDLo = (result & 0xffff);
        this.regMDHi = (src % dst) & 0xffff;
    }
    else {
        if (!X86.helpDIV32.call(this, this.regEAX, this.regEDX, dst)) {
            X86.helpDIVOverflow.call(this);
            return dst;
        }
        this.regMDLo |= 0;
        this.regMDHi |= 0;
    }

    this.fMDSet = true;

    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesDivWR : this.cycleCounts.nOpCyclesDivWM);
    this.opFlags |= X86.OPFLAG.NOWRITE;
    return dst;
};

/**
 * fnESC(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number} dst unchanged
 */
X86.fnESC = function(dst, src)
{
    if (this.fpuActive) {
        this.fpuActive.opFPU(this.bOpcode, this.bModRM, dst, src);
    }
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? 2 : 8);
    return dst;
};

/**
 * fnGRPFault(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnGRPFault = function(dst, src)
{
    /*
     * This should NEVER be called on 8086/8088 CPUs, and yet we preset some of the handlers in aOpGrpPOPw,
     * aOpGrp4b, and aOpGrp4w to call it.  initProcessor() DOES patch aOpGrp4b[0x07] and aOpGrp4w[0x07] to
     * fnGRPInvalid, but that's it.
     *
     * However, given the infrequency of this call, it's simpler to continue presetting all the handlers in
     * aOpGrpPOPw to their post-8086 default, and deal with the appropriate 8086 behavior here (which for now,
     * is to call fnGRPUndefined instead).
     */
    if (this.model < X86.MODEL_80186) {
        return X86.fnGRPUndefined.call(this, dst, src);
    }
    X86.helpFault.call(this, X86.EXCEPTION.GP_FAULT, 0);
    return dst;
};

/**
 * fnGRPInvalid(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnGRPInvalid = function(dst, src)
{
    X86.opInvalid.call(this);
    return dst;
};

/**
 * fnGRPUndefined(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnGRPUndefined = function(dst, src)
{
    X86.opUndefined.call(this);
    return dst;
};

/**
 * fnIDIVb(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst (the divisor)
 * @param {number} src (null; AX is the implied src)
 * @return {number} (we return dst unchanged, since it's actually AX that's modified)
 */
X86.fnIDIVb = function(dst, src)
{
    /*
     * Detect zero divisor
     */
    if (!dst) {
        X86.helpDIVOverflow.call(this);
        return dst;
    }

    /*
     * Detect too-small divisor (quotient overflow)
     */
    let div = ((dst << 24) >> 24);
    let result = ((src = (this.regEAX << 16) >> 16) / div)|0;

    /*
     * Note the following difference, from "AP-186: Introduction to the 80186 Microprocessor, March 1983":
     *
     *      "The 8086 will cause a divide error whenever the absolute value of the quotient is greater then 7FFFH
     *      (for word operations) or if the absolute value of the quotient is greater than 7FH (for byte operations).
     *      The 80186 has expanded the range of negative numbers allowed as a quotient by 1 to include 8000H and 80H.
     *      These numbers represent the most negative numbers representable using 2's complement arithmetic (equaling
     *      -32768 and -128 in decimal, respectively)."
     */
    if (result != ((result << 24) >> 24) || this.model <= X86.MODEL_8088 && result == -128) {
        X86.helpDIVOverflow.call(this);
        return dst;
    }

    this.regMDLo = (result & 0xff) | (((src % div) & 0xff) << 8);
    this.fMDSet = true;

    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesIDivBR : this.cycleCounts.nOpCyclesIDivBM);
    this.opFlags |= X86.OPFLAG.NOWRITE;
    return dst;
};

/**
 * fnIDIVw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst (the divisor)
 * @param {number} src (null; DX:AX or EDX:EAX is the implied src)
 * @return {number} (we return dst unchanged, since it's actually DX:AX that's modified)
 */
X86.fnIDIVw = function(dst, src)
{
    if (this.sizeData == 2) {
        /*
         * Detect zero divisor
         */
        if (!dst) {
            X86.helpDIVOverflow.call(this);
            return dst;
        }

        /*
         * Detect too-small divisor (quotient overflow)
         */
        let div = ((dst << 16) >> 16);
        let result = ((src = (this.regEDX << 16) | (this.regEAX & 0xffff)) / div)|0;

        /*
         * Note the following difference, from "AP-186: Introduction to the 80186 Microprocessor, March 1983":
         *
         *      "The 8086 will cause a divide error whenever the absolute value of the quotient is greater then 7FFFH
         *      (for word operations) or if the absolute value of the quotient is greater than 7FH (for byte operations).
         *      The 80186 has expanded the range of negative numbers allowed as a quotient by 1 to include 8000H and 80H.
         *      These numbers represent the most negative numbers representable using 2's complement arithmetic (equaling
         *      -32768 and -128 in decimal, respectively)."
         */
        if (result != ((result << 16) >> 16) || this.model <= X86.MODEL_8088 && result == -32768) {
            X86.helpDIVOverflow.call(this);
            return dst;
        }

        this.regMDLo = (result & 0xffff);
        this.regMDHi = (src % div) & 0xffff;
    }
    else {
        if (!X86.helpIDIV32.call(this, this.regEAX, this.regEDX, dst)) {
            X86.helpDIVOverflow.call(this);
            return dst;
        }
        this.regMDLo |= 0;
        this.regMDHi |= 0;
    }

    this.fMDSet = true;

    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesIDivWR : this.cycleCounts.nOpCyclesIDivWM);
    this.opFlags |= X86.OPFLAG.NOWRITE;
    return dst;
};

/**
 * fnIMUL8(dst, src)
 *
 * 80286_and_80287_Programmers_Reference_Manual_1987.pdf, p.B-44 (p.254) notes that:
 *
 *      "The low 16 bits of the product of a 16-bit signed multiply are the same as those of an
 *      unsigned multiply. The three operand IMUL instruction can be used for unsigned operands as well."
 *
 * However, we still sign-extend the operands before multiplying, making it easier to range-check the result.
 *
 * (80186/80188 and up)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnIMUL8 = function(dst, src)
{
    /*
     * NOTE: getIPDisp() already sign-extends the dst parameter, so fnIMULrw() needlessly sign-extends it again;
     * a small price to pay for a common function.
     */
    let result = X86.fnIMULrw.call(this, this.getIPDisp(), src);

    /*
     * NOTE: The above function already accounted for the 80386 cycle count, so we are simply accounting for the
     * increased time on an 80286; the 80186/80188 have even larger values, but we'll worry about that another day.
     */
    if (this.model < X86.MODEL_80386) this.nStepCycles -= 12;
    return result;
};

/**
 * fnIMULn(dst, src)
 *
 * 80286_and_80287_Programmers_Reference_Manual_1987.pdf, p.B-44 (p.254) notes that:
 *
 *      "The low 16 bits of the product of a 16-bit signed multiply are the same as those of an
 *      unsigned multiply. The three operand IMUL instruction can be used for unsigned operands as well."
 *
 * However, we still sign-extend the operands before multiplying, making it easier to range-check the result.
 *
 * (80186/80188 and up)
 *
 * @this {CPUx86}
 * @param {number} dst (not used)
 * @param {number} src
 * @return {number}
 */
X86.fnIMULn = function(dst, src)
{
    let result;
    dst = this.getIPWord();

    if (this.sizeData == 2) {
        result = X86.fnIMULrw.call(this, dst, src);
    } else {
        result = X86.fnIMULrd.call(this, dst, src);
    }

    /*
     * NOTE: The above functions already accounted for 80386 cycle counts, so we are simply accounting for the
     * increased time on an 80286; the 80186/80188 have even larger values, but we'll worry about that another day.
     */
    if (this.model < X86.MODEL_80386) this.nStepCycles -= 12;
    return result;
};

/**
 * fnIMUL32(dst, src)
 *
 * This sets regMDHi:regMDLo to the 64-bit result of dst * src, both of which are treated as signed.
 *
 * @this {CPUx86}
 * @param {number} dst (any 32-bit number, treated as signed)
 * @param {number} src (any 32-bit number, treated as signed)
 */
X86.fnIMUL32 = function(dst, src)
{
    let fNeg = false;
    if (src < 0) {
        src = -src|0;
        fNeg = !fNeg;
    }
    if (dst < 0) {
        dst = -dst|0;
        fNeg = !fNeg;
    }
    X86.fnMUL32.call(this, dst, src);
    if (fNeg) {
        this.regMDLo = (~this.regMDLo + 1)|0;
        this.regMDHi = (~this.regMDHi + (this.regMDLo? 0 : 1))|0;
    }
};

/**
 * fnIMULb(dst, src)
 *
 * This 16-bit multiplication must indicate when the upper 8 bits are simply a sign-extension of the
 * lower 8 bits (carry clear) and when the upper 8 bits contain significant bits (carry set).  The latter
 * will occur whenever a positive result is > 127 (0x007f) and whenever a negative result is < -128
 * (0xff80).
 *
 * Example 1: 16 * 4 = 64 (0x0040): carry is clear
 * Example 2: 16 * 8 = 128 (0x0080): carry is set (the sign bit no longer fits in the lower 8 bits)
 * Example 3: 16 * -8 (0xf8) = -128 (0xff80): carry is clear (the sign bit *still* fits in the lower 8 bits)
 * Example 4: 16 * -16 (0xf0) = -256 (0xff00): carry is set (the sign bit no longer fits in the lower 8 bits)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null; AL is the implied src)
 * @return {number} (we return dst unchanged, since it's actually AX that's modified)
 */
X86.fnIMULb = function(dst, src)
{
    let result = (((this.regEAX << 24) >> 24) * ((dst << 24) >> 24))|0;
    this.regMDLo = result & 0xffff;
    if (result > 127 || result < -128) {
        this.setCF(); this.setOF();
    } else {
        this.clearCF(); this.clearOF();
    }
    if (this.model <= X86.MODEL_8088) {
        this.clearZF();         // differentiate ourselves from a NEC V20
    }
    this.fMDSet = true;
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesIMulBR : this.cycleCounts.nOpCyclesIMulBM);
    this.opFlags |= X86.OPFLAG.NOWRITE;
    return dst;
};

/**
 * fnIMULw(dst, src)
 *
 * regMDHi:regMDLo = dst * regEAX
 *
 * This 32-bit multiplication must indicate when the upper 16 bits are simply a sign-extension of the
 * lower 16 bits (carry clear) and when the upper 16 bits contain significant bits (carry set).  The latter
 * will occur whenever a positive result is > 32767 (0x00007fff) and whenever a negative result is < -32768
 * (0xffff8000).
 *
 * Example 1: 256 * 64 = 16384 (0x00004000): carry is clear
 * Example 2: 256 * 128 = 32768 (0x00008000): carry is set (the sign bit no longer fits in the lower 16 bits)
 * Example 3: 256 * -128 (0xff80) = -32768 (0xffff8000): carry is clear (the sign bit *still* fits in the lower 16 bits)
 * Example 4: 256 * -256 (0xff00) = -65536 (0xffff0000): carry is set (the sign bit no longer fits in the lower 16 bits)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null; AX or EAX is the implied src)
 * @return {number} (we return dst unchanged, since it's actually DX:AX or EDX:EAX that's modified)
 */
X86.fnIMULw = function(dst, src)
{
    let fOverflow;
    if (this.sizeData == 2) {
        src = this.regEAX & 0xffff;
        let result = (((src << 16) >> 16) * ((dst << 16) >> 16))|0;
        this.regMDLo = result & 0xffff;
        this.regMDHi = (result >> 16) & 0xffff;
        fOverflow = (result > 32767 || result < -32768);
    } else {
        X86.fnIMUL32.call(this, dst, this.regEAX);
        fOverflow = (this.regMDHi != (this.regMDLo >> 31));
    }
    if (fOverflow) {
        this.setCF(); this.setOF();
    } else {
        this.clearCF(); this.clearOF();
    }
    if (this.model <= X86.MODEL_8088) {
        this.clearZF();         // differentiate ourselves from a NEC V20
    }
    this.fMDSet = true;
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesIMulWR : this.cycleCounts.nOpCyclesIMulWM);
    this.opFlags |= X86.OPFLAG.NOWRITE;
    return dst;
};

/**
 * fnIMULrw(dst, src)
 *
 * This function exists for 16-bit IMUL instructions that produce a 16-bit result instead of a 32-bit result
 * (and don't implicitly use the accumulator).
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnIMULrw = function(dst, src)
{
    /*
     * Unlike fnIMULrd() below, we can use normal JavaScript multiplication, because there's no danger of
     * overflowing the floating-point result and losing accuracy in the bottom 16 bits.
     */
    let result = (((dst << 16) >> 16) * ((src << 16) >> 16))|0;
    if (result > 32767 || result < -32768) {
        this.setCF(); this.setOF();
    } else {
        this.clearCF(); this.clearOF();
    }
    result &= 0xffff;
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? 9 : 12);
    return result;
};

/**
 * fnIMULrd(dst, src)
 *
 * This function exists for 32-bit IMUL instructions that produce a 32-bit result instead of a 64-bit result
 * (and don't implicitly use the accumulator).
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnIMULrd = function(dst, src)
{
    /*
     * The following code works, but I've stopped using it because it produces different results from an actual CPU
     * when overflow occurs; the bottom 32 bits of the result are still supposed to be accurate.
     *
     * And unfortunately, we cannot achieve that level of compatibility using normal JavaScript multiplication,
     * because the result may be too large to fit in a JavaScript floating-point variable, which means we could lose
     * accuracy in the bottom 32 bits, which would defeat what we're trying to achieve here.  So we must use the
     * slower fnIMUL32() function.
     *
     *      let result = dst * src;
     *      if (result > 2147483647 || result < -2147483648) {
     *          this.setCF(); this.setOF();
     *      } else {
     *          this.clearCF(); this.clearOF();
     *      }
     *      result |= 0;
     */
    X86.fnIMUL32.call(this, dst, src);
    let fOverflow = (this.regMDHi != (this.regMDLo >> 31));
    if (fOverflow) {
        this.setCF(); this.setOF();
    } else {
        this.clearCF(); this.clearOF();
    }
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? 9 : 12);
    return this.regMDLo;
};

/**
 * fnINCb(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null)
 * @return {number}
 */
X86.fnINCb = function(dst, src)
{
    let b = (dst + 1)|0;
    this.setArithResult(dst, 1, b, X86.RESULT.BYTE | X86.RESULT.NOTCF);
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesIncR : this.cycleCounts.nOpCyclesIncM);
    return b & 0xff;
};

/**
 * fnINCw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null)
 * @return {number}
 */
X86.fnINCw = function(dst, src)
{
    let w = (dst + 1)|0;
    this.setArithResult(dst, 1, w, this.typeData | X86.RESULT.NOTCF);
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesIncR : this.cycleCounts.nOpCyclesIncM);
    return w & this.maskData;
};

/**
 * fnJMPw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null)
 * @return {number}
 */
X86.fnJMPw = function(dst, src)
{
    this.setIP(dst);
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesJmpWR : this.cycleCounts.nOpCyclesJmpWM);
    this.opFlags |= X86.OPFLAG.NOWRITE;
    return dst;
};

/**
 * fnJMPFdw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null)
 * @return {number}
 */
X86.fnJMPFdw = function(dst, src)
{
    if (this.regEA === X86.ADDR_INVALID) {
        return X86.fnGRPUndefined.call(this, dst, src);
    }
    this.setCSIP(dst, this.getShort(this.regEA + this.sizeData));
    if (MAXDEBUG && this.cIntReturn) this.checkIntReturn(this.regLIP);
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpDM;
    this.opFlags |= X86.OPFLAG.NOWRITE;
    return dst;
};

/**
 * fnLAR(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnLAR = function(dst, src)
{
    this.nStepCycles -= (14 + (this.regEA === X86.ADDR_INVALID? 0 : 2));
    /*
     * Currently, segVER.load() will return an error only if the selector is beyond the bounds of the
     * descriptor table or the descriptor is not for a segment.
     *
     * TODO: This instruction's 80286 documentation does not discuss conforming code segments; determine
     * if we need a special check for them.
     */
    this.clearZF();
    if (this.segVER.load(src) !== X86.ADDR_INVALID) {
        if (this.segVER.dpl >= this.nCPL && this.segVER.dpl >= (src & X86.SEL.RPL)) {
            this.setZF();
            dst = this.segVER.acc & ~X86.DESC.ACC.BASE1623;
            if (this.sizeData > 2) {
                dst |= ((this.segVER.ext & ~X86.DESC.EXT.BASE2431) << 16);
            }
        }
    }
    return dst;
};

/**
 * fnLDS(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnLDS = function(dst, src)
{
    if (this.regEA === X86.ADDR_INVALID) {
        X86.opUndefined.call(this);
        return dst;
    }
    this.setDS(this.getShort(this.regEA + this.sizeData));
    this.nStepCycles -= this.cycleCounts.nOpCyclesLS;
    return src;
};

/**
 * fnLEA(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnLEA = function(dst, src)
{
    /*
     * TODO: Until I bite the bullet and choose a truly invalid value for X86.ADDR_INVALID (eg, null),
     * this code must be disabled, because otherwise an instruction like "LEA ECX,[EAX-1]" will fail when
     * EAX is zero.  And we can't have that.
     *
    if (this.regEA === X86.ADDR_INVALID) {
        //
        // TODO: After reading http://www.os2museum.com/wp/undocumented-8086-opcodes/, it seems that this
        // form of LEA (eg, "LEA AX,DX") simply returns the last calculated EA.  Since we always reset regEA
        // at the start of a new instruction, we would need to preserve the previous EA if we want to mimic
        // that (undocumented) behavior.
        //
        // And for completeness, we would have to extend EA tracking beyond the usual ModRM instructions
        // (eg, XLAT, instructions that modify the stack pointer, and string instructions).  Anything else?
        //
        X86.opUndefined.call(this);
        return dst;
    }
    */
    this.nStepCycles -= this.cycleCounts.nOpCyclesLEA;
    return this.regEA;
};

/**
 * fnLES(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnLES = function(dst, src)
{
    if (this.regEA === X86.ADDR_INVALID) {
        X86.opUndefined.call(this);
        return dst;
    }
    this.setES(this.getShort(this.regEA + this.sizeData));
    this.nStepCycles -= this.cycleCounts.nOpCyclesLS;
    return src;
};

/**
 * fnLFS(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnLFS = function(dst, src)
{
    if (this.regEA === X86.ADDR_INVALID) {
        X86.opUndefined.call(this);
        return dst;
    }
    this.setFS(this.getShort(this.regEA + this.sizeData));
    this.nStepCycles -= this.cycleCounts.nOpCyclesLS;
    return src;
};

/**
 * fnLGDT(dst, src)
 *
 * op=0x0F,0x01,reg=0x2 (GRP7:LGDT)
 *
 * The 80286 LGDT instruction assumes a 40-bit operand: a 16-bit limit followed by a 24-bit base address;
 * the ModRM decoder has already supplied the first word of the operand (in dst), which corresponds to
 * the limit, so we must fetch the remaining bits ourselves.
 *
 * The 80386 LGDT instruction assumes a 48-bit operand: a 16-bit limit followed by a 32-bit base address,
 * but it ignores the last 8 bits of the base address if the OPERAND size is 16 bits; we interpret that to
 * mean that the 24-bit base address should be zero-extended to 32 bits.
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null)
 * @return {number}
 */
X86.fnLGDT = function(dst, src)
{
    /*
     * TODO: Consider swapping out this function whenever setProtMode() changes the mode to V86-mode.
     */
    if (this.regEA === X86.ADDR_INVALID || I386 && (this.regPS & X86.PS.VM)) {
        X86.opInvalid.call(this);
    } else {
        /*
         * Hopefully it won't hurt to always fetch a 32-bit base address (even on an 80286), which we then
         * mask appropriately.
         */
        this.addrGDT = this.getLong(this.regEA + 2) & (this.maskData | (this.maskData << 8));
        /*
         * An idiosyncrasy of our ModRM decoders is that, if the OPERAND size is 32 bits, then it will have
         * fetched a 32-bit dst operand; we mask off those extra bits now.
         */
        dst &= 0xffff;
        this.addrGDTLimit = this.addrGDT + dst;
        this.opFlags |= X86.OPFLAG.NOWRITE;
        this.nStepCycles -= 11;
    }
    return dst;
};

/**
 * fnLGS(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnLGS = function(dst, src)
{
    if (this.regEA === X86.ADDR_INVALID) {
        X86.opUndefined.call(this);
        return dst;
    }
    this.setGS(this.getShort(this.regEA + this.sizeData));
    this.nStepCycles -= this.cycleCounts.nOpCyclesLS;
    return src;
};

/**
 * fnLIDT(dst, src)
 *
 * op=0x0F,0x01,reg=0x3 (GRP7:LIDT)
 *
 * The 80286 LIDT instruction assumes a 40-bit operand: a 16-bit limit followed by a 24-bit base address;
 * the ModRM decoder has already supplied the first word of the operand (in dst), which corresponds to
 * the limit, so we must fetch the remaining bits ourselves.
 *
 * The 80386 LIDT instruction assumes a 48-bit operand: a 16-bit limit followed by a 32-bit base address,
 * but it ignores the last 8 bits of the base address if the OPERAND size is 16 bits; we interpret that to
 * mean that the 24-bit base address should be zero-extended to 32 bits.
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null)
 * @return {number}
 */
X86.fnLIDT = function(dst, src)
{
    /*
     * TODO: Consider swapping out this function whenever setProtMode() changes the mode to V86-mode.
     */
    if (this.regEA === X86.ADDR_INVALID || I386 && (this.regPS & X86.PS.VM)) {
        X86.opInvalid.call(this);
    } else {
        /*
         * Hopefully it won't hurt to always fetch a 32-bit base address (even on an 80286), which we then
         * mask appropriately.
         */
        this.addrIDT = this.getLong(this.regEA + 2) & (this.maskData | (this.maskData << 8));
        /*
         * An idiosyncrasy of our ModRM decoders is that, if the OPERAND size is 32 bits, then it will have
         * fetched a 32-bit dst operand; we mask off those extra bits now.
         */
        dst &= 0xffff;
        this.addrIDTLimit = this.addrIDT + dst;
        this.opFlags |= X86.OPFLAG.NOWRITE;
        this.nStepCycles -= 12;
    }
    return dst;
};

/**
 * fnLLDT(dst, src)
 *
 * op=0x0F,0x00,reg=0x2 (GRP6:LLDT)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null)
 * @return {number}
 */
X86.fnLLDT = function(dst, src)
{
    this.opFlags |= X86.OPFLAG.NOWRITE;
    this.segLDT.load(dst);
    this.nStepCycles -= (17 + (this.regEA === X86.ADDR_INVALID? 0 : 2));
    return dst;
};

/**
 * fnLMSW(dst, src)
 *
 * op=0x0F,0x01,reg=0x6 (GRP7:LMSW)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null)
 * @return {number}
 */
X86.fnLMSW = function(dst, src)
{
    /*
     * TODO: Consider swapping out this function whenever setProtMode() changes the mode to V86-mode.
     */
    if (I386 && (this.regPS & X86.PS.VM)) {
        X86.opInvalid.call(this);
    } else {
        this.setMSW(dst);
        this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? 3 : 6);
        this.opFlags |= X86.OPFLAG.NOWRITE;
    }
    return dst;
};

/**
 * fnLSL(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (the selector)
 * @return {number}
 */
X86.fnLSL = function(dst, src)
{
    /*
     * TODO: Is this an invalid operation if regEAWrite is set?  dst is required to be a register.
     */
    this.nStepCycles -= (14 + (this.regEA === X86.ADDR_INVALID? 0 : 2));
    /*
     * Currently, segVER.load() will return an error only if the selector is beyond the bounds of the
     * descriptor table or the descriptor is not for a segment.
     *
     * TODO: LSL is explicitly documented as ALSO requiring a non-null selector, so we check X86.SEL.MASK;
     * are there any other instructions that were, um, less explicit but also require a non-null selector?
     */
    if ((src & X86.SEL.MASK) && this.segVER.load(src) !== X86.ADDR_INVALID) {
        let fConforming = ((this.segVER.acc & X86.DESC.ACC.TYPE.CODE_CONFORMING) == X86.DESC.ACC.TYPE.CODE_CONFORMING);
        if ((fConforming || this.segVER.dpl >= this.nCPL) && this.segVER.dpl >= (src & X86.SEL.RPL)) {
            this.setZF();
            return this.segVER.limit;
        }
    }
    this.clearZF();
    return dst;
};

/**
 * fnLSS(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnLSS = function(dst, src)
{
    if (this.regEA === X86.ADDR_INVALID) {
        X86.opUndefined.call(this);
        return dst;
    }
    this.setSS(this.getShort(this.regEA + this.sizeData));
    this.nStepCycles -= this.cycleCounts.nOpCyclesLS;
    return src;
};

/**
 * fnLTR(dst, src)
 *
 * op=0x0F,0x00,reg=0x3 (GRP6:LTR)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null)
 * @return {number}
 */
X86.fnLTR = function(dst, src)
{
    this.opFlags |= X86.OPFLAG.NOWRITE;
    if (this.segTSS.load(dst) !== X86.ADDR_INVALID) {
        this.setShort(this.segTSS.addrDesc + X86.DESC.ACC.OFFSET, this.segTSS.acc |= X86.DESC.ACC.TYPE.TSS_BUSY);
        this.segTSS.type |= X86.DESC.ACC.TYPE.TSS_BUSY;
    }
    this.nStepCycles -= (17 + (this.regEA === X86.ADDR_INVALID? 0 : 2));
    return dst;
};

/**
 * fnMOV(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst (current value, ignored)
 * @param {number} src (new value)
 * @return {number} dst (updated value, from src)
 */
X86.fnMOV = function(dst, src)
{
    this.nStepCycles -= (this.regEAWrite === X86.ADDR_INVALID? (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesMovRR : this.cycleCounts.nOpCyclesMovRM) : this.cycleCounts.nOpCyclesMovMR);
    return src;
};

/**
 * fnMOVXb(dst, src)
 *
 * Helper for opMOVSXb() and opMOVZXb() (which also take care of updating nStepCycles, so we don't have to)
 *
 * @this {CPUx86}
 * @param {number} dst (current value, ignored)
 * @param {number} src (new value)
 * @return {number} dst (updated value, from src)
 */
X86.fnMOVXb = function(dst, src)
{
    /*
     * The ModRegByte handlers update the registers in the 1st column, but we need to update those in the 2nd column.
     *
     *      000:    AL      ->      000:    AX
     *      001:    CL      ->      001:    CX
     *      010:    DL      ->      010:    DX
     *      011:    BL      ->      011:    BX
     *      100:    AH      ->      100:    SP
     *      101:    CH      ->      101:    BP
     *      110:    DH      ->      110:    SI
     *      111:    BH      ->      111:    DI
     */
    let reg = (this.bModRM >> 3) & 0x7;

    switch(reg) {
    case 0x4:
        this.regXX = this.regEAX;
        break;
    case 0x5:
        this.regXX = this.regECX;
        break;
    case 0x6:
        this.regXX = this.regEDX;
        break;
    case 0x7:
        this.regXX = this.regEBX;
        break;
    }
    return src;
};

/**
 * fnMOVXw(dst, src)
 *
 * Helper for opMOVSXw() and opMOVZXw() (which also take care of updating nStepCycles, so we don't have to)
 *
 * @this {CPUx86}
 * @param {number} dst (current value, ignored)
 * @param {number} src (new value)
 * @return {number} dst (updated value, from src)
 */
X86.fnMOVXw = function(dst, src)
{
    return src;
};

/**
 * fnMOVn(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst (current value, ignored)
 * @param {number} src (new value)
 * @return {number} dst (updated value, from src)
 */
X86.fnMOVn = function(dst, src)
{
    this.nStepCycles -= (this.regEAWrite === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesMovRI : this.cycleCounts.nOpCyclesMovMI);
    return src;
};

/**
 * fnMOVsrw(dst, src)
 *
 * This helper saves the contents of the general-purpose register that will be overwritten, so that the caller
 * can restore it after moving the updated value to the correct segment register.
 *
 * @this {CPUx86}
 * @param {number} dst (current value, ignored)
 * @param {number} src (new value)
 * @return {number} dst (updated value, from src)
 */
X86.fnMOVsrw = function(dst, src)
{
    let reg = (this.bModRM >> 3) & 0x7;

    switch(reg) {
    case 0x0:
        this.regXX = this.regEAX;
        break;
    case 0x2:
        this.regXX = this.regEDX;
        break;
    case 0x3:
        this.regXX = this.regEBX;
        break;
    default:
        if (this.model == X86.MODEL_80286 || this.model == X86.MODEL_80386 && reg != 0x4 && reg != 0x5) {
            X86.opInvalid.call(this);
            break;
        }
        switch(reg) {
        case 0x1:           // MOV to CS is undocumented on 8086/8088/80186/80188, and invalid on 80286 and up
            this.regXX = this.regECX;
            break;
        case 0x4:           // this form of MOV to ES is undocumented on 8086/8088/80186/80188, invalid on 80286, and uses FS starting with 80386
            this.regXX = this.getSP();
            break;
        case 0x5:           // this form of MOV to CS is undocumented on 8086/8088/80186/80188, invalid on 80286, and uses GS starting with 80386
            this.regXX = this.regEBP;
            break;
        case 0x6:           // this form of MOV to SS is undocumented on 8086/8088/80186/80188, invalid on 80286 and up
            this.regXX = this.regESI;
            break;
        case 0x7:           // this form of MOV to DS is undocumented on 8086/8088/80186/80188, invalid on 80286 and up
            this.regXX = this.regEDI;
            break;
        default:
            break;
        }
        break;
    }
    /*
     * We could just return src, but nStepCycles needs to be updated, too.
     */
    return X86.fnMOV.call(this, dst, src);
};

/**
 * fnMOVwsr(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst (current value, ignored)
 * @param {number} src (new value)
 * @return {number} dst
 */
X86.fnMOVwsr = function(dst, src)
{
    let reg = (this.bModRM >> 3) & 0x7;

    switch (reg) {
    case 0x0:
        src = this.segES.sel;
        break;
    case 0x1:
        src = this.segCS.sel;
        break;
    case 0x2:
        src = this.segSS.sel;
        break;
    case 0x3:
        src = this.segDS.sel;
        break;
    case 0x4:
        if (I386 && this.model >= X86.MODEL_80386) {
            src = this.segFS.sel;
            break;
        }
        X86.opInvalid.call(this);
        src = dst;
        break;
    case 0x5:
        if (I386 && this.model >= X86.MODEL_80386) {
            src = this.segGS.sel;
            break;
        }
        /* falls through */
    default:
        X86.opInvalid.call(this);
        src = dst;
        break;
    }

    /*
     * When a 32-bit OPERAND size is in effect, segment register writes via opMOVwsr() must write 32 bits
     * (zero-extended) if the destination is a register, but only 16 bits if the destination is memory,
     * hence the setDataSize(2) below.
     *
     * The only other caller, opMOVrc(), is not affected, because it writes only to register destinations.
     */
    if (this.regEAWrite !== X86.ADDR_INVALID) {
        this.setDataSize(2);
    }
    /*
     * We could just return src, but nStepCycles needs to be updated, too.
     */
    return X86.fnMOV.call(this, dst, src);
};

/**
 * fnMULb(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null)
 * @return {number} (we return dst unchanged, since it's actually AX that's modified)
 */
X86.fnMULb = function(dst, src)
{
    this.regMDLo = ((this.regEAX & 0xff) * dst) & 0xffff;
    if (this.regMDLo & 0xff00) {
        this.setCF(); this.setOF();
    } else {
        this.clearCF(); this.clearOF();
    }
    if (this.model <= X86.MODEL_8088) {
        this.clearZF();         // differentiate ourselves from a NEC V20
    }
    this.fMDSet = true;
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesMulBR : this.cycleCounts.nOpCyclesMulBM);
    this.opFlags |= X86.OPFLAG.NOWRITE;
    return dst;
};

/**
 * fnMUL32(dst, src)
 *
 * This sets regMDHi:regMDLo to the 64-bit result of dst * src, both of which are treated as unsigned.
 *
 * The algorithm is based on the traditional "by hand" multiplication method, by treating the two inputs
 * (dst and src) as two 2-digit numbers, where each digit is a base-65536 digit.
 *
 * @this {CPUx86}
 * @param {number} dst (any 32-bit number, treated as unsigned)
 * @param {number} src (any 32-bit number, treated as unsigned)
 */
X86.fnMUL32 = function(dst, src)
{
    if (!(dst & ~0xffff) && !(src & ~0xffff)) {
        this.regMDLo = (dst * src)|0;
        this.regMDHi = 0;
    }
    else {
        let srcLo = src & 0xffff;
        let srcHi = src >>> 16;
        let dstLo = dst & 0xffff;
        let dstHi = dst >>> 16;

        let mul00 = srcLo * dstLo;
        let mul16 = ((mul00 >>> 16) + (srcHi * dstLo));
        let mul32 = mul16 >>> 16;
        mul16 = ((mul16 & 0xffff) + (srcLo * dstHi));
        mul32 += ((mul16 >>> 16) + (srcHi * dstHi));

        this.regMDLo = (mul16 << 16) | (mul00 & 0xffff);
        this.regMDHi = mul32|0;
    }
};

/**
 * fnMULw(dst, src)
 *
 * regMDHi:regMDLo = dst * regEAX
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null; AX or EAX is the implied src)
 * @return {number} (we return dst unchanged, since it's actually DX:AX that's modified)
 */
X86.fnMULw = function(dst, src)
{
    if (this.sizeData == 2) {
        src = this.regEAX & 0xffff;
        let result = (src * dst)|0;
        this.regMDLo = result & 0xffff;
        this.regMDHi = (result >> 16) & 0xffff;
    } else {
        X86.fnMUL32.call(this, dst, this.regEAX);
        if (this.stepping == X86.STEPPING_80386_B1) {
            if (this.regEAX == 0x0417A000 && dst == 0x00000081) {
                /*
                 * Normally, the result should be 0x20FE7A000 (ie, regMDHi should be 0x2).
                 * I'm not sure what a typical B1 stepping failure looked like, so I'll set regMDHi to 0.
                 *
                 * If you want a B1 stepping without this 32-bit multiplication flaw, select the B2 stepping.
                 */

                this.regMDHi = 0;
            }
        }
    }

    if (this.regMDHi) {
        this.setCF(); this.setOF();
    } else {
        this.clearCF(); this.clearOF();
    }
    if (this.model <= X86.MODEL_8088) {
        this.clearZF();         // differentiate ourselves from a NEC V20
    }
    this.fMDSet = true;
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesMulWR : this.cycleCounts.nOpCyclesMulWM);
    this.opFlags |= X86.OPFLAG.NOWRITE;
    return dst;
};

/**
 * fnNEGb(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null)
 * @return {number}
 */
X86.fnNEGb = function(dst, src)
{
    let b = (-dst)|0;
    this.setArithResult(0, dst, b, X86.RESULT.BYTE | X86.RESULT.ALL, true);
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesNegR : this.cycleCounts.nOpCyclesNegM);
    return b & 0xff;
};

/**
 * fnNEGw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null)
 * @return {number}
 */
X86.fnNEGw = function(dst, src)
{
    let w = (-dst)|0;
    this.setArithResult(0, dst, w, this.typeData | X86.RESULT.ALL, true);
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesNegR : this.cycleCounts.nOpCyclesNegM);
    return w & this.maskData;
};

/**
 * fnNOTb(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null)
 * @return {number}
 */
X86.fnNOTb = function(dst, src)
{
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesNegR : this.cycleCounts.nOpCyclesNegM);
    return dst ^ 0xff;
};

/**
 * fnNOTw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null)
 * @return {number}
 */
X86.fnNOTw = function(dst, src)
{
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesNegR : this.cycleCounts.nOpCyclesNegM);
    return dst ^ this.maskData;
};

/**
 * fnORb(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnORb = function(dst, src)
{
    this.nStepCycles -= (this.regEAWrite === X86.ADDR_INVALID? (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesArithRR : this.cycleCounts.nOpCyclesArithRM) : this.cycleCounts.nOpCyclesArithMR);
    return this.setLogicResult(dst | src, X86.RESULT.BYTE);
};

/**
 * fnORw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnORw = function(dst, src)
{
    this.nStepCycles -= (this.regEAWrite === X86.ADDR_INVALID? (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesArithRR : this.cycleCounts.nOpCyclesArithRM) : this.cycleCounts.nOpCyclesArithMR);
    return this.setLogicResult(dst | src, this.typeData) & this.maskData;
};

/**
 * fnPOPw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst (current value, ignored)
 * @param {number} src (new value)
 * @return {number} dst (updated value, from src)
 */
X86.fnPOPw = function(dst, src)
{
    this.nStepCycles -= (this.regEAWrite === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesPopReg : this.cycleCounts.nOpCyclesPopMem);
    return src;
};

/**
 * fnPUSHw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null)
 * @return {number}
 */
X86.fnPUSHw = function(dst, src)
{
    let w = dst;
    if (this.opFlags & X86.OPFLAG.PUSHSP) {
        /*
         * This is the one case where must actually modify dst, so that the ModRM function will
         * not put a stale value back into the SP register.
         */
        dst = (dst - 2) & 0xffff;
        /*
         * And on the 8086/8088, the value we just calculated also happens to be the value that must
         * be pushed.
         */
        if (this.model < X86.MODEL_80286) w = dst;
    }
    this.pushWord(w);
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesPushReg : this.cycleCounts.nOpCyclesPushMem);
    /*
     * The PUSH is the only write that needs to occur; dst was the source operand and does not need to be rewritten.
     */
    this.opFlags |= X86.OPFLAG.NOWRITE;
    return dst;
};

/**
 * fnRCLb(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (1 or CL)
 * @return {number}
 */
X86.fnRCLb = function(dst, src)
{
    let result = dst;
    let count = src & this.nShiftCountMask;
    if (count) {
        let carry = this.getCarry();
        count %= 9;
        if (!count) {
            carry <<= 7;
        } else {
            result = ((dst << count) | (carry << (count - 1)) | (dst >> (9 - count))) & 0xff;
            carry = dst << (count - 1);
        }
        this.setRotateResult(result, carry, X86.RESULT.BYTE);
    }
    return result;
};

/**
 * fnRCLw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (1 or CL)
 * @return {number}
 */
X86.fnRCLw = function(dst, src)
{
    let result = dst;
    let count = src & this.nShiftCountMask;
    if (count) {
        let carry = this.getCarry();
        count %= 17;
        if (!count) {
            carry <<= 15;
        } else {
            result = ((dst << count) | (carry << (count - 1)) | (dst >> (17 - count))) & 0xffff;
            carry = dst << (count - 1);
        }
        this.setRotateResult(result, carry, X86.RESULT.WORD);
    }
    return result;
};

/**
 * fnRCLd(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (1 or CL)
 * @return {number}
 */
X86.fnRCLd = function(dst, src)
{
    let result = dst;
    let count = src & this.nShiftCountMask;     // this 32-bit-only function could mask with 0x1f directly
    if (count) {
        let carry = this.getCarry();
        /*
         * JavaScript Alert: much like a post-8086 Intel CPU, JavaScript shift counts are mod 32,
         * so "dst >>> 32" is equivalent to "dst >>> 0", which doesn't shift any bits at all.  To
         * compensate, we shift one bit less than the maximum, and then shift one bit farther.
         */
        result = (dst << count) | (carry << (count - 1)) | ((dst >>> (32 - count)) >>> 1);
        carry = dst << (count - 1);
        this.setRotateResult(result, carry, X86.RESULT.DWORD);
    }
    return result;
};

/**
 * fnRCRb(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (1 or CL)
 * @return {number}
 */
X86.fnRCRb = function(dst, src)
{
    let result = dst;
    let count = src & this.nShiftCountMask;
    if (count) {
        let carry = this.getCarry();
        count %= 9;
        if (!count) {
            carry <<= 7;
        } else {
            result = ((dst >> count) | (carry << (8 - count)) | (dst << (9 - count))) & 0xff;
            carry = dst << (8 - count);
        }
        this.setRotateResult(result, carry, X86.RESULT.BYTE);
    }
    return result;
};

/**
 * fnRCRw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (1 or CL)
 * @return {number}
 */
X86.fnRCRw = function(dst, src)
{
    let result = dst;
    let count = src & this.nShiftCountMask;
    if (count) {
        let carry = this.getCarry();
        count %= 17;
        if (!count) {
            carry <<= 15;
        } else {
            result = ((dst >> count) | (carry << (16 - count)) | (dst << (17 - count))) & 0xffff;
            carry = dst << (16 - count);
        }
        this.setRotateResult(result, carry, X86.RESULT.WORD);
    }
    return result;
};

/**
 * fnRCRd(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (1 or CL)
 * @return {number}
 */
X86.fnRCRd = function(dst, src)
{
    let result = dst;
    let count = src & this.nShiftCountMask;     // this 32-bit-only function could mask with 0x1f directly
    if (count) {
        let carry = this.getCarry();
        /*
         * JavaScript Alert: much like a post-8086 Intel CPU, JavaScript shift counts are mod 32,
         * so "dst << 32" is equivalent to "dst << 0", which doesn't shift any bits at all.  To
         * compensate, we shift one bit less than the maximum, and then shift one bit farther.
         */
        result = (dst >>> count) | (carry << (32 - count)) | ((dst << (32 - count)) << 1);
        carry = dst << (32 - count);
        this.setRotateResult(result, carry, X86.RESULT.DWORD);
    }
    return result;
};

/**
 * fnROLb(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (1 or CL)
 * @return {number}
 */
X86.fnROLb = function(dst, src)
{
    let result = dst;
    let count = src & this.nShiftCountMask;
    if (count) {
        let carry;
        count &= 0x7;
        if (!count) {
            carry = dst << 7;
        } else {
            carry = dst << (count - 1);
            result = ((dst << count) | (dst >> (8 - count))) & 0xff;
        }
        this.setRotateResult(result, carry, X86.RESULT.BYTE);
    }
    return result;
};

/**
 * fnROLw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (1 or CL)
 * @return {number}
 */
X86.fnROLw = function(dst, src)
{
    let result = dst;
    let count = src & this.nShiftCountMask;
    if (count) {
        let carry;
        count &= 0xf;
        if (!count) {
            carry = dst << 15;
        } else {
            carry = dst << (count - 1);
            result = ((dst << count) | (dst >> (16 - count))) & 0xffff;
        }
        this.setRotateResult(result, carry, X86.RESULT.WORD);
    }
    return result;
};

/**
 * fnROLd(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (1 or CL)
 * @return {number}
 */
X86.fnROLd = function(dst, src)
{
    let result = dst;
    let count = src & this.nShiftCountMask;
    if (count) {
        let carry = dst << (count - 1);
        result = (dst << count) | (dst >>> (32 - count));
        this.setRotateResult(result, carry, X86.RESULT.DWORD);
    }
    return result;
};

/**
 * fnRORb(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (1 or CL)
 * @return {number}
 */
X86.fnRORb = function(dst, src)
{
    let result = dst;
    let count = src & this.nShiftCountMask;
    if (count) {
        let carry;
        count &= 0x7;
        if (!count) {
            carry = dst;
        } else {
            carry = dst << (8 - count);
            result = ((dst >>> count) | carry) & 0xff;
        }
        this.setRotateResult(result, carry, X86.RESULT.BYTE);
    }
    return result;
};

/**
 * fnRORw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (1 or CL)
 * @return {number}
 */
X86.fnRORw = function(dst, src)
{
    let result = dst;
    let count = src & this.nShiftCountMask;
    if (count) {
        let carry;
        count &= 0xf;
        if (!count) {
            carry = dst;
        } else {
            carry = dst << (16 - count);
            result = ((dst >>> count) | carry) & 0xffff;
        }
        this.setRotateResult(result, carry, X86.RESULT.WORD);
    }
    return result;
};

/**
 * fnRORd(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (1 or CL)
 * @return {number}
 */
X86.fnRORd = function(dst, src)
{
    let result = dst;
    let count = src & this.nShiftCountMask;
    if (count) {
        let carry = dst << (32 - count);
        result = (dst >>> count) | carry;
        this.setRotateResult(result, carry, X86.RESULT.DWORD);
    }
    return result;
};

/**
 * fnSARb(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (1 or CL, or an immediate byte for 80186/80188 and up)
 * @return {number}
 */
X86.fnSARb = function(dst, src)
{
    let count = src & this.nShiftCountMask;
    if (count) {
        if (count > 9) count = 9;
        let carry = ((dst << 24) >> 24) >> (count - 1);
        dst = (carry >> 1) & 0xff;
        this.setLogicResult(dst, X86.RESULT.BYTE, carry & 0x1);
    }
    return dst;
};

/**
 * fnSARw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (1 or CL, or an immediate byte for 80186/80188 and up)
 * @return {number}
 */
X86.fnSARw = function(dst, src)
{
    let count = src & this.nShiftCountMask;
    if (count) {
        if (count > 17) count = 17;
        let carry = ((dst << 16) >> 16) >> (count - 1);
        dst = (carry >> 1) & 0xffff;
        this.setLogicResult(dst, X86.RESULT.WORD, carry & 0x1);
    }
    return dst;
};

/**
 * fnSARd(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (1 or CL, or an immediate byte for 80186/80188 and up)
 * @return {number}
 */
X86.fnSARd = function(dst, src)
{
    let count = src & this.nShiftCountMask;
    if (count) {
        let carry = dst >> (count - 1);
        dst = (carry >> 1);
        this.setLogicResult(dst, X86.RESULT.DWORD, carry & 0x1);
    }
    return dst;
};

/**
 * fnSBBb(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnSBBb = function(dst, src)
{
    let b = (dst - src - this.getCarry())|0;
    this.setArithResult(dst, src, b, X86.RESULT.BYTE | X86.RESULT.ALL, true);
    this.nStepCycles -= (this.regEAWrite === X86.ADDR_INVALID? (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesArithRR : this.cycleCounts.nOpCyclesArithRM) : this.cycleCounts.nOpCyclesArithMR);
    return b & 0xff;
};

/**
 * fnSBBw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnSBBw = function(dst, src)
{
    let w = (dst - src - this.getCarry())|0;
    this.setArithResult(dst, src, w, this.typeData | X86.RESULT.ALL, true);
    this.nStepCycles -= (this.regEAWrite === X86.ADDR_INVALID? (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesArithRR : this.cycleCounts.nOpCyclesArithRM) : this.cycleCounts.nOpCyclesArithMR);
    return w & this.maskData;
};

/**
 * fnSETO(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst (ignored)
 * @param {number} src (ignored)
 * @return {number}
 */
X86.fnSETO = function(dst, src)
{
    return (this.getOF()? 1 : 0);
};

/**
 * fnSETNO(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst (ignored)
 * @param {number} src (ignored)
 * @return {number}
 */
X86.fnSETNO = function(dst, src)
{
    return (this.getOF()? 0 : 1);
};

/**
 * fnSETC(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst (ignored)
 * @param {number} src (ignored)
 * @return {number}
 */
X86.fnSETC = function(dst, src)
{
    return (this.getCF()? 1 : 0);
};

/**
 * fnSETNC(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst (ignored)
 * @param {number} src (ignored)
 * @return {number}
 */
X86.fnSETNC = function(dst, src)
{
    return (this.getCF()? 0 : 1);
};

/**
 * fnSETZ(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst (ignored)
 * @param {number} src (ignored)
 * @return {number}
 */
X86.fnSETZ = function(dst, src)
{
    return (this.getZF()? 1 : 0);
};

/**
 * fnSETNZ(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst (ignored)
 * @param {number} src (ignored)
 * @return {number}
 */
X86.fnSETNZ = function(dst, src)
{
    return (this.getZF()? 0 : 1);
};

/**
 * fnSETBE(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst (ignored)
 * @param {number} src (ignored)
 * @return {number}
 */
X86.fnSETBE = function(dst, src)
{
    return (this.getCF() || this.getZF()? 1 : 0);
};

/**
 * fnSETNBE(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst (ignored)
 * @param {number} src (ignored)
 * @return {number}
 */
X86.fnSETNBE = function(dst, src)
{
    return (this.getCF() || this.getZF()? 0 : 1);
};

/**
 * fnSETS(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst (ignored)
 * @param {number} src (ignored)
 * @return {number}
 */
X86.fnSETS = function(dst, src)
{
    return (this.getSF()? 1 : 0);
};

/**
 * fnSETNS(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst (ignored)
 * @param {number} src (ignored)
 * @return {number}
 */
X86.fnSETNS = function(dst, src)
{
    return (this.getSF()? 0 : 1);
};

/**
 * fnSETP(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst (ignored)
 * @param {number} src (ignored)
 * @return {number}
 */
X86.fnSETP = function(dst, src)
{
    return (this.getPF()? 1 : 0);
};

/**
 * fnSETNP(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst (ignored)
 * @param {number} src (ignored)
 * @return {number}
 */
X86.fnSETNP = function(dst, src)
{
    return (this.getPF()? 0 : 1);
};

/**
 * fnSETL(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst (ignored)
 * @param {number} src (ignored)
 * @return {number}
 */
X86.fnSETL = function(dst, src)
{
    return (!this.getSF() != !this.getOF()? 1 : 0);
};

/**
 * fnSETNL(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst (ignored)
 * @param {number} src (ignored)
 * @return {number}
 */
X86.fnSETNL = function(dst, src)
{
    return (!this.getSF() != !this.getOF()? 0 : 1);
};

/**
 * fnSETLE(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst (ignored)
 * @param {number} src (ignored)
 * @return {number}
 */
X86.fnSETLE = function(dst, src)
{
    return (this.getZF() || !this.getSF() != !this.getOF()? 1 : 0);
};

/**
 * fnSETNLE(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst (ignored)
 * @param {number} src (ignored)
 * @return {number}
 */
X86.fnSETNLE = function(dst, src)
{
    return (this.getZF() || !this.getSF() != !this.getOF()? 0 : 1);
};

/**
 * fnSGDT(dst, src)
 *
 * op=0x0F,0x01,reg=0x0 (GRP7:SGDT)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null)
 * @return {number}
 */
X86.fnSGDT = function(dst, src)
{
    if (this.regEA === X86.ADDR_INVALID) {
        X86.opInvalid.call(this);
    } else {
        /*
         * We don't need to set the first word of the operand, because the ModRM group decoder that calls us
         * does that automatically with the value we return (dst).
         */
        dst = this.addrGDTLimit - this.addrGDT;


        let addr = this.addrGDT;
        if (this.model == X86.MODEL_80286) {
            /*
             * We previously left the 6th byte of the target operand "undefined".  But it turns out we have to set
             * it to *something*, because there's processor detection in PC-DOS 7.0 (at least in the SETUP portion)
             * that looks like this:
             *
             *      145E:4B84 9C            PUSHF
             *      145E:4B85 55            PUSH     BP
             *      145E:4B86 8BEC          MOV      BP,SP
             *      145E:4B88 B80000        MOV      AX,0000
             *      145E:4B8B 50            PUSH     AX
             *      145E:4B8C 9D            POPF
             *      145E:4B8D 9C            PUSHF
             *      145E:4B8E 58            POP      AX
             *      145E:4B8F 2500F0        AND      AX,F000
             *      145E:4B92 3D00F0        CMP      AX,F000
             *      145E:4B95 7511          JNZ      4BA8
             *      145E:4BA8 C8060000      ENTER    0006,00
             *      145E:4BAC 0F0146FA      SGDT     [BP-06]
             *      145E:4BB0 807EFFFF      CMP      [BP-01],FF
             *      145E:4BB4 C9            LEAVE
             *      145E:4BB5 BA8603        MOV      DX,0386
             *      145E:4BB8 7503          JNZ      4BBD
             *      145E:4BBA BA8602        MOV      DX,0286
             *      145E:4BBD 89163004      MOV      [0430],DX
             *      145E:4BC1 5D            POP      BP
             *      145E:4BC2 9D            POPF
             *      145E:4BC3 CB            RETF
             *
             * This code is expecting SGDT on an 80286 to set the 6th "undefined" byte to 0xFF, so that's what we do.
             */
            addr |= (0xff000000|0);
        }
        else if (this.model >= X86.MODEL_80386) {
            /*
             * The 80386 added another wrinkle: Intel's documentation claimed that the 6th byte is either set to zero
             * or the high byte of the BASE field, depending on the OPERAND size; from the "INTEL 80386 PROGRAMMER'S
             * REFERENCE MANUAL 1986":
             *
             *      The LIMIT field of the [GDTR or IDTR] register is assigned to the first word at the effective address.
             *      If the operand-size attribute is 32 bits, the next three bytes are assigned the BASE field of the
             *      register, and the fourth byte is written with zero. The last byte is undefined. Otherwise, if the
             *      operand-size attribute is 16 bits, the next 4 bytes are assigned the 32-bit BASE field of the register.
             *
             * However, Intel obviously meant the reverse (ie, that the BASE field is truncated when using a 16-bit
             * OPERAND size, not when using a 32-bit OPERAND size).
             */
            if (this.sizeData == 2) {
                /*
                 * Thanks to Michal Necasek, we now know that the: "386 in reality does not pay attention to the operand
                 * size (despite Intel's claims to the contrary). In fact Windows 3.11/Win32s relies on it -- at least in
                 * some configurations, it will execute SGDT in 16-bit code and will crash if all 6 bytes aren't stored."
                 *
                 * Based on the above information, we no longer mask the 6th byte on the 80386 when the OPERAND size is 2.
                 *
                 *      addr &= 0x00ffffff;
                 */
            } else {
                /*
                 * When the OPERAND size is 4, our ModRM group decoder will call setLong(dst) rather than setShort(dst);
                 * we could fix that by calling setDataSize(2), but it seems safer/simpler to set the high bits (16-31)
                 * of dst to match the low bits (0-15) of addr, so that the caller will harmlessly rewrite what we are
                 * already writing with the setLong() below.
                 */
                dst |= (addr << 16);
            }
        }
        this.setLong(this.regEA + 2, addr);
        this.nStepCycles -= 11;
    }
    return dst;
};

/**
 * fnSHLb(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (1 or CL, or an immediate byte for 80186/80188 and up)
 * @return {number}
 */
X86.fnSHLb = function(dst, src)
{
    let result = dst;
    let count = src & this.nShiftCountMask;
    if (count) {
        let carry = 0;
        if (count > 8) {
            result = 0;
        } else {
            carry = dst << (count - 1);
            result = (carry << 1) & 0xff;
        }
        this.setLogicResult(result, X86.RESULT.BYTE, carry & X86.RESULT.BYTE, (result ^ carry) & X86.RESULT.BYTE);
    }
    return result;
};

/**
 * fnSHLw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (1 or CL, or an immediate byte for 80186/80188 and up)
 * @return {number}
 */
X86.fnSHLw = function(dst, src)
{
    let result = dst;
    let count = src & this.nShiftCountMask;
    if (count) {
        let carry = 0;
        if (count > 16) {
            result = 0;
        } else {
            carry = dst << (count - 1);
            result = (carry << 1) & 0xffff;
        }
        this.setLogicResult(result, X86.RESULT.WORD, carry & X86.RESULT.WORD, (result ^ carry) & X86.RESULT.WORD);
    }
    return result;
};

/**
 * fnSHLd(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (1 or CL, or an immediate byte for 80186/80188 and up)
 * @return {number}
 */
X86.fnSHLd = function(dst, src)
{
    let result = dst;
    let count = src & this.nShiftCountMask;     // this 32-bit-only function could mask with 0x1f directly
    if (count) {
        let carry = dst << (count - 1);
        result = (carry << 1);
        this.setLogicResult(result, X86.RESULT.DWORD, carry & X86.RESULT.DWORD, (result ^ carry) & X86.RESULT.DWORD);
    }
    return result;
};

/**
 * fnSHLDwi(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnSHLDwi = function(dst, src)
{
    return X86.helpSHLDw.call(this, dst, src, this.getIPByte());
};

/**
 * fnSHLDdi(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnSHLDdi = function(dst, src)
{
    return X86.helpSHLDd.call(this, dst, src, this.getIPByte());
};

/**
 * fnSHLDwCL(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnSHLDwCL = function(dst, src)
{
    return X86.helpSHLDw.call(this, dst, src, this.regECX & 0x1f);
};

/**
 * fnSHLDdCL(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnSHLDdCL = function(dst, src)
{
    return X86.helpSHLDd.call(this, dst, src, this.regECX & 0x1f);
};

/**
 * fnSHRb(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (1 or CL, or an immediate byte for 80186/80188 and up)
 * @return {number}
 */
X86.fnSHRb = function(dst, src)
{
    let count = src & this.nShiftCountMask;
    if (count) {
        let carry = (count > 8? 0 : (dst >>> (count - 1)));
        dst = (carry >>> 1) & 0xff;
        this.setLogicResult(dst, X86.RESULT.BYTE, carry & 0x1, dst & X86.RESULT.BYTE);
    }
    return dst;
};

/**
 * fnSHRw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (1 or CL, or an immediate byte for 80186/80188 and up)
 * @return {number}
 */
X86.fnSHRw = function(dst, src)
{
    let count = src & this.nShiftCountMask;
    if (count) {
        let carry = (count > 16? 0 : (dst >>> (count - 1)));
        dst = (carry >>> 1) & 0xffff;
        this.setLogicResult(dst, X86.RESULT.WORD, carry & 0x1, dst & X86.RESULT.WORD);
    }
    return dst;
};

/**
 * fnSHRd(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (1 or CL, or an immediate byte for 80186/80188 and up)
 * @return {number}
 */
X86.fnSHRd = function(dst, src)
{
    let count = src & this.nShiftCountMask;
    if (count) {
        let carry = (dst >>> (count - 1));
        dst = (carry >>> 1);
        this.setLogicResult(dst, X86.RESULT.DWORD, carry & 0x1, dst & X86.RESULT.DWORD);
    }
    return dst;
};

/**
 * fnSHRDwi(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnSHRDwi = function(dst, src)
{
    return X86.helpSHRDw.call(this, dst, src, this.getIPByte());
};

/**
 * fnSHRDdi(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnSHRDdi = function(dst, src)
{
    return X86.helpSHRDd.call(this, dst, src, this.getIPByte());
};

/**
 * fnSHRDwCL(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnSHRDwCL = function(dst, src)
{
    return X86.helpSHRDw.call(this, dst, src, this.regECX & 0x1f);
};

/**
 * fnSHRDdCL(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnSHRDdCL = function(dst, src)
{
    return X86.helpSHRDd.call(this, dst, src, this.regECX & 0x1f);
};

/**
 * fnSIDT(dst, src)
 *
 * op=0x0F,0x01,reg=0x1 (GRP7:SIDT)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null)
 * @return {number}
 */
X86.fnSIDT = function(dst, src)
{
    if (this.regEA === X86.ADDR_INVALID) {
        X86.opInvalid.call(this);
    } else {
        /*
         * We don't need to set the first word of the operand, because the ModRM group decoder that calls us
         * does that automatically with the value we return (dst).
         */
        dst = this.addrIDTLimit - this.addrIDT;

        /*
         * As with SGDT, the 6th byte is technically "undefined" on an 80286, but we now set it to 0xFF, for the
         * same reasons discussed in SGDT (above).
         */
        let addr = this.addrIDT;
        if (this.model == X86.MODEL_80286) {
            addr |= (0xff000000|0);
        }
        else if (this.model >= X86.MODEL_80386) {
            if (this.sizeData == 2) {
                /*
                 * Based on the SGDT information above, we no longer mask the 6th byte when the OPERAND size is 2.
                 *
                 *      addr &= 0x00ffffff;
                 */
            } else {
                dst |= (addr << 16);
            }
        }
        this.setLong(this.regEA + 2, addr);
        this.nStepCycles -= 12;
    }
    return dst;
};

/**
 * fnSLDT(dst, src)
 *
 * op=0x0F,0x00,reg=0x0 (GRP6:SLDT)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null)
 * @return {number}
 */
X86.fnSLDT = function(dst, src)
{
    this.nStepCycles -= (2 + (this.regEA === X86.ADDR_INVALID? 0 : 1));
    return this.segLDT.sel;
};

/**
 * fnSMSW(dst, src)
 *
 * TODO: I've seen a claim that SMSW can be used with an operand size override to obtain the entire CR0.
 * I don't dispute that, and since I don't mask the return value, that should be possible here; however, it
 * should still be confirmed on real hardware at some point.  Note that this differs from LMSW, which is
 * REQUIRED to mask the source operand.
 *
 * op=0x0F,0x01,reg=0x4 (GRP7:SMSW)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null)
 * @return {number}
 */
X86.fnSMSW = function(dst, src)
{
    this.nStepCycles -= (2 + (this.regEA === X86.ADDR_INVALID? 0 : 1));
    return this.regCR0;
};

/**
 * fnSTR(dst, src)
 *
 * op=0x0F,0x00,reg=0x1 (GRP6:STR)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null)
 * @return {number}
 */
X86.fnSTR = function(dst, src)
{
    this.nStepCycles -= (2 + (this.regEA === X86.ADDR_INVALID? 0 : 1));
    return this.segTSS.sel;
};

/**
 * fnSUBb(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnSUBb = function(dst, src)
{
    let b = (dst - src)|0;
    this.setArithResult(dst, src, b, X86.RESULT.BYTE | X86.RESULT.ALL, true);
    this.nStepCycles -= (this.regEAWrite === X86.ADDR_INVALID? (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesArithRR : this.cycleCounts.nOpCyclesArithRM) : this.cycleCounts.nOpCyclesArithMR);
    return b & 0xff;
};

/**
 * fnSUBw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnSUBw = function(dst, src)
{
    let w = (dst - src)|0;
    this.setArithResult(dst, src, w, this.typeData | X86.RESULT.ALL, true);
    this.nStepCycles -= (this.regEAWrite === X86.ADDR_INVALID? (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesArithRR : this.cycleCounts.nOpCyclesArithRM) : this.cycleCounts.nOpCyclesArithMR);
    return w & this.maskData;
};

/**
 * fnTESTib(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null; we have to supply the source ourselves)
 * @return {number}
 */
X86.fnTESTib = function(dst, src)
{
    src = this.getIPByte();
    this.setLogicResult(dst & src, X86.RESULT.BYTE);
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesTestRI : this.cycleCounts.nOpCyclesTestMI);
    this.opFlags |= X86.OPFLAG.NOWRITE;
    return dst;
};

/**
 * fnTESTiw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null; we have to supply the source ourselves)
 * @return {number}
 */
X86.fnTESTiw = function(dst, src)
{
    src = this.getIPWord();
    this.setLogicResult(dst & src, this.typeData);
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesTestRI : this.cycleCounts.nOpCyclesTestMI);
    this.opFlags |= X86.OPFLAG.NOWRITE;
    return dst;
};

/**
 * fnTESTb(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnTESTb = function(dst, src)
{
    this.setLogicResult(dst & src, X86.RESULT.BYTE);
    this.nStepCycles -= (this.regEAWrite === X86.ADDR_INVALID? (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesTestRR : this.cycleCounts.nOpCyclesTestRM) : this.cycleCounts.nOpCyclesTestRM);
    this.opFlags |= X86.OPFLAG.NOWRITE;
    return dst;
};

/**
 * fnTESTw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnTESTw = function(dst, src)
{
    this.setLogicResult(dst & src, this.typeData);
    this.nStepCycles -= (this.regEAWrite === X86.ADDR_INVALID? (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesTestRR : this.cycleCounts.nOpCyclesTestRM) : this.cycleCounts.nOpCyclesTestRM);
    this.opFlags |= X86.OPFLAG.NOWRITE;
    return dst;
};

/**
 * fnVERR(dst, src)
 *
 * op=0x0F,0x00,reg=0x4 (GRP6:VERR)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null)
 * @return {number}
 */
X86.fnVERR = function(dst, src)
{
    this.opFlags |= X86.OPFLAG.NOWRITE;
    /*
     * Currently, segVER.load() will return an error only if the selector is beyond the bounds of the
     * descriptor table or the descriptor is not for a segment.
     */
    this.nStepCycles -= (14 + (this.regEA === X86.ADDR_INVALID? 0 : 2));
    if (this.segVER.load(dst) !== X86.ADDR_INVALID) {
        /*
         * Verify that this is a readable segment; that is, of these four combinations (code+readable,
         * code+nonreadable, data+writable, date+nonwritable), make sure we're not the second combination.
         */
        if ((this.segVER.acc & (X86.DESC.ACC.TYPE.READABLE | X86.DESC.ACC.TYPE.CODE)) != X86.DESC.ACC.TYPE.CODE) {
            /*
             * For VERR, if the code segment is readable and conforming, the descriptor privilege level
             * (DPL) can be any value.
             *
             * Otherwise, DPL must be greater than or equal to (have less or the same privilege as) both the
             * current privilege level and the selector's RPL.
             */
            if (this.segVER.dpl >= this.nCPL && this.segVER.dpl >= (dst & X86.SEL.RPL) ||
                (this.segVER.acc & X86.DESC.ACC.TYPE.CODE_CONFORMING) == X86.DESC.ACC.TYPE.CODE_CONFORMING) {
                this.setZF();
                return dst;
            }
        }
    }
    this.clearZF();
    if (DEBUG && (this.sizeData > 2 || this.sizeAddr > 2)) this.stopCPU();
    return dst;
};

/**
 * fnVERW(dst, src)
 *
 * op=0x0F,0x00,reg=0x5 (GRP6:VERW)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src (null)
 * @return {number}
 */
X86.fnVERW = function(dst, src)
{
    this.opFlags |= X86.OPFLAG.NOWRITE;
    /*
     * Currently, segVER.load() will return an error only if the selector is beyond the bounds of the
     * descriptor table or the descriptor is not for a segment.
     */
    this.nStepCycles -= (14 + (this.regEA === X86.ADDR_INVALID? 0 : 2));
    if (this.segVER.load(dst) !== X86.ADDR_INVALID) {
        /*
         * Verify that this is a writable data segment
         */
        if ((this.segVER.acc & (X86.DESC.ACC.TYPE.WRITABLE | X86.DESC.ACC.TYPE.CODE)) == X86.DESC.ACC.TYPE.WRITABLE) {
            /*
             * DPL must be greater than or equal to (have less or the same privilege as) both the current
             * privilege level and the selector's RPL.
             */
            if (this.segVER.dpl >= this.nCPL && this.segVER.dpl >= (dst & X86.SEL.RPL)) {
                this.setZF();
                return dst;
            }
        }
    }
    this.clearZF();
    if (DEBUG && (this.sizeData > 2 || this.sizeAddr > 2)) this.stopCPU();
    return dst;
};

/**
 * fnIBTS(dst, src)
 *
 * As best I can determine, this function copies the specified bits from src (starting at bit 0 for CL
 * bits) to dst (starting at bit offset in AX).  For register operands, that's simple enough.
 *
 * TODO: If dst refers to a memory location, then the bit index may refer to higher memory locations, just
 * like the BT/BTC/BTR/BTS instructions.  For an instruction that no one was really able to use, except
 * as a CPU stepping discriminator, that doesn't seem worth the effort.
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnIBTS = function(dst, src)
{
    let shift = (this.regEAX & this.maskData);
    let mask = ((1 << (this.regECX & 0x1f)) - 1);
    return (dst & ~(mask << shift)) | ((src & mask) << shift);
};

/**
 * fnXBTS(dst, src)
 *
 * As best I can determine, this function copies the specified bits from src (starting at the bit offset
 * in AX, for the bit length in CL) to dst (starting at bit 0).  For register operands, that's simple enough.
 *
 * TODO: If src refers to a memory location, then the bit index may refer to higher memory locations, just
 * like the BT/BTC/BTR/BTS instructions.  For an instruction that no one was really able to use, except
 * as a CPU stepping discriminator, that doesn't seem worth the effort.
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnXBTS = function(dst, src)
{
    /*
     * Shift src right by the bit offset in [E]AX, then apply a mask equal to the number of bits in CL,
     * then mask the resulting bit string with the current OPERAND size.
     */
    return ((src >> (this.regEAX & this.maskData)) & ((1 << (this.regECX & 0x1f)) - 1)) & this.maskData;
};

/**
 * fnXCHGrb(dst, src)
 *
 * If an instruction like "XCHG AL,AH" was a traditional "op dst,src" instruction, dst would contain AL,
 * src would contain AH, and we would return src, which the caller would then store in AL, and we'd be done.
 *
 * However, that's only half of what XCHG does, so THIS function must perform the other half; in the previous
 * example, that means storing the original AL (dst) into AH (src).
 *
 * BACKTRACK support is incomplete without also passing bti values as parameters, because the caller will
 * store btiAH in btiAL, but the original btiAL will be lost.  Similarly, if src is a memory operand, the
 * caller will store btiEALo in btiAL, but again, the original btiAL will be lost.
 *
 * BACKTRACK support for memory operands could be fixed by decoding the dst register in order to determine the
 * corresponding bti and then temporarily storing it in btiEALo around the setEAByte() call below.  Register-only
 * XCHGs would require a more extensive hack.  For now, I'm going to live with one-way BACKTRACK support here.
 *
 * TODO: Implement full BACKTRACK support for XCHG instructions.
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnXCHGrb = function(dst, src)
{
    if (this.regEA === X86.ADDR_INVALID) {
        /*
         * Decode which register was src
         */

        switch (this.bModRM & 0x7) {
        case 0x0:       // AL
            this.regEAX = (this.regEAX & ~0xff) | dst;
            break;
        case 0x1:       // CL
            this.regECX = (this.regECX & ~0xff) | dst;
            break;
        case 0x2:       // DL
            this.regEDX = (this.regEDX & ~0xff) | dst;
            break;
        case 0x3:       // BL
            this.regEBX = (this.regEBX & ~0xff) | dst;
            break;
        case 0x4:       // AH
            this.regEAX = (this.regEAX & ~0xff00) | (dst << 8);
            break;
        case 0x5:       // CH
            this.regECX = (this.regECX & ~0xff00) | (dst << 8);
            break;
        case 0x6:       // DH
            this.regEDX = (this.regEDX & ~0xff00) | (dst << 8);
            break;
        case 0x7:       // BH
            this.regEBX = (this.regEBX & ~0xff00) | (dst << 8);
            break;
        default:
            break;      // there IS no other case, but JavaScript inspections don't know that
        }
        this.nStepCycles -= this.cycleCounts.nOpCyclesXchgRR;
    } else {
        /*
         * This is a case where the ModRM decoder that's calling us didn't know it should have set regEAWrite,
         * so we compensate by updating regEAWrite.  However, setEAWord() has since been changed to revalidate
         * the write using segEA:offEA, so updating regEAWrite here isn't strictly necessary.
         */
        this.regEAWrite = this.regEA;
        this.setEAByte(dst);
        this.nStepCycles -= this.cycleCounts.nOpCyclesXchgRM;
    }
    return src;
};

/**
 * fnXCHGrw(dst, src)
 *
 * If an instruction like "XCHG AX,DX" was a traditional "op dst,src" instruction, dst would contain AX,
 * src would contain DX, and we would return src, which the caller would then store in AX, and we'd be done.
 *
 * However, that's only half of what XCHG does, so THIS function must perform the other half; in the previous
 * example, that means storing the original AX (dst) into DX (src).
 *
 * TODO: Implement full BACKTRACK support for XCHG instructions (see fnXCHGrb comments).
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnXCHGrw = function(dst, src)
{
    if (this.regEA === X86.ADDR_INVALID) {
        /*
         * Decode which register was src
         */

        switch (this.bModRM & 0x7) {
        case 0x0:       // [E]AX
            this.regEAX = (this.regEAX & ~this.maskData) | dst;
            break;
        case 0x1:       // [E]CX
            this.regECX = (this.regECX & ~this.maskData) | dst;
            break;
        case 0x2:       // [E]DX
            this.regEDX = (this.regEDX & ~this.maskData) | dst;
            break;
        case 0x3:       // [E]BX
            this.regEBX = (this.regEBX & ~this.maskData) | dst;
            break;
        case 0x4:       // [E]SP
            this.setSP((this.getSP() & ~this.maskData) | dst);
            break;
        case 0x5:       // [E]BP
            this.regEBP = (this.regEBX & ~this.maskData) | dst;
            break;
        case 0x6:       // [E]SI
            this.regESI = (this.regESI & ~this.maskData) | dst;
            break;
        case 0x7:       // [E]DI
            this.regEDI = (this.regEDI & ~this.maskData) | dst;
            break;
        default:
            break;      // there IS no other case, but JavaScript inspections don't know that
        }
        this.nStepCycles -= this.cycleCounts.nOpCyclesXchgRR;
    } else {
        /*
         * This is a case where the ModRM decoder that's calling us didn't know it should have set regEAWrite,
         * so we compensate by updating regEAWrite.  However, setEAWord() has since been changed to revalidate
         * the write using segEA:offEA, so updating regEAWrite here isn't strictly necessary.
         */
        this.regEAWrite = this.regEA;
        this.setEAWord(dst);
        this.nStepCycles -= this.cycleCounts.nOpCyclesXchgRM;
    }
    return src;
};

/**
 * fnXORb(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnXORb = function(dst, src)
{
    let b = dst ^ src;
    this.setLogicResult(b, X86.RESULT.BYTE);
    this.nStepCycles -= (this.regEAWrite === X86.ADDR_INVALID? (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesArithRR : this.cycleCounts.nOpCyclesArithRM) : this.cycleCounts.nOpCyclesArithMR);
    return b;
};

/**
 * fnXORw(dst, src)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @return {number}
 */
X86.fnXORw = function(dst, src)
{
    this.nStepCycles -= (this.regEAWrite === X86.ADDR_INVALID? (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesArithRR : this.cycleCounts.nOpCyclesArithRM) : this.cycleCounts.nOpCyclesArithMR);
    return this.setLogicResult(dst ^ src, this.typeData) & this.maskData;
};

/**
 * @copyright https://www.pcjs.org/machines/pcx86/lib/x86help.js (C) 2012-2021 Jeff Parsons
 */


/**
 * helpAdd64(r64Dst, r64Src)
 *
 * Adds r64Src to r64Dst.
 *
 * @param {Array.<number>} r64Dst is a 64-bit value
 * @param {Array.<number>} r64Src is a 64-bit value
 */
X86.helpAdd64 = function(r64Dst, r64Src)
{
    r64Dst[0] += r64Src[0];
    r64Dst[1] += r64Src[1];
    if (r64Dst[0] > 0xffffffff) {
        r64Dst[0] >>>= 0;       // truncate r64Dst[0] to 32 bits AND keep it unsigned
        r64Dst[1]++;
    }
};

/**
 * helpCmp64(r64Dst, r64Src)
 *
 * Compares r64Dst to r64Src, by computing r64Dst - r64Src.
 *
 * @param {Array.<number>} r64Dst is a 64-bit value
 * @param {Array.<number>} r64Src is a 64-bit value
 * @return {number} > 0 if r64Dst > r64Src, == 0 if r64Dst == r64Src, < 0 if r64Dst < r64Src
 */
X86.helpCmp64 = function(r64Dst, r64Src)
{
    let result = r64Dst[1] - r64Src[1];
    if (!result) result = r64Dst[0] - r64Src[0];
    return result;
};

/**
 * helpSet64(r64Dst, lo, hi)
 *
 * @param {Array.<number>} r64Dst
 * @param {number} lo
 * @param {number} hi
 * @return {Array.<number>}
 */
X86.helpSet64 = function(r64Dst, lo, hi)
{
    r64Dst[0] = lo >>> 0;
    r64Dst[1] = hi >>> 0;
    return r64Dst;
};

/**
 * helpShr64(r64Dst)
 *
 * Shifts r64Dst right one bit.
 *
 * @param {Array.<number>} r64Dst is a 64-bit value
 */
X86.helpShr64 = function(r64Dst)
{
    r64Dst[0] >>>= 1;
    if (r64Dst[1] & 0x1) {
        r64Dst[0] = (r64Dst[0] | 0x80000000) >>> 0;
    }
    r64Dst[1] >>>= 1;
};

/**
 * helpSub64(r64Dst, r64Src)
 *
 * Subtracts r64Src from r64Dst.
 *
 * @param {Array.<number>} r64Dst is a 64-bit value
 * @param {Array.<number>} r64Src is a 64-bit value
 */
X86.helpSub64 = function(r64Dst, r64Src)
{
    r64Dst[0] -= r64Src[0];
    r64Dst[1] -= r64Src[1];
    if (r64Dst[0] < 0) {
        r64Dst[0] >>>= 0;       // truncate r64Dst[0] to 32 bits AND keep it unsigned
        r64Dst[1]--;
    }
};

/**
 * helpDECreg(w)
 *
 * @this {CPUx86}
 * @param {number} w
 * @return {number}
 */
X86.helpDECreg = function(w)
{
    let result = (w - 1)|0;
    this.setArithResult(w, 1, result, this.typeData | X86.RESULT.NOTCF, true);
    this.nStepCycles -= 2;                          // the register form of DEC takes 2 cycles on all CPUs
    return (w & ~this.maskData) | (result & this.maskData);
};

/**
 * helpDIV32(dstLo, dstHi, src)
 *
 * This sets regMDLo to dstHi:dstLo / src, and regMDHi to dstHi:dstLo % src; all inputs are treated as unsigned.
 *
 * Refer to: http://lxr.linux.no/linux+v2.6.22/lib/div64.c
 *
 * @this {CPUx86}
 * @param {number} dstLo (low 32-bit portion of dividend)
 * @param {number} dstHi (high 32-bit portion of dividend)
 * @param {number} src (32-bit divisor)
 * @return {boolean} true if successful, false if overflow (ie, the divisor was either zero or too small)
 */
X86.helpDIV32 = function(dstLo, dstHi, src)
{
    src >>>= 0;

    if (!src || src <= (dstHi >>> 0)) {
        return false;
    }

    let result = 0, bit = 1;

    let r64Div = X86.helpSet64(this.r64Div, src, 0);
    let r64Rem = X86.helpSet64(this.r64Rem, dstLo, dstHi);

    while (X86.helpCmp64(r64Rem, r64Div) > 0) {
        X86.helpAdd64(r64Div, r64Div);
        bit += bit;
    }
    do {
        if (X86.helpCmp64(r64Rem, r64Div) >= 0) {
            X86.helpSub64(r64Rem, r64Div);
            result += bit;
        }
        X86.helpShr64(r64Div);
        bit /= 2;
    } while (bit >= 1);



    this.regMDLo = result;      // result is the quotient, which callers expect in the low MD register
    this.regMDHi = r64Rem[0];   // r64Rem[0] is the remainder, which callers expect in the high MD register
    return true;
};

/**
 * helpIDIV32(dstLo, dstHi, src)
 *
 * This sets regMDLo to dstHi:dstLo / src, and regMDHi to dstHi:dstLo % src; all inputs are treated as signed.
 *
 * Refer to: http://lxr.linux.no/linux+v2.6.22/lib/div64.c
 *
 * @this {CPUx86}
 * @param {number} dstLo (low 32-bit portion of dividend)
 * @param {number} dstHi (high 32-bit portion of dividend)
 * @param {number} src (32-bit divisor)
 * @return {boolean} true if successful, false if overflow (ie, the divisor was either zero or too small)
 */
X86.helpIDIV32 = function(dstLo, dstHi, src)
{
    let bNegLo = 0, bNegHi = 0;
    /*
     *      dividend    divisor       quotient    remainder
     *        (dst)      (src)          (lo)         (hi)
     *      --------    -------       --------    ---------
     *         +           +     ->       +           +
     *         +           -     ->       -           +
     *         -           +     ->       -           -
     *         -           -     ->       +           -
     */
    if (src < 0) {
        src = -src|0;
        bNegLo = 1 - bNegLo;
    }
    if (dstHi < 0) {
        dstLo = -dstLo|0;
        dstHi = (~dstHi + (dstLo? 0 : 1))|0;
        bNegHi = 1;
        bNegLo = 1 - bNegLo;
    }
    if (!X86.helpDIV32.call(this, dstLo, dstHi, src) || this.regMDLo > 0x7fffffff+bNegLo || this.regMDHi > 0x7fffffff+bNegHi) {
        return false;
    }
    if (bNegLo) this.regMDLo = -this.regMDLo;
    if (bNegHi) this.regMDHi = -this.regMDHi;
    return true;
};

/**
 * helpINCreg(w)
 *
 * @this {CPUx86}
 * @param {number} w
 * @return {number}
 */
X86.helpINCreg = function(w)
{
    let result = (w + 1)|0;
    this.setArithResult(w, 1, result, this.typeData | X86.RESULT.NOTCF);
    this.nStepCycles -= 2;                          // the register form of INC takes 2 cycles on all CPUs
    return (w & ~this.maskData) | (result & this.maskData);
};

/**
 * helpLoadCR0(l)
 *
 * This is called by an 80386 control instruction (ie, MOV CR0,reg).
 *
 * @this {CPUx86}
 * @param {number} l
 */
X86.helpLoadCR0 = function(l)
{
    this.regCR0 = l | X86.CR0.ON;
    this.setProtMode();
    if (this.regCR0 & X86.CR0.PG) {
        /*
         * TODO: Determine if setting X86.CR0.PG when already set should really act as a flush;
         * I'm not currently worried about it, because I'm assuming CR0 is not rewritten that often.
         */
        this.enablePageBlocks();
    } else {
        this.disablePageBlocks();
    }
};

/**
 * helpLoadCR3(l)
 *
 * This is called by an 80386 control instruction (ie, MOV CR3,reg) or an 80386 task switch.
 *
 * @this {CPUx86}
 * @param {number} l
 */
X86.helpLoadCR3 = function(l)
{
    this.regCR3 = l;
    /*
     * Normal use of regCR3 involves adding a 0-4K (12-bit) offset to obtain a page directory entry,
     * so let's ensure that the low 12 bits of regCR3 are always zero.
     */

    this.flushPageBlocks();
};

/**
 * helpSETcc()
 *
 * @this {CPUx86}
 * @param {function(number,number)} fnSet
 */
X86.helpSETcc = function(fnSet)
{
    this.opFlags |= X86.OPFLAG.NOREAD;
    this.decodeModMemByte.call(this, fnSet);
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? 4 : 5);
};

/**
 * helpSHLDw(dst, src, count)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @param {number} count (0-31)
 * @return {number}
 */
X86.helpSHLDw = function(dst, src, count)
{
    if (count) {
        if (count > 16) {
            dst = src;
            count -= 16;
        }
        let carry = dst << (count - 1);
        dst = ((carry << 1) | (src >>> (16 - count))) & 0xffff;
        this.setLogicResult(dst, X86.RESULT.WORD, carry & X86.RESULT.WORD);
    }
    return dst;
};

/**
 * helpSHLDd(dst, src, count)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @param {number} count
 * @return {number}
 */
X86.helpSHLDd = function(dst, src, count)
{
    if (count) {
        let carry = dst << (count - 1);
        dst = (carry << 1) | (src >>> (32 - count));
        this.setLogicResult(dst, X86.RESULT.DWORD, carry & X86.RESULT.DWORD);
    }
    return dst;
};

/**
 * helpSHRDw(dst, src, count)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @param {number} count (0-31)
 * @return {number}
 */
X86.helpSHRDw = function(dst, src, count)
{
    if (count) {
        if (count > 16) {
            dst = src;
            count -= 16;
        }
        let carry = dst >>> (count - 1);
        dst = ((carry >>> 1) | (src << (16 - count))) & 0xffff;
        this.setLogicResult(dst, X86.RESULT.WORD, carry & 0x1);
    }
    return dst;
};

/**
 * helpSHRDd(dst, src, count)
 *
 * @this {CPUx86}
 * @param {number} dst
 * @param {number} src
 * @param {number} count
 * @return {number}
 */
X86.helpSHRDd = function(dst, src, count)
{
    if (count) {
        let carry = dst >>> (count - 1);
        dst = (carry >>> 1) | (src << (32 - count));
        this.setLogicResult(dst, X86.RESULT.DWORD, carry & 0x1);
    }
    return dst;
};

/**
 * helpSRC1()
 *
 * @this {CPUx86}
 * @return {number}
 */
X86.helpSRC1 = function()
{
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? 2 : this.cycleCounts.nOpCyclesShift1M);
    return 1;
};

/**
 * helpSRCCL()
 *
 * @this {CPUx86}
 * @return {number}
 */
X86.helpSRCCL = function()
{
    let count = this.regECX & 0xff;
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesShiftCR : this.cycleCounts.nOpCyclesShiftCM) + (count << this.cycleCounts.nOpCyclesShiftCS);
    return count;
};

/**
 * helpSRCByte()
 *
 * @this {CPUx86}
 * @return {number}
 */
X86.helpSRCByte = function()
{
    let count = this.getIPByte();
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? this.cycleCounts.nOpCyclesShiftCR : this.cycleCounts.nOpCyclesShiftCM) + (count << this.cycleCounts.nOpCyclesShiftCS);
    return count;
};

/**
 * helpSRCNone()
 *
 * @this {CPUx86}
 * @return {number|null}
 */
X86.helpSRCNone = function()
{
    return null;
};

/**
 * helpSRCxx()
 *
 * This is used by opPOPmw(), because the actual pop must occur BEFORE the effective address (EA)
 * calculation.  So opPOPmw() does the pop, saves the popped value in regXX, and this passes src function
 * to the EA worker.
 *
 * @this {CPUx86}
 * @return {number} regXX
 */
X86.helpSRCxx = function()
{
    return this.regXX;
};

/**
 * helpCALLF(off, sel)
 *
 * For protected-mode, this function must attempt to load the new code segment first, because if the new segment
 * requires a change in privilege level, the return address must be pushed on the NEW stack, not the current stack.
 *
 * Also, we rely on a new function, pushData(), instead of pushWord(), to accommodate the outgoing segment size,
 * which may differ from the incoming segment.  For example, when a 32-bit code segment performs a 16:32 call to a
 * 16-bit code segment, we must push 32-bit segment and offset values.
 *
 * TODO: Since setCSIP() already informs the segCS load() function when it's making a call, the load() function
 * could automatically push the old CS and IP values *before* segCS is updated -- which would be a better time to do
 * those pushes AND eliminate the need for pushData().  Unfortunately, load() is also used by loadIDT(), and loadIDT()
 * has different requirements (eg, pushing flags first), so it's not a trivial change.
 *
 * @this {CPUx86}
 * @param {number} off
 * @param {number} sel
 */
X86.helpCALLF = function(off, sel)
{
    /*
     * Since we always push the return address AFTER calling setCSIP(), and since either push could trigger
     * a fault (eg, segment fault, page fault, etc), we must not only snapshot regSS and regLSP, but also regCS,
     * so that helpFault() can always make CALLF restartable.
     */
    this.opCS = this.getCS();
    this.opSS = this.getSS();
    this.opLSP = this.regLSP;
    let oldIP = this.getIP();
    let oldSize = (I386? this.sizeData : 2);
    if (this.setCSIP(off, sel, true) != null) {
        /*
         * When the OPERAND size is 32 bits, the 80386 will decrement the stack pointer by 4, write the selector
         * into the 2 lower bytes, and leave the 2 upper bytes untouched; at least, that's the case for all other
         * segment register writes, so we assume this case is no different.  Hence, the hard-coded size of 2.
         */
        this.pushData(this.opCS, oldSize, 2);
        this.pushData(oldIP, oldSize, oldSize);
    }
    this.opLSP = X86.ADDR_INVALID;
    this.opCS = this.opSS = -1;
};

/**
 * helpINT(nIDT, nError, nCycles)
 *
 * NOTE: We no longer use setCSIP(), because it always loads the new CS using segCS.load(), which only knows
 * how to load GDT and LDT descriptors, whereas interrupts must use setCS.loadIDT(), which deals exclusively
 * with IDT descriptors.
 *
 * @this {CPUx86}
 * @param {number} nIDT
 * @param {number|null} [nError]
 * @param {number} [nCycles] (in addition to the default of nOpCyclesInt)
 */
X86.helpINT = function(nIDT, nError, nCycles)
{
    /*
     * TODO: We assess the cycle cost up front, because otherwise, if loadIDT() fails, no cost may be assessed.
     */
    this.nStepCycles -= this.cycleCounts.nOpCyclesInt + (nCycles || 0);
    let oldPS = this.getPS();
    let oldCS = this.getCS();
    let oldIP = this.getIP();
    /*
     * Support for INT 06h operation checks.  The only operation we consume is the one reserved for breakpoints,
     * and only if our debugger is running.  All these should only occur in DEBUG builds of the underlying operating
     * system, which should clean up after itself.
     */
    if (nIDT == 0x06 && this.model <= X86.MODEL_8088) {
        let op = this.getSOWord(this.segCS, oldIP-2);
        if (op == 0x06CD) {
            let actual;
            let argA = this.getSOWord(this.segSS, this.regEBP+10) | (this.getSOWord(this.segSS, this.regEBP+12) << 16);
            let argB = this.getSOWord(this.segSS, this.regEBP+6) | (this.getSOWord(this.segSS, this.regEBP+8) << 16);
            let result = this.regEAX | (this.regEDX << 16);
            let remainder = this.regEDI | (this.regESI << 16);
            switch(this.peekIPByte()) {
            case 0xCC:
                if (DEBUGGER && this.dbg && this.flags.running) {
                    this.getIPByte();
                    this.printMessage("debugger halting on INT 0x06,0xCC", DEBUGGER || this.bitsMessage);
                    this.dbg.stopCPU();
                    return;
                }
                break;
            case 0xFB:
                actual = (argA * argB)|0;
                if (result != actual) {
                    if (!COMPILED) this.printf(Messages.INT, "result %#x for %#x * %#x does not match actual: %#x\n", result, argA, argB, actual);
                }
                break;
            case 0xFC:
                actual = (argA / argB)|0;
                if (result != actual) {
                    if (!COMPILED) this.printf(Messages.INT, "result %#x for %#x / %#x does not match actual: %#x\n", result, argA, argB, actual);
                }
                actual = (argA % argB)|0;
                if (remainder != actual) {
                    if (!COMPILED) this.printf(Messages.INT, "result %#x for %#x % %#x does not match actual: %#x\n", result, argA, argB, actual);
                }
                break;
            }
        }
    }
    if (nIDT == 0x13 && this.model <= X86.MODEL_8088) {
        if (DEBUGGER && this.dbg && this.regEAX == 0x0201 && this.regEBX == 0x7C00 && this.segES.sel == 0) {
            this.setShort(0x52D, 0x4442);       // on 8088 boot up, set a special "BD" boot indicator in low memory
        }
    }
    let addr = this.segCS.loadIDT(nIDT);
    if (addr !== X86.ADDR_INVALID) {
        /*
         * TODO: Determine if we should use pushData() instead of pushWord() for oldCS and nError, to deal with
         * the same 32-bit 80386 compatibility issue that helpCALLF(), opPUSHCS(), et al must deal with; namely, that
         * 32-bit segment register writes (and, reportedly, 32-bit error codes) don't modify the upper 16 bits.
         *
         * Also, note that helpCALLF() is using the OPERAND size in effect *before* CS is loaded, whereas here we're
         * using the OPERAND size in effect *after* CS is loaded.  Is that correct?  And does an explicit OPERAND
         * size override on an "INT" instruction have any effect on that behavior?  Is that even allowed?
         */
        this.pushWord(oldPS);
        this.pushWord(oldCS);
        this.pushWord(oldIP);
        if (nError != null) this.pushWord(nError);
        this.nFault = -1;
        this.setLIP(addr);
    }
};

/**
 * helpIRET()
 *
 * @this {CPUx86}
 */
X86.helpIRET = function()
{
    this.opSS = this.getSS();
    this.opLSP = this.regLSP;

    this.nStepCycles -= this.cycleCounts.nOpCyclesIRet;

    if ((this.regCR0 & X86.CR0.MSW.PE) && (this.regPS & X86.PS.NT)) {
        let addrNew = this.segTSS.base;
        /*
         * Fortunately, X86.TSS286.PREV_TSS and X86.TSS386.PREV_TSS refer to the same TSS offset.
         * TODO: Update switchTS() to assess a cycle cost; currently, all we assess is what's shown above.
         */
        let sel = this.getShort(addrNew + X86.TSS286.PREV_TSS);
        this.segCS.switchTSS(sel, false);
    }
    else {
        let cpl = this.nCPL;
        let newIP = this.popWord();
        let newCS = this.popWord();
        let newPS = this.popWord();

        if (I386) {
            if (this.regPS & X86.PS.VM) {
                /*
                 * On the 80386, in V86-mode, RF is the only defined EFLAGS bit above bit 15 that may be changed by IRETD.
                 * This is less restrictive than POPFD, which cannot change ANY bits above bit 15; see opPOPF() for details.
                 */
                newPS = (newPS & (0xffff | X86.PS.RF)) | (this.regPS & ~(0xffff | X86.PS.RF));
            }
            else {
                if (newPS & X86.PS.VM) {
                    /*
                     * As noted in loadDesc8(), where the V86-mode frame we're about to pop was originally pushed,
                     * these frames ALWAYS contain 32-bit values, so make sure that sizeData reflects that.
                     */

                    /*
                     * We have to assume that a full V86-mode interrupt frame was on the protected-mode stack; namely:
                     *
                     *      low:    EIP
                     *              CS (padded to 32 bits)
                     *              EFLAGS
                     *              ESP
                     *              SS (padded to 32 bits)
                     *              ES (padded to 32 bits)
                     *              DS (padded to 32 bits)
                     *              FS (padded to 32 bits)
                     *      high:   GS (padded to 32 bits)
                     *
                     * We've already popped EIP, CS, and EFLAGS into newIP, newCS and newPS, respectively, so we must now
                     * pop the rest, while we're still in protected-mode, before the switch to V86-mode alters the current
                     * operand size (among other things).
                     */
                    let newSP = this.popWord();
                    let newSS = this.popWord();
                    let newES = this.popWord();
                    let newDS = this.popWord();
                    let newFS = this.popWord();
                    let newGS = this.popWord();
                    this.setProtMode(true, true);       // flip the switch to V86-mode now
                    this.setSS(newSS);
                    this.setSP(newSP);
                    this.setES(newES);
                    this.setDS(newDS);
                    this.setFS(newFS);
                    this.setGS(newGS);
                }
            }
        }

        if (this.setCSIP(newIP, newCS, false) != null) {
            this.setPS(newPS, cpl);
            if (this.cIntReturn) this.checkIntReturn(this.regLIP);
        }
    }

    this.opLSP = X86.ADDR_INVALID;
    this.opSS = -1;
};

/**
 * helpRETF(n)
 *
 * For protected-mode, this function must pop any arguments off the current stack AND whatever stack
 * we may have switched to; setCSIP() returns true if a stack switch occurred, false if not, and null
 * if an error occurred.
 *
 * @this {CPUx86}
 * @param {number} n
 */
X86.helpRETF = function(n)
{
    this.opSS = this.getSS();
    this.opLSP = this.regLSP;

    let newIP = this.popWord();
    let newCS = this.popWord();

    if (n) this.setSP(this.getSP() + n);            // TODO: optimize

    if (this.setCSIP(newIP, newCS, false)) {        // returns true if a stack switch occurred
        /*
         * Fool me once, shame on... whatever.  If setCSIP() indicates a stack switch occurred,
         * make sure we're in protected mode, because automatic stack switches can't occur in real mode.
         */


        if (n) this.setSP(this.getSP() + n);        // TODO: optimize

        /*
         * As per Intel documentation: "If any of [the DS or ES] registers refer to segments whose DPL is
         * less than the new CPL (excluding conforming code segments), the segment register is loaded with
         * the null selector."
         *
         * TODO: I'm not clear on whether a conforming code segment must also be marked readable, so I'm playing
         * it safe and using CODE_CONFORMING instead of CODE_CONFORMING_READABLE.  Also, for the record, I've not
         * seen this situation occur yet (eg, in OS/2 1.0).
         */
        X86.zeroSeg.call(this, this.segDS);
        X86.zeroSeg.call(this, this.segES);
        if (I386 && this.model >= X86.MODEL_80386) {
            X86.zeroSeg.call(this, this.segFS);
            X86.zeroSeg.call(this, this.segGS);
        }
    }
    if (n == 2 && this.cIntReturn) this.checkIntReturn(this.regLIP);

    this.opLSP = X86.ADDR_INVALID;
    this.opSS = -1;
};

/**
 * helpDIVOverflow()
 *
 * @this {CPUx86}
 */
X86.helpDIVOverflow = function()
{
    /*
     * Divide error exceptions are traps on the 8086 and faults on later processors.  I question the value of that
     * change, because it implies that someone might actually want to restart a failing divide.  The only reasonable
     * explanation I can see for the change is to enable the exception handler to accurately record the address of
     * the failing divide, which seems like a very minor benefit.  It doesn't change the fact that, on any processor,
     * the exception handler's only reasonable recourse is to unwind execution to a safe point (or terminate the app).
     *
     * TODO: Determine the proper cycle cost.
     */
    if (this.model <= X86.MODEL_8088) {
        X86.helpTrap.call(this, X86.EXCEPTION.DE_EXC, 2);
    } else {
        X86.helpFault.call(this, X86.EXCEPTION.DE_EXC, null, 2);
    }
};

/**
 * helpInterrupt(nIDT, nCycles)
 *
 * Helper to dispatch external interrupts.  nCycles defaults to 11 for the 8086/8088
 * if no alternate value is specified.
 *
 * @this {CPUx86}
 * @param {number} nIDT
 * @param {number} [nCycles] (number of cycles in addition to the default of nOpCyclesInt)
 */
X86.helpInterrupt = function(nIDT, nCycles)
{
    this.nFault = nIDT;
    if (nCycles === undefined) nCycles = 11;
    X86.helpINT.call(this, nIDT, null, nCycles);
};

/**
 * helpTrap(nIDT, nCycles)
 *
 * Helper to dispatch traps (ie, exceptions that occur AFTER the instruction, with NO error code)
 *
 * @this {CPUx86}
 * @param {number} nIDT
 * @param {number} [nCycles] (number of cycles in addition to the default of nOpCyclesInt)
 */
X86.helpTrap = function(nIDT, nCycles)
{
    this.nFault = -1;
    X86.helpINT.call(this, nIDT, null, nCycles);
};

/**
 * helpFault(nFault, nError, nCycles, fHalt)
 *
 * Helper to dispatch faults (ie, exceptions that occur DURING an instruction and MAY generate an error code)
 *
 * @this {CPUx86}
 * @param {number} nFault
 * @param {number|null} [nError] (if omitted, no error code will be pushed)
 * @param {number} [nCycles] cycle count to pass through to helpINT(), if any
 * @param {boolean} [fHalt] (true to halt the CPU, false to not, undefined if "it depends")
 */
X86.helpFault = function(nFault, nError, nCycles, fHalt)
{
    let fDispatch = false;

    if (!this.flags.complete) {
        /*
         * Prior to each new burst of instructions, stepCPU() sets fComplete to true, and the only (normal) way
         * for fComplete to become false is through stopCPU(), which isn't ordinarily called, except by the Debugger.
         */
        this.setLIP(this.opLIP);
    }
    else if (this.model >= X86.MODEL_80186) {

        fDispatch = true;

        if (this.nFault < 0) {
            /*
             * Single-fault (error code is passed through, and the responsible instruction is restartable.
             *
             * TODO: The following opCS/opLIP/opSS/opLSP checks are primarily required for 80386-based machines
             * with paging enabled, because page faults introduce a new set of complex faults that our current
             * segment load "probes" are insufficient to catch.  So as a stop-gap measure, we rely on these four
             * "snapshot" registers to resolve the general instruction restartability problem (for now).
             *
             * If you want to closely examine the underlying causes of these more complex faults, set breakpoints
             * where indicated below, and examine the stack trace.
             */
            if (this.opCS != -1) {
                if (this.opCS !== this.segCS.sel) {
                    /*
                     * HACK: We slam the RPL into this.segCS.cpl to ensure that loading the original CS segment doesn't
                     * fail.  For example, if we faulted in the middle of a ring transition that loaded CS with a higher
                     * privilege (lower CPL) code segment, then our attempt here to reload the lower privilege (higher CPL)
                     * code segment could be viewed as a privilege violation (which it would be outside this context).
                     */
                    this.segCS.cpl = this.opCS & 0x3;           // set breakpoint here to inspect complex faults
                    this.setCS(this.opCS);
                }
                this.opCS = -1;
            }
            if (this.opLIP !== this.regLIP) {
                this.setLIP(this.opLIP);                        // set breakpoint here to inspect complex faults

            }
            if (this.opSS != -1) {
                if (this.opSS !== this.segSS.sel) {
                    this.setSS(this.opSS);                      // set breakpoint here to inspect complex faults
                }
                this.opSS = -1;
            }
            if (this.opLSP !== X86.ADDR_INVALID) {
                if (this.opLSP !== this.regLSP) {               // set breakpoint below to inspect complex faults
                    this.setSP((this.regESP & ~this.segSS.maskAddr) | (this.opLSP - this.segSS.base));

                }
                this.opLSP = X86.ADDR_INVALID;
            }
        }
        else if (this.nFault != X86.EXCEPTION.DF_FAULT) {
            /*
             * Double-fault (error code is always zero, and the responsible instruction is not restartable).
             */
            nError = 0;
            nFault = X86.EXCEPTION.DF_FAULT;
        }
        else {
            /*
             * This is a triple-fault (usually referred to in Intel literature as a "shutdown", but it's actually a
             * "reset").  There's nothing to "dispatch" in this case, but we still want to let helpCheckFault() see
             * the triple-fault.  However, regardless what helpCheckFault() returns, we must leave via "throw -1",
             * because we need to blow off whatever context triggered the triple-fault; that was less critical when
             * all we dealt with were 80286-based triple-faults (at least the "normal" triple-faults that OS/2 would
             * generate), but for any other unexpected triple-faults, "dispatching" a throw is critical.
             */
            nError = 0;
            nFault = -1;
            fHalt = false;
            this.resetRegs();
        }
    }

    if (X86.helpCheckFault.call(this, nFault, nError, fHalt) || nFault < 0) {
        /*
         * If this is a fault that would normally be dispatched BUT helpCheckFault() wants us to halt,
         * then we throw a bogus fault number (-1), simply to interrupt the current instruction in exactly
         * the same way that a dispatched fault would interrupt it.
         */
        if (fDispatch) throw -1;
    }

    if (fDispatch) {

        this.nFault = nFault;
        X86.helpINT.call(this, nFault, nError, nCycles);

        /*
         * REP'eated instructions that rewind regLIP to opLIP used to screw up this dispatch,
         * so now we slip the new regLIP into opLIP, effectively turning their action into a no-op.
         */
        this.opLIP = this.regLIP;

        /*
         * X86.OPFLAG.FAULT flag is used by selected opcodes to provide an early exit, restore register(s),
         * or whatever is needed to help ensure instruction restartability; there is currently no general
         * mechanism for snapping and restoring all registers for any instruction that might fault.
         *
         * X86.EXCEPTION.DB_EXC exceptions set their own special flag, X86.OPFLAG.DBEXC, to prevent redundant
         * DEBUG exceptions, so we don't need to set OPFLAG.FAULT in that case, because a DEBUG exception
         * doesn't actually prevent an instruction from executing (and therefore doesn't need to be restarted).
         */
        if (nFault == X86.EXCEPTION.DB_EXC) {
            this.opFlags |= X86.OPFLAG.DBEXC;
        } else {

            this.opFlags |= X86.OPFLAG.FAULT;
        }

        /*
         * Since this fault is likely being issued in the context of an instruction that hasn't finished
         * executing, if we don't do anything to interrupt that execution (eg, throw a JavaScript exception),
         * then we would need to shut off all further reads/writes for the current instruction.
         *
         * That's easy for any EA-based memory accesses: simply set both the NOREAD and NOWRITE flags.
         * However, there are also direct, non-EA-based memory accesses to consider.  A perfect example is
         * opPUSHA(): if a GP fault occurs on any PUSH other than the last, a subsequent PUSH is likely to
         * cause another fault, which we will misinterpret as a double-fault -- unless the handler for
         * such an opcode checks this.opFlags for X86.OPFLAG.FAULT after each step of the operation.
         *
         *      this.opFlags |= (X86.OPFLAG.NOREAD | X86.OPFLAG.NOWRITE);
         *
         * Fortunately, we now throw an exception that terminates the current instruction, so the above hack
         * should no longer be necessary.
         */
        throw nFault;
    }
};

/**
 * helpPageFault(addr, fPresent, fWrite)
 *
 * Helper to dispatch page faults.
 *
 * @this {CPUx86}
 * @param {number} addr
 * @param {boolean} fPresent
 * @param {boolean} fWrite
 */
X86.helpPageFault = function(addr, fPresent, fWrite)
{
    this.regCR2 = addr;
    let nError = 0;
    if (fPresent) nError |= X86.PTE.PRESENT;
    if (fWrite) nError |= X86.PTE.READWRITE;
    if (this.nCPL == 3) nError |= X86.PTE.USER;
    X86.helpFault.call(this, X86.EXCEPTION.PF_FAULT, nError);
};

/**
 * helpCheckFault(nFault, nError, fHalt)
 *
 * Aside from giving the Debugger an opportunity to report every fault, this also gives us the ability to
 * halt exception processing in tracks: return true to prevent the fault handler from being dispatched.
 *
 * At the moment, the only Debugger control you have over fault interception is setting MESSAGE.FAULT, which
 * will display faults as they occur, and MESSAGE.HALT, which will halt after any Debugger message, including
 * MESSAGE.FAULT.  If you want execution to continue after halting, clear MESSAGE.FAULT and/or MESSAGE.HALT,
 * or single-step over the offending instruction, which will allow the fault to be dispatched.
 *
 * @this {CPUx86}
 * @param {number} nFault
 * @param {number|null} [nError] (if omitted, no error code will be reported)
 * @param {boolean} [fHalt] (true to halt the CPU, false to not, undefined if "it depends")
 * @return {boolean|undefined} true to block the fault (often desirable when fHalt is true), otherwise dispatch it
 */
X86.helpCheckFault = function(nFault, nError, fHalt)
{
    let bitsMessage = Messages.FAULT;

    let bOpcode = this.probeAddr(this.regLIP);

    /*
     * OS/2 1.0 uses an INT3 (0xCC) opcode in conjunction with an invalid IDT to trigger a triple-fault
     * reset and return to real-mode, and these resets happen quite frequently during boot; for example,
     * OS/2 startup messages are displayed using a series of INT 0x10 BIOS calls for each character, and
     * each series of BIOS calls requires a round-trip mode switch.
     *
     * Since we really only want to halt on "bad" faults, not "good" (ie, intentional) faults, we take
     * advantage of the fact that all 3 faults comprising the triple-fault point to an INT3 (0xCC) opcode,
     * and so whenever we see that opcode, we ignore the caller's fHalt flag, and suppress FAULT messages
     * unless CPU messages are also enabled.
     *
     * When a triple fault shows up, nFault is -1; it displays as 0xff only because we use toHexByte().
     */
    if (bOpcode == X86.OPCODE.INT3 && !this.addrIDTLimit) {
        fHalt = false;
    }

    /*
     * There are a number of V86-mode exceptions we don't need to know about.  For starters, Windows 3.00
     * (and other versions of enhanced-mode Windows) use an ARPL to switch out of V86-mode, so we can ignore
     * those UD_FAULTs.
     *
     * Ditto for software interrupts, which will generate a GP_FAULT when the interrupt number (eg, 0x6D)
     * exceeds the protected-mode IDT's limit (eg, a limit of 0x2FF corresponds to a maximum interrupt number
     * of 0x5F).  Windows doesn't really care if its IDT is too small, because it has to simulate all software
     * interrupts in V86-mode regardless (they generate a GP_FAULT if IOPL < 3, and even when IOPL == 3, only
     * the protected-mode IDT handler gets to run).
     */
    if (this.regPS & X86.PS.VM) {
        if (nFault == X86.EXCEPTION.UD_FAULT && bOpcode == X86.OPCODE.ARPL ||
            nFault == X86.EXCEPTION.GP_FAULT && bOpcode == X86.OPCODE.INTN) {
            fHalt = false;
        }
    }
    // else if (DEBUG && nFault == X86.EXCEPTION.GP_FAULT && fHalt === undefined) fHalt = true;

    /*
     * If fHalt has been explicitly set to false, we also take that as a cue to disable fault messages
     * (which you can override by turning on CPU messages).
     */
    if (fHalt === false) {
        bitsMessage |= Messages.CPU;
    }

    /*
     * Similarly, the PC AT ROM BIOS deliberately generates a couple of GP faults as part of the POST
     * (Power-On Self Test); we don't want to ignore those, but we don't want to halt on them either.  We
     * detect those faults by virtue of the LIP being in the range 0x0F0000 to 0x0FFFFF.
     *
     * TODO: Be aware that this test can trigger false positives, such as when a V86-mode ARPL is hit; eg:
     *
     *      &FD82:22F7 6338            ARPL     [BX+SI],DI
     */
    if (this.regLIP >= 0x0F0000 && this.regLIP <= 0x0FFFFF) {
        fHalt = false;
    }

    /*
     * However, the foregoing notwithstanding, if MESSAGE.HALT is enabled along with all the other required
     * MESSAGE bits, then we want to halt regardless.
     */
    if (this.messageEnabled(bitsMessage + Messages.HALT)) {
        fHalt = true;
    }

    if (this.messageEnabled(bitsMessage) || fHalt) {

        let fRunning = this.flags.running;
        let sMessage = "Fault " + Str.toHexByte(nFault) + (nError != null? " (" + Str.toHexWord(nError) + ")" : "") + " on opcode " + Str.toHexByte(bOpcode);
        if (fHalt && fRunning) sMessage += " (blocked)";

        if (DEBUGGER && this.dbg) {
            this.printMessage(sMessage, fHalt || bitsMessage, true);
            if (fHalt) {
                /*
                 * By setting fHalt to fRunning (which is true while running but false while single-stepping),
                 * this allows a fault to be dispatched when you single-step over a faulting instruction; you can
                 * then continue single-stepping into the fault handler, or start running again.
                 *
                 * Note that we had to capture fRunning before calling printMessage(), because if MESSAGE.HALT
                 * is set, printMessage() will have already halted the CPU.
                 */
                fHalt = fRunning;
                this.dbg.stopCPU();
            }
        } else {
            /*
             * If there's no Debugger, then messageEnabled() must have returned false, which means that fHalt must
             * be true.  Which means we should shut the machine down.
             */

            this.notice(sMessage);
            this.stopCPU();
        }
    }
    return fHalt;
};

/**
 * zeroSeg(seg)
 *
 * Helper to zero a segment register whenever transitioning to a less privileged (numerically higher) level.
 *
 * @this {CPUx86}
 * @param {SegX86} seg
 */
X86.zeroSeg = function(seg)
{
    let acc = seg.acc & X86.DESC.ACC.TYPE.CODE_OR_DATA;
    if (seg.sel & X86.SEL.MASK) {
        if (acc == X86.DESC.ACC.TYPE.CODE_EXECONLY ||           // non-readable code segment (not allowed)
            acc == X86.DESC.ACC.TYPE.CODE_CONFORMING ||         // non-readable code segment (not allowed)
            acc < X86.DESC.ACC.TYPE.CODE_CONFORMING && seg.dpl < this.nCPL && seg.dpl < (seg.sel & X86.SEL.RPL)) {
            seg.load(0);
        }
    }
};

/**
 * @copyright https://www.pcjs.org/machines/pcx86/lib/x86mods.js (C) 2012-2021 Jeff Parsons
 */


/*
 * Before 80386 support was added to PCx86, the approach to decoding ModRegRM bytes (which I usually
 * just call ModRM bytes) used one generated function per ModRM value.  This was optimal for 16-bit processors,
 * because the functions were small, and it was maximally efficient, turning the entire ModRM decoding operation
 * into one table lookup and function call.
 *
 * However, that approach didn't scale well for 32-bit processors, which had extended ModRM capabilities in both
 * the addressing mode dimension and the operand size dimension.  So I've rewritten ModRM decoding as 18 functions.
 * The first 9 are for 16-bit addressing modes, and the second 9 are for 32-bit addressing modes.  Within each
 * group of 9, there are 3 for 8-bit operands, 3 for 16-bit operands, and 3 for 32-bit operands.  And each group of 3
 * contains functions for register-source, memory-source, and group-source.
 *
 * Each of the 18 functions must do additional work to examine the ModRM bits, which makes decoding slightly slower,
 * but it's not really noticeable, and the speed difference didn't justify the additional generated code.  So one much
 * smaller file (x86mods.js) replaces a host of older files (x86modb.js, x86modw.js, x86modb16.js, x86modw16.js,
 * x86modb32.js, x86modw32.js, and x86modsib.js).
 *
 * You can dig up the older files from the repository if you're curious, or you can run /modules/pcx86/bin/x86gen.js to
 * get a sense of what they contained (x86gen.js created most of the code, but it still had to be massaged afterward).
 */

/**
 * modRegByte16(fn)
 *
 * @this {CPUx86}
 * @param {function(number,number)} fn (dst,src)
 */
X86.modRegByte16 = function(fn)
{
    let dst, src;
    let bModRM = (this.bModRM = this.getIPByte()) & 0xC7;

    switch(bModRM) {
    case 0x00:
        src = this.getEAByteData(this.regEBX + this.regESI);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndex;
        break;
    case 0x01:
        src = this.getEAByteData(this.regEBX + this.regEDI);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexExtra;
        break;
    case 0x02:
        src = this.getEAByteStack(this.regEBP + this.regESI);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexExtra;
        break;
    case 0x03:
        src = this.getEAByteStack(this.regEBP + this.regEDI);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndex;
        break;
    case 0x04:
        src = this.getEAByteData(this.regESI);
        this.nStepCycles -= this.cycleCounts.nEACyclesBase;
        break;
    case 0x05:
        src = this.getEAByteData(this.regEDI);
        this.nStepCycles -= this.cycleCounts.nEACyclesBase;
        break;
    case 0x06:
        src = this.getEAByteData(this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesDisp;
        break;
    case 0x07:
        src = this.getEAByteData(this.regEBX);
        this.nStepCycles -= this.cycleCounts.nEACyclesBase;
        break;
    case 0x40:
        src = this.getEAByteData(this.regEBX + this.regESI + this.getIPDisp());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDisp;
        break;
    case 0x41:
        src = this.getEAByteData(this.regEBX + this.regEDI + this.getIPDisp());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDispExtra;
        break;
    case 0x42:
        src = this.getEAByteStack(this.regEBP + this.regESI + this.getIPDisp());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDispExtra;
        break;
    case 0x43:
        src = this.getEAByteStack(this.regEBP + this.regEDI + this.getIPDisp());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDisp;
        break;
    case 0x44:
        src = this.getEAByteData(this.regESI + this.getIPDisp());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0x45:
        src = this.getEAByteData(this.regEDI + this.getIPDisp());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0x46:
        src = this.getEAByteStack(this.regEBP + this.getIPDisp());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0x47:
        src = this.getEAByteData(this.regEBX + this.getIPDisp());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0x80:
        src = this.getEAByteData(this.regEBX + this.regESI + this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDisp;
        break;
    case 0x81:
        src = this.getEAByteData(this.regEBX + this.regEDI + this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDispExtra;
        break;
    case 0x82:
        src = this.getEAByteStack(this.regEBP + this.regESI + this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDispExtra;
        break;
    case 0x83:
        src = this.getEAByteStack(this.regEBP + this.regEDI + this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDisp;
        break;
    case 0x84:
        src = this.getEAByteData(this.regESI + this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0x85:
        src = this.getEAByteData(this.regEDI + this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0x86:
        src = this.getEAByteStack(this.regEBP + this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0x87:
        src = this.getEAByteData(this.regEBX + this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0xC0:
        src = this.regEAX & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiAL;
        break;
    case 0xC1:
        src = this.regECX & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiCL;
        break;
    case 0xC2:
        src = this.regEDX & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiDL;
        break;
    case 0xC3:
        src = this.regEBX & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiBL;
        break;
    case 0xC4:
        src = (this.regEAX >> 8) & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiAH;
        break;
    case 0xC5:
        src = (this.regECX >> 8) & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiCH;
        break;
    case 0xC6:
        src = (this.regEDX >> 8) & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiDH;
        break;
    case 0xC7:
        src = (this.regEBX >> 8) & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiBH;
        break;
    default:
        src = 0;

        break;
    }

    let reg = (this.bModRM >> 3) & 0x7;

    switch(reg) {
    case 0x0:
        dst = this.regEAX & 0xff;
        break;
    case 0x1:
        dst = this.regECX & 0xff;
        break;
    case 0x2:
        dst = this.regEDX & 0xff;
        break;
    case 0x3:
        dst = this.regEBX & 0xff;
        break;
    case 0x4:
        dst = (this.regEAX >> 8) & 0xff;
        break;
    case 0x5:
        dst = (this.regECX >> 8) & 0xff;
        break;
    case 0x6:
        dst = (this.regEDX >> 8) & 0xff;
        break;
    case 0x7:
        dst = (this.regEBX >> 8) & 0xff;
        break;
    default:
        dst = 0;
        break;
    }

    let b = fn.call(this, dst, src);

    switch(reg) {
    case 0x0:
        this.regEAX = (this.regEAX & ~0xff) | b;
        if (BACKTRACK) this.backTrack.btiAL = this.backTrack.btiEALo;
        break;
    case 0x1:
        this.regECX = (this.regECX & ~0xff) | b;
        if (BACKTRACK) this.backTrack.btiCL = this.backTrack.btiEALo;
        break;
    case 0x2:
        this.regEDX = (this.regEDX & ~0xff) | b;
        if (BACKTRACK) this.backTrack.btiDL = this.backTrack.btiEALo;
        break;
    case 0x3:
        this.regEBX = (this.regEBX & ~0xff) | b;
        if (BACKTRACK) this.backTrack.btiBL = this.backTrack.btiEALo;
        break;
    case 0x4:
        this.regEAX = (this.regEAX & ~0xff00) | (b << 8);
        if (BACKTRACK) this.backTrack.btiAH = this.backTrack.btiEALo;
        break;
    case 0x5:
        this.regECX = (this.regECX & ~0xff00) | (b << 8);
        if (BACKTRACK) this.backTrack.btiCH = this.backTrack.btiEALo;
        break;
    case 0x6:
        this.regEDX = (this.regEDX & ~0xff00) | (b << 8);
        if (BACKTRACK) this.backTrack.btiDH = this.backTrack.btiEALo;
        break;
    case 0x7:
        this.regEBX = (this.regEBX & ~0xff00) | (b << 8);
        if (BACKTRACK) this.backTrack.btiBH = this.backTrack.btiEALo;
        break;
    }
};

/**
 * modMemByte16(fn)
 *
 * @this {CPUx86}
 * @param {function(number,number)} fn (dst,src)
 */
X86.modMemByte16 = function(fn)
{
    let dst, src;
    let bModRM = (this.bModRM = this.getIPByte()) & 0xC7;

    switch(bModRM) {
    case 0x00:
        dst = this.getEAByteData(this.regEBX + this.regESI);
        this.regEAWrite = this.regEA;
        break;
    case 0x01:
        dst = this.getEAByteData(this.regEBX + this.regEDI);
        this.regEAWrite = this.regEA;
        break;
    case 0x02:
        dst = this.getEAByteStack(this.regEBP + this.regESI);
        this.regEAWrite = this.regEA;
        break;
    case 0x03:
        dst = this.getEAByteStack(this.regEBP + this.regEDI);
        this.regEAWrite = this.regEA;
        break;
    case 0x04:
        dst = this.getEAByteData(this.regESI);
        this.regEAWrite = this.regEA;
        break;
    case 0x05:
        dst = this.getEAByteData(this.regEDI);
        this.regEAWrite = this.regEA;
        break;
    case 0x06:
        dst = this.getEAByteData(this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x07:
        dst = this.getEAByteData(this.regEBX);
        this.regEAWrite = this.regEA;
        break;
    case 0x40:
        dst = this.getEAByteData(this.regEBX + this.regESI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x41:
        dst = this.getEAByteData(this.regEBX + this.regEDI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x42:
        dst = this.getEAByteStack(this.regEBP + this.regESI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x43:
        dst = this.getEAByteStack(this.regEBP + this.regEDI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x44:
        dst = this.getEAByteData(this.regESI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x45:
        dst = this.getEAByteData(this.regEDI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x46:
        dst = this.getEAByteStack(this.regEBP + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x47:
        dst = this.getEAByteData(this.regEBX + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x80:
        dst = this.getEAByteData(this.regEBX + this.regESI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x81:
        dst = this.getEAByteData(this.regEBX + this.regEDI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x82:
        dst = this.getEAByteStack(this.regEBP + this.regESI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x83:
        dst = this.getEAByteStack(this.regEBP + this.regEDI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x84:
        dst = this.getEAByteData(this.regESI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x85:
        dst = this.getEAByteData(this.regEDI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x86:
        dst = this.getEAByteStack(this.regEBP + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x87:
        dst = this.getEAByteData(this.regEBX + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0xC0:
        dst = this.regEAX & 0xff;
        break;
    case 0xC1:
        dst = this.regECX & 0xff;
        break;
    case 0xC2:
        dst = this.regEDX & 0xff;
        break;
    case 0xC3:
        dst = this.regEBX & 0xff;
        break;
    case 0xC4:
        dst = (this.regEAX >> 8) & 0xff;
        break;
    case 0xC5:
        dst = (this.regECX >> 8) & 0xff;
        break;
    case 0xC6:
        dst = (this.regEDX >> 8) & 0xff;
        break;
    case 0xC7:
        dst = (this.regEBX >> 8) & 0xff;
        break;
    default:
        dst = 0;

        break;
    }

    let reg = (this.bModRM >> 3) & 0x7;

    switch(reg) {
    case 0x0:
        src = this.regEAX & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiAL;
        break;
    case 0x1:
        src = this.regECX & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiCL;
        break;
    case 0x2:
        src = this.regEDX & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiDL;
        break;
    case 0x3:
        src = this.regEBX & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiBL;
        break;
    case 0x4:
        src = (this.regEAX >> 8) & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiAH;
        break;
    case 0x5:
        src = (this.regECX >> 8) & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiCH;
        break;
    case 0x6:
        src = (this.regEDX >> 8) & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiDH;
        break;
    case 0x7:
        src = (this.regEBX >> 8) & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiBH;
        break;
    default:
        src = 0;
        break;
    }

    let b = fn.call(this, dst, src);

    switch(bModRM) {
    case 0x00:
    case 0x03:
        this.setEAByte(b);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndex;
        break;
    case 0x01:
    case 0x02:
        this.setEAByte(b);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexExtra;
        break;
    case 0x04:
    case 0x05:
    case 0x07:
        this.setEAByte(b);
        this.nStepCycles -= this.cycleCounts.nEACyclesBase;
        break;
    case 0x06:
        this.setEAByte(b);
        this.nStepCycles -= this.cycleCounts.nEACyclesDisp;
        break;
    case 0x40:
    case 0x43:
    case 0x80:
    case 0x83:
        this.setEAByte(b);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDisp;
        break;
    case 0x41:
    case 0x42:
    case 0x81:
    case 0x82:
        this.setEAByte(b);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDispExtra;
        break;
    case 0x44:
    case 0x45:
    case 0x46:
    case 0x47:
    case 0x84:
    case 0x85:
    case 0x86:
    case 0x87:
        this.setEAByte(b);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0xC0:
        this.regEAX = (this.regEAX & ~0xff) | b;
        if (BACKTRACK) this.backTrack.btiAL = this.backTrack.btiEALo;
        break;
    case 0xC1:
        this.regECX = (this.regECX & ~0xff) | b;
        if (BACKTRACK) this.backTrack.btiCL = this.backTrack.btiEALo;
        break;
    case 0xC2:
        this.regEDX = (this.regEDX & ~0xff) | b;
        if (BACKTRACK) this.backTrack.btiDL = this.backTrack.btiEALo;
        break;
    case 0xC3:
        this.regEBX = (this.regEBX & ~0xff) | b;
        if (BACKTRACK) this.backTrack.btiBL = this.backTrack.btiEALo;
        break;
    case 0xC4:
        this.regEAX = (this.regEAX & ~0xff00) | (b << 8);
        if (BACKTRACK) this.backTrack.btiAH = this.backTrack.btiEALo;
        break;
    case 0xC5:
        this.regECX = (this.regECX & ~0xff00) | (b << 8);
        if (BACKTRACK) this.backTrack.btiCH = this.backTrack.btiEALo;
        break;
    case 0xC6:
        this.regEDX = (this.regEDX & ~0xff00) | (b << 8);
        if (BACKTRACK) this.backTrack.btiDH = this.backTrack.btiEALo;
        break;
    case 0xC7:
        this.regEBX = (this.regEBX & ~0xff00) | (b << 8);
        if (BACKTRACK) this.backTrack.btiBH = this.backTrack.btiEALo;
        break;
    default:

        break;
    }
};

/**
 * modGrpByte16(afnGrp, fnSrc)
 *
 * @this {CPUx86}
 * @param {Array.<function(number,number)>} afnGrp
 * @param {function()} fnSrc
 */
X86.modGrpByte16 = function(afnGrp, fnSrc)
{
    let dst;
    let bModRM = (this.bModRM = this.getIPByte()) & 0xC7;

    switch(bModRM) {
    case 0x00:
        dst = this.getEAByteData(this.regEBX + this.regESI);
        this.regEAWrite = this.regEA;
        break;
    case 0x01:
        dst = this.getEAByteData(this.regEBX + this.regEDI);
        this.regEAWrite = this.regEA;
        break;
    case 0x02:
        dst = this.getEAByteStack(this.regEBP + this.regESI);
        this.regEAWrite = this.regEA;
        break;
    case 0x03:
        dst = this.getEAByteStack(this.regEBP + this.regEDI);
        this.regEAWrite = this.regEA;
        break;
    case 0x04:
        dst = this.getEAByteData(this.regESI);
        this.regEAWrite = this.regEA;
        break;
    case 0x05:
        dst = this.getEAByteData(this.regEDI);
        this.regEAWrite = this.regEA;
        break;
    case 0x06:
        dst = this.getEAByteData(this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x07:
        dst = this.getEAByteData(this.regEBX);
        this.regEAWrite = this.regEA;
        break;
    case 0x40:
        dst = this.getEAByteData(this.regEBX + this.regESI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x41:
        dst = this.getEAByteData(this.regEBX + this.regEDI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x42:
        dst = this.getEAByteStack(this.regEBP + this.regESI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x43:
        dst = this.getEAByteStack(this.regEBP + this.regEDI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x44:
        dst = this.getEAByteData(this.regESI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x45:
        dst = this.getEAByteData(this.regEDI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x46:
        dst = this.getEAByteStack(this.regEBP + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x47:
        dst = this.getEAByteData(this.regEBX + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x80:
        dst = this.getEAByteData(this.regEBX + this.regESI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x81:
        dst = this.getEAByteData(this.regEBX + this.regEDI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x82:
        dst = this.getEAByteStack(this.regEBP + this.regESI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x83:
        dst = this.getEAByteStack(this.regEBP + this.regEDI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x84:
        dst = this.getEAByteData(this.regESI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x85:
        dst = this.getEAByteData(this.regEDI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x86:
        dst = this.getEAByteStack(this.regEBP + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x87:
        dst = this.getEAByteData(this.regEBX + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0xC0:
        dst = this.regEAX & 0xff;
        break;
    case 0xC1:
        dst = this.regECX & 0xff;
        break;
    case 0xC2:
        dst = this.regEDX & 0xff;
        break;
    case 0xC3:
        dst = this.regEBX & 0xff;
        break;
    case 0xC4:
        dst = (this.regEAX >> 8) & 0xff;
        break;
    case 0xC5:
        dst = (this.regECX >> 8) & 0xff;
        break;
    case 0xC6:
        dst = (this.regEDX >> 8) & 0xff;
        break;
    case 0xC7:
        dst = (this.regEBX >> 8) & 0xff;
        break;
    default:
        dst = 0;

        break;
    }

    let reg = (this.bModRM >> 3) & 0x7;

    let b = afnGrp[reg].call(this, dst, fnSrc.call(this));

    switch(bModRM) {
    case 0x00:
    case 0x03:
        this.setEAByte(b);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndex;
        break;
    case 0x01:
    case 0x02:
        this.setEAByte(b);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexExtra;
        break;
    case 0x04:
    case 0x05:
    case 0x07:
        this.setEAByte(b);
        this.nStepCycles -= this.cycleCounts.nEACyclesBase;
        break;
    case 0x06:
        this.setEAByte(b);
        this.nStepCycles -= this.cycleCounts.nEACyclesDisp;
        break;
    case 0x40:
    case 0x43:
    case 0x80:
    case 0x83:
        this.setEAByte(b);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDisp;
        break;
    case 0x41:
    case 0x42:
    case 0x81:
    case 0x82:
        this.setEAByte(b);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDispExtra;
        break;
    case 0x44:
    case 0x45:
    case 0x46:
    case 0x47:
    case 0x84:
    case 0x85:
    case 0x86:
    case 0x87:
        this.setEAByte(b);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0xC0:
        this.regEAX = (this.regEAX & ~0xff) | b;
        break;
    case 0xC1:
        this.regECX = (this.regECX & ~0xff) | b;
        break;
    case 0xC2:
        this.regEDX = (this.regEDX & ~0xff) | b;
        break;
    case 0xC3:
        this.regEBX = (this.regEBX & ~0xff) | b;
        break;
    case 0xC4:
        this.regEAX = (this.regEAX & ~0xff00) | (b << 8);
        break;
    case 0xC5:
        this.regECX = (this.regECX & ~0xff00) | (b << 8);
        break;
    case 0xC6:
        this.regEDX = (this.regEDX & ~0xff00) | (b << 8);
        break;
    case 0xC7:
        this.regEBX = (this.regEBX & ~0xff00) | (b << 8);
        break;
    }
};

/**
 * modRegShort16(fn)
 *
 * @this {CPUx86}
 * @param {function(number,number)} fn (dst,src)
 */
X86.modRegShort16 = function(fn)
{
    let dst, src;
    let bModRM = (this.bModRM = this.getIPByte()) & 0xC7;

    switch(bModRM) {
    case 0x00:
        src = this.getEAShortData(this.regEBX + this.regESI);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndex;
        break;
    case 0x01:
        src = this.getEAShortData(this.regEBX + this.regEDI);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexExtra;
        break;
    case 0x02:
        src = this.getEAShortStack(this.regEBP + this.regESI);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexExtra;
        break;
    case 0x03:
        src = this.getEAShortStack(this.regEBP + this.regEDI);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndex;
        break;
    case 0x04:
        src = this.getEAShortData(this.regESI);
        this.nStepCycles -= this.cycleCounts.nEACyclesBase;
        break;
    case 0x05:
        src = this.getEAShortData(this.regEDI);
        this.nStepCycles -= this.cycleCounts.nEACyclesBase;
        break;
    case 0x06:
        src = this.getEAShortData(this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesDisp;
        break;
    case 0x07:
        src = this.getEAShortData(this.regEBX);
        this.nStepCycles -= this.cycleCounts.nEACyclesBase;
        break;
    case 0x40:
        src = this.getEAShortData(this.regEBX + this.regESI + this.getIPDisp());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDisp;
        break;
    case 0x41:
        src = this.getEAShortData(this.regEBX + this.regEDI + this.getIPDisp());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDispExtra;
        break;
    case 0x42:
        src = this.getEAShortStack(this.regEBP + this.regESI + this.getIPDisp());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDispExtra;
        break;
    case 0x43:
        src = this.getEAShortStack(this.regEBP + this.regEDI + this.getIPDisp());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDisp;
        break;
    case 0x44:
        src = this.getEAShortData(this.regESI + this.getIPDisp());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0x45:
        src = this.getEAShortData(this.regEDI + this.getIPDisp());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0x46:
        src = this.getEAShortStack(this.regEBP + this.getIPDisp());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0x47:
        src = this.getEAShortData(this.regEBX + this.getIPDisp());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0x80:
        src = this.getEAShortData(this.regEBX + this.regESI + this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDisp;
        break;
    case 0x81:
        src = this.getEAShortData(this.regEBX + this.regEDI + this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDispExtra;
        break;
    case 0x82:
        src = this.getEAShortStack(this.regEBP + this.regESI + this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDispExtra;
        break;
    case 0x83:
        src = this.getEAShortStack(this.regEBP + this.regEDI + this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDisp;
        break;
    case 0x84:
        src = this.getEAShortData(this.regESI + this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0x85:
        src = this.getEAShortData(this.regEDI + this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0x86:
        src = this.getEAShortStack(this.regEBP + this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0x87:
        src = this.getEAShortData(this.regEBX + this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0xC0:
        src = this.regEAX & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiAL; this.backTrack.btiEAHi = this.backTrack.btiAH;
        }
        break;
    case 0xC1:
        src = this.regECX & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiCL; this.backTrack.btiEAHi = this.backTrack.btiCH;
        }
        break;
    case 0xC2:
        src = this.regEDX & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiDL; this.backTrack.btiEAHi = this.backTrack.btiDH;
        }
        break;
    case 0xC3:
        src = this.regEBX & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiBL; this.backTrack.btiEAHi = this.backTrack.btiBH;
        }
        break;
    case 0xC4:
        src = this.getSP() & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = X86.BTINFO.SP_LO; this.backTrack.btiEAHi = X86.BTINFO.SP_HI;
        }
        break;
    case 0xC5:
        src = this.regEBP & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiBPLo; this.backTrack.btiEAHi = this.backTrack.btiBPHi;
        }
        break;
    case 0xC6:
        src = this.regESI & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiSILo; this.backTrack.btiEAHi = this.backTrack.btiSIHi;
        }
        break;
    case 0xC7:
        src = this.regEDI & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiDILo; this.backTrack.btiEAHi = this.backTrack.btiDIHi;
        }
        break;
    default:
        src = 0;

        break;
    }

    let reg = (this.bModRM >> 3) & 0x7;

    switch(reg) {
    case 0x0:
        dst = this.regEAX & 0xffff;
        break;
    case 0x1:
        dst = this.regECX & 0xffff;
        break;
    case 0x2:
        dst = this.regEDX & 0xffff;
        break;
    case 0x3:
        dst = this.regEBX & 0xffff;
        break;
    case 0x4:
        dst = this.getSP() & 0xffff;
        break;
    case 0x5:
        dst = this.regEBP & 0xffff;
        break;
    case 0x6:
        dst = this.regESI & 0xffff;
        break;
    case 0x7:
        dst = this.regEDI & 0xffff;
        break;
    default:
        dst = 0;
        break;
    }

    let w = fn.call(this, dst, src);

    switch(reg) {
    case 0x0:
        this.regEAX = (this.regEAX & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiAL = this.backTrack.btiEALo; this.backTrack.btiAH = this.backTrack.btiEAHi;
        }
        break;
    case 0x1:
        this.regECX = (this.regECX & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiCL = this.backTrack.btiEALo; this.backTrack.btiCH = this.backTrack.btiEAHi;
        }
        break;
    case 0x2:
        this.regEDX = (this.regEDX & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiDL = this.backTrack.btiEALo; this.backTrack.btiDH = this.backTrack.btiEAHi;
        }
        break;
    case 0x3:
        this.regEBX = (this.regEBX & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiBL = this.backTrack.btiEALo; this.backTrack.btiBH = this.backTrack.btiEAHi;
        }
        break;
    case 0x4:
        this.setSP((this.getSP() & ~0xffff) | w);
        break;
    case 0x5:
        this.regEBP = (this.regEBP & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiBPLo = this.backTrack.btiEALo; this.backTrack.btiBPHi = this.backTrack.btiEAHi;
        }
        break;
    case 0x6:
        this.regESI = (this.regESI & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiSILo = this.backTrack.btiEALo; this.backTrack.btiSIHi = this.backTrack.btiEAHi;
        }
        break;
    case 0x7:
        this.regEDI = (this.regEDI & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiDILo = this.backTrack.btiEALo; this.backTrack.btiDIHi = this.backTrack.btiEAHi;
        }
        break;
    }
};

/**
 * modMemShort16(fn)
 *
 * @this {CPUx86}
 * @param {function(number,number)} fn (dst,src)
 */
X86.modMemShort16 = function(fn)
{
    let dst, src;
    let bModRM = (this.bModRM = this.getIPByte()) & 0xC7;

    switch(bModRM) {
    case 0x00:
        dst = this.getEAShortData(this.regEBX + this.regESI);
        this.regEAWrite = this.regEA;
        break;
    case 0x01:
        dst = this.getEAShortData(this.regEBX + this.regEDI);
        this.regEAWrite = this.regEA;
        break;
    case 0x02:
        dst = this.getEAShortStack(this.regEBP + this.regESI);
        this.regEAWrite = this.regEA;
        break;
    case 0x03:
        dst = this.getEAShortStack(this.regEBP + this.regEDI);
        this.regEAWrite = this.regEA;
        break;
    case 0x04:
        dst = this.getEAShortData(this.regESI);
        this.regEAWrite = this.regEA;
        break;
    case 0x05:
        dst = this.getEAShortData(this.regEDI);
        this.regEAWrite = this.regEA;
        break;
    case 0x06:
        dst = this.getEAShortData(this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x07:
        dst = this.getEAShortData(this.regEBX);
        this.regEAWrite = this.regEA;
        break;
    case 0x40:
        dst = this.getEAShortData(this.regEBX + this.regESI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x41:
        dst = this.getEAShortData(this.regEBX + this.regEDI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x42:
        dst = this.getEAShortStack(this.regEBP + this.regESI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x43:
        dst = this.getEAShortStack(this.regEBP + this.regEDI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x44:
        dst = this.getEAShortData(this.regESI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x45:
        dst = this.getEAShortData(this.regEDI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x46:
        dst = this.getEAShortStack(this.regEBP + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x47:
        dst = this.getEAShortData(this.regEBX + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x80:
        dst = this.getEAShortData(this.regEBX + this.regESI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x81:
        dst = this.getEAShortData(this.regEBX + this.regEDI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x82:
        dst = this.getEAShortStack(this.regEBP + this.regESI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x83:
        dst = this.getEAShortStack(this.regEBP + this.regEDI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x84:
        dst = this.getEAShortData(this.regESI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x85:
        dst = this.getEAShortData(this.regEDI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x86:
        dst = this.getEAShortStack(this.regEBP + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x87:
        dst = this.getEAShortData(this.regEBX + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0xC0:
        dst = this.regEAX & 0xffff;
        break;
    case 0xC1:
        dst = this.regECX & 0xffff;
        break;
    case 0xC2:
        dst = this.regEDX & 0xffff;
        break;
    case 0xC3:
        dst = this.regEBX & 0xffff;
        break;
    case 0xC4:
        dst = this.getSP() & 0xffff;
        break;
    case 0xC5:
        dst = this.regEBP & 0xffff;
        break;
    case 0xC6:
        dst = this.regESI & 0xffff;
        break;
    case 0xC7:
        dst = this.regEDI & 0xffff;
        break;
    default:
        dst = 0;

        break;
    }

    let reg = (this.bModRM >> 3) & 0x7;

    switch(reg) {
    case 0x0:
        src = this.regEAX & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiAL; this.backTrack.btiEAHi = this.backTrack.btiAH;
        }
        break;
    case 0x1:
        src = this.regECX & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiCL; this.backTrack.btiEAHi = this.backTrack.btiCH;
        }
        break;
    case 0x2:
        src = this.regEDX & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiDL; this.backTrack.btiEAHi = this.backTrack.btiDH;
        }
        break;
    case 0x3:
        src = this.regEBX & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiBL; this.backTrack.btiEAHi = this.backTrack.btiBH;
        }
        break;
    case 0x4:
        src = this.getSP() & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = X86.BTINFO.SP_LO; this.backTrack.btiEAHi = X86.BTINFO.SP_HI;
        }
        break;
    case 0x5:
        src = this.regEBP & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiBPLo; this.backTrack.btiEAHi = this.backTrack.btiBPHi;
        }
        break;
    case 0x6:
        src = this.regESI & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiSILo; this.backTrack.btiEAHi = this.backTrack.btiSIHi;
        }
        break;
    case 0x7:
        src = this.regEDI & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiDILo; this.backTrack.btiEAHi = this.backTrack.btiDIHi;
        }
        break;
    default:
        src = 0;
        break;
    }

    let w = fn.call(this, dst, src);

    switch(bModRM) {
    case 0x00:
    case 0x03:
        this.setEAShort(w);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndex;
        break;
    case 0x01:
    case 0x02:
        this.setEAShort(w);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexExtra;
        break;
    case 0x04:
    case 0x05:
    case 0x07:
        this.setEAShort(w);
        this.nStepCycles -= this.cycleCounts.nEACyclesBase;
        break;
    case 0x06:
        this.setEAShort(w);
        this.nStepCycles -= this.cycleCounts.nEACyclesDisp;
        break;
    case 0x40:
    case 0x43:
    case 0x80:
    case 0x83:
        this.setEAShort(w);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDisp;
        break;
    case 0x41:
    case 0x42:
    case 0x81:
    case 0x82:
        this.setEAShort(w);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDispExtra;
        break;
    case 0x44:
    case 0x45:
    case 0x46:
    case 0x47:
    case 0x84:
    case 0x85:
    case 0x86:
    case 0x87:
        this.setEAShort(w);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0xC0:
        this.regEAX = (this.regEAX & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiAL = this.backTrack.btiEALo; this.backTrack.btiAH = this.backTrack.btiEAHi;
        }
        break;
    case 0xC1:
        this.regECX = (this.regECX & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiCL = this.backTrack.btiEALo; this.backTrack.btiCH = this.backTrack.btiEAHi;
        }
        break;
    case 0xC2:
        this.regEDX = (this.regEDX & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiDL = this.backTrack.btiEALo; this.backTrack.btiDH = this.backTrack.btiEAHi;
        }
        break;
    case 0xC3:
        this.regEBX = (this.regEBX & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiBL = this.backTrack.btiEALo; this.backTrack.btiBH = this.backTrack.btiEAHi;
        }
        break;
    case 0xC4:
        this.setSP((this.getSP() & ~0xffff) | w);
        break;
    case 0xC5:
        this.regEBP = (this.regEBP & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiBPLo = this.backTrack.btiEALo; this.backTrack.btiBPHi = this.backTrack.btiEAHi;
        }
        break;
    case 0xC6:
        this.regESI = (this.regESI & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiSILo = this.backTrack.btiEALo; this.backTrack.btiSIHi = this.backTrack.btiEAHi;
        }
        break;
    case 0xC7:
        this.regEDI = (this.regEDI & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiDILo = this.backTrack.btiEALo; this.backTrack.btiDIHi = this.backTrack.btiEAHi;
        }
        break;
    default:

        break;
    }
};

/**
 * modGrpShort16(afnGrp, fnSrc)
 *
 * @this {CPUx86}
 * @param {Array.<function(number,number)>} afnGrp
 * @param {function()} fnSrc
 */
X86.modGrpShort16 = function(afnGrp, fnSrc)
{
    let dst;
    let bModRM = (this.bModRM = this.getIPByte()) & 0xC7;

    switch(bModRM) {
    case 0x00:
        dst = this.getEAShortData(this.regEBX + this.regESI);
        this.regEAWrite = this.regEA;
        break;
    case 0x01:
        dst = this.getEAShortData(this.regEBX + this.regEDI);
        this.regEAWrite = this.regEA;
        break;
    case 0x02:
        dst = this.getEAShortStack(this.regEBP + this.regESI);
        this.regEAWrite = this.regEA;
        break;
    case 0x03:
        dst = this.getEAShortStack(this.regEBP + this.regEDI);
        this.regEAWrite = this.regEA;
        break;
    case 0x04:
        dst = this.getEAShortData(this.regESI);
        this.regEAWrite = this.regEA;
        break;
    case 0x05:
        dst = this.getEAShortData(this.regEDI);
        this.regEAWrite = this.regEA;
        break;
    case 0x06:
        dst = this.getEAShortData(this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x07:
        dst = this.getEAShortData(this.regEBX);
        this.regEAWrite = this.regEA;
        break;
    case 0x40:
        dst = this.getEAShortData(this.regEBX + this.regESI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x41:
        dst = this.getEAShortData(this.regEBX + this.regEDI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x42:
        dst = this.getEAShortStack(this.regEBP + this.regESI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x43:
        dst = this.getEAShortStack(this.regEBP + this.regEDI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x44:
        dst = this.getEAShortData(this.regESI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x45:
        dst = this.getEAShortData(this.regEDI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x46:
        dst = this.getEAShortStack(this.regEBP + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x47:
        dst = this.getEAShortData(this.regEBX + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x80:
        dst = this.getEAShortData(this.regEBX + this.regESI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x81:
        dst = this.getEAShortData(this.regEBX + this.regEDI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x82:
        dst = this.getEAShortStack(this.regEBP + this.regESI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x83:
        dst = this.getEAShortStack(this.regEBP + this.regEDI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x84:
        dst = this.getEAShortData(this.regESI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x85:
        dst = this.getEAShortData(this.regEDI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x86:
        dst = this.getEAShortStack(this.regEBP + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x87:
        dst = this.getEAShortData(this.regEBX + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0xC0:
        dst = this.regEAX & 0xffff;
        break;
    case 0xC1:
        dst = this.regECX & 0xffff;
        break;
    case 0xC2:
        dst = this.regEDX & 0xffff;
        break;
    case 0xC3:
        dst = this.regEBX & 0xffff;
        break;
    case 0xC4:
        dst = this.getSP() & 0xffff;
        break;
    case 0xC5:
        dst = this.regEBP & 0xffff;
        break;
    case 0xC6:
        dst = this.regESI & 0xffff;
        break;
    case 0xC7:
        dst = this.regEDI & 0xffff;
        break;
    default:
        dst = 0;

        break;
    }

    let reg = (this.bModRM >> 3) & 0x7;

    let w = afnGrp[reg].call(this, dst, fnSrc.call(this));

    switch(bModRM) {
    case 0x00:
    case 0x03:
        this.setEAShort(w);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndex;
        break;
    case 0x01:
    case 0x02:
        this.setEAShort(w);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexExtra;
        break;
    case 0x04:
    case 0x05:
    case 0x07:
        this.setEAShort(w);
        this.nStepCycles -= this.cycleCounts.nEACyclesBase;
        break;
    case 0x06:
        this.setEAShort(w);
        this.nStepCycles -= this.cycleCounts.nEACyclesDisp;
        break;
    case 0x40:
    case 0x43:
    case 0x80:
    case 0x83:
        this.setEAShort(w);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDisp;
        break;
    case 0x41:
    case 0x42:
    case 0x81:
    case 0x82:
        this.setEAShort(w);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDispExtra;
        break;
    case 0x44:
    case 0x45:
    case 0x46:
    case 0x47:
    case 0x84:
    case 0x85:
    case 0x86:
    case 0x87:
        this.setEAShort(w);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0xC0:
        this.regEAX = (this.regEAX & ~0xffff) | w;
        break;
    case 0xC1:
        this.regECX = (this.regECX & ~0xffff) | w;
        break;
    case 0xC2:
        this.regEDX = (this.regEDX & ~0xffff) | w;
        break;
    case 0xC3:
        this.regEBX = (this.regEBX & ~0xffff) | w;
        break;
    case 0xC4:
        this.setSP((this.getSP() & ~0xffff) | w);
        break;
    case 0xC5:
        this.regEBP = (this.regEBP & ~0xffff) | w;
        break;
    case 0xC6:
        this.regESI = (this.regESI & ~0xffff) | w;
        break;
    case 0xC7:
        this.regEDI = (this.regEDI & ~0xffff) | w;
        break;
    }
};

/**
 * modRegLong16(fn)
 *
 * @this {CPUx86}
 * @param {function(number,number)} fn (dst,src)
 */
X86.modRegLong16 = function(fn)
{
    let dst, src;
    let bModRM = (this.bModRM = this.getIPByte()) & 0xC7;

    switch(bModRM) {
    case 0x00:
        src = this.getEALongData(this.regEBX + this.regESI);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndex;
        break;
    case 0x01:
        src = this.getEALongData(this.regEBX + this.regEDI);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexExtra;
        break;
    case 0x02:
        src = this.getEALongStack(this.regEBP + this.regESI);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexExtra;
        break;
    case 0x03:
        src = this.getEALongStack(this.regEBP + this.regEDI);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndex;
        break;
    case 0x04:
        src = this.getEALongData(this.regESI);
        this.nStepCycles -= this.cycleCounts.nEACyclesBase;
        break;
    case 0x05:
        src = this.getEALongData(this.regEDI);
        this.nStepCycles -= this.cycleCounts.nEACyclesBase;
        break;
    case 0x06:
        src = this.getEALongData(this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesDisp;
        break;
    case 0x07:
        src = this.getEALongData(this.regEBX);
        this.nStepCycles -= this.cycleCounts.nEACyclesBase;
        break;
    case 0x40:
        src = this.getEALongData(this.regEBX + this.regESI + this.getIPDisp());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDisp;
        break;
    case 0x41:
        src = this.getEALongData(this.regEBX + this.regEDI + this.getIPDisp());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDispExtra;
        break;
    case 0x42:
        src = this.getEALongStack(this.regEBP + this.regESI + this.getIPDisp());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDispExtra;
        break;
    case 0x43:
        src = this.getEALongStack(this.regEBP + this.regEDI + this.getIPDisp());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDisp;
        break;
    case 0x44:
        src = this.getEALongData(this.regESI + this.getIPDisp());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0x45:
        src = this.getEALongData(this.regEDI + this.getIPDisp());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0x46:
        src = this.getEALongStack(this.regEBP + this.getIPDisp());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0x47:
        src = this.getEALongData(this.regEBX + this.getIPDisp());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0x80:
        src = this.getEALongData(this.regEBX + this.regESI + this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDisp;
        break;
    case 0x81:
        src = this.getEALongData(this.regEBX + this.regEDI + this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDispExtra;
        break;
    case 0x82:
        src = this.getEALongStack(this.regEBP + this.regESI + this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDispExtra;
        break;
    case 0x83:
        src = this.getEALongStack(this.regEBP + this.regEDI + this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDisp;
        break;
    case 0x84:
        src = this.getEALongData(this.regESI + this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0x85:
        src = this.getEALongData(this.regEDI + this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0x86:
        src = this.getEALongStack(this.regEBP + this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0x87:
        src = this.getEALongData(this.regEBX + this.getIPAddr());
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0xC0:
        src = this.regEAX;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiAL; this.backTrack.btiEAHi = this.backTrack.btiAH;
        }
        break;
    case 0xC1:
        src = this.regECX;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiCL; this.backTrack.btiEAHi = this.backTrack.btiCH;
        }
        break;
    case 0xC2:
        src = this.regEDX;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiDL; this.backTrack.btiEAHi = this.backTrack.btiDH;
        }
        break;
    case 0xC3:
        src = this.regEBX;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiBL; this.backTrack.btiEAHi = this.backTrack.btiBH;
        }
        break;
    case 0xC4:
        src = this.getSP();
        if (BACKTRACK) {
            this.backTrack.btiEALo = X86.BTINFO.SP_LO; this.backTrack.btiEAHi = X86.BTINFO.SP_HI;
        }
        break;
    case 0xC5:
        src = this.regEBP;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiBPLo; this.backTrack.btiEAHi = this.backTrack.btiBPHi;
        }
        break;
    case 0xC6:
        src = this.regESI;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiSILo; this.backTrack.btiEAHi = this.backTrack.btiSIHi;
        }
        break;
    case 0xC7:
        src = this.regEDI;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiDILo; this.backTrack.btiEAHi = this.backTrack.btiDIHi;
        }
        break;
    default:
        src = 0;

        break;
    }

    let reg = (this.bModRM >> 3) & 0x7;

    switch(reg) {
    case 0x0:
        dst = this.regEAX;
        break;
    case 0x1:
        dst = this.regECX;
        break;
    case 0x2:
        dst = this.regEDX;
        break;
    case 0x3:
        dst = this.regEBX;
        break;
    case 0x4:
        dst = this.getSP();
        break;
    case 0x5:
        dst = this.regEBP;
        break;
    case 0x6:
        dst = this.regESI;
        break;
    case 0x7:
        dst = this.regEDI;
        break;
    default:
        dst = 0;
        break;
    }

    let l = fn.call(this, dst, src);

    switch(reg) {
    case 0x0:
        this.regEAX = l;
        if (BACKTRACK) {
            this.backTrack.btiAL = this.backTrack.btiEALo; this.backTrack.btiAH = this.backTrack.btiEAHi;
        }
        break;
    case 0x1:
        this.regECX = l;
        if (BACKTRACK) {
            this.backTrack.btiCL = this.backTrack.btiEALo; this.backTrack.btiCH = this.backTrack.btiEAHi;
        }
        break;
    case 0x2:
        this.regEDX = l;
        if (BACKTRACK) {
            this.backTrack.btiDL = this.backTrack.btiEALo; this.backTrack.btiDH = this.backTrack.btiEAHi;
        }
        break;
    case 0x3:
        this.regEBX = l;
        if (BACKTRACK) {
            this.backTrack.btiBL = this.backTrack.btiEALo; this.backTrack.btiBH = this.backTrack.btiEAHi;
        }
        break;
    case 0x4:
        this.setSP(l);
        break;
    case 0x5:
        this.regEBP = l;
        if (BACKTRACK) {
            this.backTrack.btiBPLo = this.backTrack.btiEALo; this.backTrack.btiBPHi = this.backTrack.btiEAHi;
        }
        break;
    case 0x6:
        this.regESI = l;
        if (BACKTRACK) {
            this.backTrack.btiSILo = this.backTrack.btiEALo; this.backTrack.btiSIHi = this.backTrack.btiEAHi;
        }
        break;
    case 0x7:
        this.regEDI = l;
        if (BACKTRACK) {
            this.backTrack.btiDILo = this.backTrack.btiEALo; this.backTrack.btiDIHi = this.backTrack.btiEAHi;
        }
        break;
    }
};

/**
 * modMemLong16(fn)
 *
 * @this {CPUx86}
 * @param {function(number,number)} fn (dst,src)
 */
X86.modMemLong16 = function(fn)
{
    let dst, src;
    let bModRM = (this.bModRM = this.getIPByte()) & 0xC7;

    switch(bModRM) {
    case 0x00:
        dst = this.getEALongData(this.regEBX + this.regESI);
        this.regEAWrite = this.regEA;
        break;
    case 0x01:
        dst = this.getEALongData(this.regEBX + this.regEDI);
        this.regEAWrite = this.regEA;
        break;
    case 0x02:
        dst = this.getEALongStack(this.regEBP + this.regESI);
        this.regEAWrite = this.regEA;
        break;
    case 0x03:
        dst = this.getEALongStack(this.regEBP + this.regEDI);
        this.regEAWrite = this.regEA;
        break;
    case 0x04:
        dst = this.getEALongData(this.regESI);
        this.regEAWrite = this.regEA;
        break;
    case 0x05:
        dst = this.getEALongData(this.regEDI);
        this.regEAWrite = this.regEA;
        break;
    case 0x06:
        dst = this.getEALongData(this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x07:
        dst = this.getEALongData(this.regEBX);
        this.regEAWrite = this.regEA;
        break;
    case 0x40:
        dst = this.getEALongData(this.regEBX + this.regESI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x41:
        dst = this.getEALongData(this.regEBX + this.regEDI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x42:
        dst = this.getEALongStack(this.regEBP + this.regESI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x43:
        dst = this.getEALongStack(this.regEBP + this.regEDI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x44:
        dst = this.getEALongData(this.regESI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x45:
        dst = this.getEALongData(this.regEDI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x46:
        dst = this.getEALongStack(this.regEBP + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x47:
        dst = this.getEALongData(this.regEBX + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x80:
        dst = this.getEALongData(this.regEBX + this.regESI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x81:
        dst = this.getEALongData(this.regEBX + this.regEDI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x82:
        dst = this.getEALongStack(this.regEBP + this.regESI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x83:
        dst = this.getEALongStack(this.regEBP + this.regEDI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x84:
        dst = this.getEALongData(this.regESI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x85:
        dst = this.getEALongData(this.regEDI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x86:
        dst = this.getEALongStack(this.regEBP + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x87:
        dst = this.getEALongData(this.regEBX + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0xC0:
        dst = this.regEAX;
        break;
    case 0xC1:
        dst = this.regECX;
        break;
    case 0xC2:
        dst = this.regEDX;
        break;
    case 0xC3:
        dst = this.regEBX;
        break;
    case 0xC4:
        dst = this.getSP();
        break;
    case 0xC5:
        dst = this.regEBP;
        break;
    case 0xC6:
        dst = this.regESI;
        break;
    case 0xC7:
        dst = this.regEDI;
        break;
    default:
        dst = 0;

        break;
    }

    let reg = (this.bModRM >> 3) & 0x7;

    switch(reg) {
    case 0x0:
        src = this.regEAX;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiAL; this.backTrack.btiEAHi = this.backTrack.btiAH;
        }
        break;
    case 0x1:
        src = this.regECX;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiCL; this.backTrack.btiEAHi = this.backTrack.btiCH;
        }
        break;
    case 0x2:
        src = this.regEDX;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiDL; this.backTrack.btiEAHi = this.backTrack.btiDH;
        }
        break;
    case 0x3:
        src = this.regEBX;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiBL; this.backTrack.btiEAHi = this.backTrack.btiBH;
        }
        break;
    case 0x4:
        src = this.getSP();
        if (BACKTRACK) {
            this.backTrack.btiEALo = X86.BTINFO.SP_LO; this.backTrack.btiEAHi = X86.BTINFO.SP_HI;
        }
        break;
    case 0x5:
        src = this.regEBP;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiBPLo; this.backTrack.btiEAHi = this.backTrack.btiBPHi;
        }
        break;
    case 0x6:
        src = this.regESI;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiSILo; this.backTrack.btiEAHi = this.backTrack.btiSIHi;
        }
        break;
    case 0x7:
        src = this.regEDI;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiDILo; this.backTrack.btiEAHi = this.backTrack.btiDIHi;
        }
        break;
    default:
        src = 0;
        break;
    }

    let l = fn.call(this, dst, src);

    switch(bModRM) {
    case 0x00:
    case 0x03:
        this.setEALong(l);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndex;
        break;
    case 0x01:
    case 0x02:
        this.setEALong(l);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexExtra;
        break;
    case 0x04:
    case 0x05:
    case 0x07:
        this.setEALong(l);
        this.nStepCycles -= this.cycleCounts.nEACyclesBase;
        break;
    case 0x06:
        this.setEALong(l);
        this.nStepCycles -= this.cycleCounts.nEACyclesDisp;
        break;
    case 0x40:
    case 0x43:
    case 0x80:
    case 0x83:
        this.setEALong(l);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDisp;
        break;
    case 0x41:
    case 0x42:
    case 0x81:
    case 0x82:
        this.setEALong(l);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDispExtra;
        break;
    case 0x44:
    case 0x45:
    case 0x46:
    case 0x47:
    case 0x84:
    case 0x85:
    case 0x86:
    case 0x87:
        this.setEALong(l);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0xC0:
        this.regEAX = l;
        if (BACKTRACK) {
            this.backTrack.btiAL = this.backTrack.btiEALo; this.backTrack.btiAH = this.backTrack.btiEAHi;
        }
        break;
    case 0xC1:
        this.regECX = l;
        if (BACKTRACK) {
            this.backTrack.btiCL = this.backTrack.btiEALo; this.backTrack.btiCH = this.backTrack.btiEAHi;
        }
        break;
    case 0xC2:
        this.regEDX = l;
        if (BACKTRACK) {
            this.backTrack.btiDL = this.backTrack.btiEALo; this.backTrack.btiDH = this.backTrack.btiEAHi;
        }
        break;
    case 0xC3:
        this.regEBX = l;
        if (BACKTRACK) {
            this.backTrack.btiBL = this.backTrack.btiEALo; this.backTrack.btiBH = this.backTrack.btiEAHi;
        }
        break;
    case 0xC4:
        this.setSP(l);
        break;
    case 0xC5:
        this.regEBP = l;
        if (BACKTRACK) {
            this.backTrack.btiBPLo = this.backTrack.btiEALo; this.backTrack.btiBPHi = this.backTrack.btiEAHi;
        }
        break;
    case 0xC6:
        this.regESI = l;
        if (BACKTRACK) {
            this.backTrack.btiSILo = this.backTrack.btiEALo; this.backTrack.btiSIHi = this.backTrack.btiEAHi;
        }
        break;
    case 0xC7:
        this.regEDI = l;
        if (BACKTRACK) {
            this.backTrack.btiDILo = this.backTrack.btiEALo; this.backTrack.btiDIHi = this.backTrack.btiEAHi;
        }
        break;
    default:

        break;
    }
};

/**
 * modGrpLong16(afnGrp, fnSrc)
 *
 * @this {CPUx86}
 * @param {Array.<function(number,number)>} afnGrp
 * @param {function()} fnSrc
 */
X86.modGrpLong16 = function(afnGrp, fnSrc)
{
    let dst;
    let bModRM = (this.bModRM = this.getIPByte()) & 0xC7;

    switch(bModRM) {
    case 0x00:
        dst = this.getEALongData(this.regEBX + this.regESI);
        this.regEAWrite = this.regEA;
        break;
    case 0x01:
        dst = this.getEALongData(this.regEBX + this.regEDI);
        this.regEAWrite = this.regEA;
        break;
    case 0x02:
        dst = this.getEALongStack(this.regEBP + this.regESI);
        this.regEAWrite = this.regEA;
        break;
    case 0x03:
        dst = this.getEALongStack(this.regEBP + this.regEDI);
        this.regEAWrite = this.regEA;
        break;
    case 0x04:
        dst = this.getEALongData(this.regESI);
        this.regEAWrite = this.regEA;
        break;
    case 0x05:
        dst = this.getEALongData(this.regEDI);
        this.regEAWrite = this.regEA;
        break;
    case 0x06:
        dst = this.getEALongData(this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x07:
        dst = this.getEALongData(this.regEBX);
        this.regEAWrite = this.regEA;
        break;
    case 0x40:
        dst = this.getEALongData(this.regEBX + this.regESI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x41:
        dst = this.getEALongData(this.regEBX + this.regEDI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x42:
        dst = this.getEALongStack(this.regEBP + this.regESI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x43:
        dst = this.getEALongStack(this.regEBP + this.regEDI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x44:
        dst = this.getEALongData(this.regESI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x45:
        dst = this.getEALongData(this.regEDI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x46:
        dst = this.getEALongStack(this.regEBP + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x47:
        dst = this.getEALongData(this.regEBX + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x80:
        dst = this.getEALongData(this.regEBX + this.regESI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x81:
        dst = this.getEALongData(this.regEBX + this.regEDI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x82:
        dst = this.getEALongStack(this.regEBP + this.regESI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x83:
        dst = this.getEALongStack(this.regEBP + this.regEDI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x84:
        dst = this.getEALongData(this.regESI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x85:
        dst = this.getEALongData(this.regEDI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x86:
        dst = this.getEALongStack(this.regEBP + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x87:
        dst = this.getEALongData(this.regEBX + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0xC0:
        dst = this.regEAX;
        break;
    case 0xC1:
        dst = this.regECX;
        break;
    case 0xC2:
        dst = this.regEDX;
        break;
    case 0xC3:
        dst = this.regEBX;
        break;
    case 0xC4:
        dst = this.getSP();
        break;
    case 0xC5:
        dst = this.regEBP;
        break;
    case 0xC6:
        dst = this.regESI;
        break;
    case 0xC7:
        dst = this.regEDI;
        break;
    default:

        break;
    }

    let reg = (this.bModRM >> 3) & 0x7;

    let l = afnGrp[reg].call(this, dst, fnSrc.call(this));

    switch(bModRM) {
    case 0x00:
    case 0x03:
        this.setEALong(l);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndex;
        break;
    case 0x01:
    case 0x02:
        this.setEALong(l);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexExtra;
        break;
    case 0x04:
    case 0x05:
    case 0x07:
        this.setEALong(l);
        this.nStepCycles -= this.cycleCounts.nEACyclesBase;
        break;
    case 0x06:
        this.setEALong(l);
        this.nStepCycles -= this.cycleCounts.nEACyclesDisp;
        break;
    case 0x40:
    case 0x43:
    case 0x80:
    case 0x83:
        this.setEALong(l);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDisp;
        break;
    case 0x41:
    case 0x42:
    case 0x81:
    case 0x82:
        this.setEALong(l);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseIndexDispExtra;
        break;
    case 0x44:
    case 0x45:
    case 0x46:
    case 0x47:
    case 0x84:
    case 0x85:
    case 0x86:
    case 0x87:
        this.setEALong(l);
        this.nStepCycles -= this.cycleCounts.nEACyclesBaseDisp;
        break;
    case 0xC0:
        this.regEAX = l;
        break;
    case 0xC1:
        this.regECX = l;
        break;
    case 0xC2:
        this.regEDX = l;
        break;
    case 0xC3:
        this.regEBX = l;
        break;
    case 0xC4:
        this.setSP(l);
        break;
    case 0xC5:
        this.regEBP = l;
        break;
    case 0xC6:
        this.regESI = l;
        break;
    case 0xC7:
        this.regEDI = l;
        break;
    }
};

/**
 * modRegByte32(fn)
 *
 * @this {CPUx86}
 * @param {function(number,number)} fn (dst,src)
 */
X86.modRegByte32 = function(fn)
{
    let dst, src;
    let bModRM = (this.bModRM = this.getIPByte()) & 0xC7;

    switch(bModRM) {
    case 0x00:
        src = this.getEAByteData(this.regEAX);
        break;
    case 0x01:
        src = this.getEAByteData(this.regECX);
        break;
    case 0x02:
        src = this.getEAByteData(this.regEDX);
        break;
    case 0x03:
        src = this.getEAByteData(this.regEBX);
        break;
    case 0x04:
        src = this.getEAByteData(X86.modSIB.call(this, 0));
        break;
    case 0x05:
        src = this.getEAByteData(this.getIPAddr());
        break;
    case 0x06:
        src = this.getEAByteData(this.regESI);
        break;
    case 0x07:
        src = this.getEAByteData(this.regEDI);
        break;
    case 0x40:
        src = this.getEAByteData(this.regEAX + this.getIPDisp());
        break;
    case 0x41:
        src = this.getEAByteData(this.regECX + this.getIPDisp());
        break;
    case 0x42:
        src = this.getEAByteData(this.regEDX + this.getIPDisp());
        break;
    case 0x43:
        src = this.getEAByteData(this.regEBX + this.getIPDisp());
        break;
    case 0x44:
        src = this.getEAByteData(X86.modSIB.call(this, 1) + this.getIPDisp());
        break;
    case 0x45:
        src = this.getEAByteStack(this.regEBP + this.getIPDisp());
        break;
    case 0x46:
        src = this.getEAByteData(this.regESI + this.getIPDisp());
        break;
    case 0x47:
        src = this.getEAByteData(this.regEDI + this.getIPDisp());
        break;
    case 0x80:
        src = this.getEAByteData(this.regEAX + this.getIPAddr());
        break;
    case 0x81:
        src = this.getEAByteData(this.regECX + this.getIPAddr());
        break;
    case 0x82:
        src = this.getEAByteData(this.regEDX + this.getIPAddr());
        break;
    case 0x83:
        src = this.getEAByteData(this.regEBX + this.getIPAddr());
        break;
    case 0x84:
        src = this.getEAByteData(X86.modSIB.call(this, 2) + this.getIPAddr());
        break;
    case 0x85:
        src = this.getEAByteStack(this.regEBP + this.getIPAddr());
        break;
    case 0x86:
        src = this.getEAByteData(this.regESI + this.getIPAddr());
        break;
    case 0x87:
        src = this.getEAByteData(this.regEDI + this.getIPAddr());
        break;
    case 0xC0:
        src = this.regEAX & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiAL;
        break;
    case 0xC1:
        src = this.regECX & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiCL;
        break;
    case 0xC2:
        src = this.regEDX & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiDL;
        break;
    case 0xC3:
        src = this.regEBX & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiBL;
        break;
    case 0xC4:
        src = (this.regEAX >> 8) & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiAH;
        break;
    case 0xC5:
        src = (this.regECX >> 8) & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiCH;
        break;
    case 0xC6:
        src = (this.regEDX >> 8) & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiDH;
        break;
    case 0xC7:
        src = (this.regEBX >> 8) & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiBH;
        break;
    default:
        src = 0;

        break;
    }

    let reg = (this.bModRM >> 3) & 0x7;

    switch(reg) {
    case 0x0:
        dst = this.regEAX & 0xff;
        break;
    case 0x1:
        dst = this.regECX & 0xff;
        break;
    case 0x2:
        dst = this.regEDX & 0xff;
        break;
    case 0x3:
        dst = this.regEBX & 0xff;
        break;
    case 0x4:
        dst = (this.regEAX >> 8) & 0xff;
        break;
    case 0x5:
        dst = (this.regECX >> 8) & 0xff;
        break;
    case 0x6:
        dst = (this.regEDX >> 8) & 0xff;
        break;
    case 0x7:
        dst = (this.regEBX >> 8) & 0xff;
        break;
    default:
        dst = 0;
        break;
    }

    let b = fn.call(this, dst, src);

    switch(reg) {
    case 0x0:
        this.regEAX = (this.regEAX & ~0xff) | b;
        if (BACKTRACK) this.backTrack.btiAL = this.backTrack.btiEALo;
        break;
    case 0x1:
        this.regECX = (this.regECX & ~0xff) | b;
        if (BACKTRACK) this.backTrack.btiCL = this.backTrack.btiEALo;
        break;
    case 0x2:
        this.regEDX = (this.regEDX & ~0xff) | b;
        if (BACKTRACK) this.backTrack.btiDL = this.backTrack.btiEALo;
        break;
    case 0x3:
        this.regEBX = (this.regEBX & ~0xff) | b;
        if (BACKTRACK) this.backTrack.btiBL = this.backTrack.btiEALo;
        break;
    case 0x4:
        this.regEAX = (this.regEAX & ~0xff00) | (b << 8);
        if (BACKTRACK) this.backTrack.btiAH = this.backTrack.btiEALo;
        break;
    case 0x5:
        this.regECX = (this.regECX & ~0xff00) | (b << 8);
        if (BACKTRACK) this.backTrack.btiCH = this.backTrack.btiEALo;
        break;
    case 0x6:
        this.regEDX = (this.regEDX & ~0xff00) | (b << 8);
        if (BACKTRACK) this.backTrack.btiDH = this.backTrack.btiEALo;
        break;
    case 0x7:
        this.regEBX = (this.regEBX & ~0xff00) | (b << 8);
        if (BACKTRACK) this.backTrack.btiBH = this.backTrack.btiEALo;
        break;
    }
};

/**
 * modMemByte32(fn)
 *
 * @this {CPUx86}
 * @param {function(number,number)} fn (dst,src)
 */
X86.modMemByte32 = function(fn)
{
    let dst, src;
    let bModRM = (this.bModRM = this.getIPByte()) & 0xC7;

    switch(bModRM) {
    case 0x00:
        dst = this.getEAByteData(this.regEAX);
        this.regEAWrite = this.regEA;
        break;
    case 0x01:
        dst = this.getEAByteData(this.regECX);
        this.regEAWrite = this.regEA;
        break;
    case 0x02:
        dst = this.getEAByteData(this.regEDX);
        this.regEAWrite = this.regEA;
        break;
    case 0x03:
        dst = this.getEAByteData(this.regEBX);
        this.regEAWrite = this.regEA;
        break;
    case 0x04:
        dst = this.getEAByteData(X86.modSIB.call(this, 0));
        this.regEAWrite = this.regEA;
        break;
    case 0x05:
        dst = this.getEAByteData(this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x06:
        dst = this.getEAByteData(this.regESI);
        this.regEAWrite = this.regEA;
        break;
    case 0x07:
        dst = this.getEAByteData(this.regEDI);
        this.regEAWrite = this.regEA;
        break;
    case 0x40:
        dst = this.getEAByteData(this.regEAX + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x41:
        dst = this.getEAByteData(this.regECX + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x42:
        dst = this.getEAByteData(this.regEDX + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x43:
        dst = this.getEAByteData(this.regEBX + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x44:
        dst = this.getEAByteData(X86.modSIB.call(this, 1) + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x45:
        dst = this.getEAByteStack(this.regEBP + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x46:
        dst = this.getEAByteData(this.regESI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x47:
        dst = this.getEAByteData(this.regEDI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x80:
        dst = this.getEAByteData(this.regEAX + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x81:
        dst = this.getEAByteData(this.regECX + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x82:
        dst = this.getEAByteData(this.regEDX + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x83:
        dst = this.getEAByteData(this.regEBX + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x84:
        dst = this.getEAByteData(X86.modSIB.call(this, 2) + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x85:
        dst = this.getEAByteStack(this.regEBP + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x86:
        dst = this.getEAByteData(this.regESI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x87:
        dst = this.getEAByteData(this.regEDI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0xC0:
        dst = this.regEAX & 0xff;
        break;
    case 0xC1:
        dst = this.regECX & 0xff;
        break;
    case 0xC2:
        dst = this.regEDX & 0xff;
        break;
    case 0xC3:
        dst = this.regEBX & 0xff;
        break;
    case 0xC4:
        dst = (this.regEAX >> 8) & 0xff;
        break;
    case 0xC5:
        dst = (this.regECX >> 8) & 0xff;
        break;
    case 0xC6:
        dst = (this.regEDX >> 8) & 0xff;
        break;
    case 0xC7:
        dst = (this.regEBX >> 8) & 0xff;
        break;
    default:
        dst = 0;

        break;
    }

    let reg = (this.bModRM >> 3) & 0x7;

    switch(reg) {
    case 0x0:
        src = this.regEAX & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiAL;
        break;
    case 0x1:
        src = this.regECX & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiCL;
        break;
    case 0x2:
        src = this.regEDX & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiDL;
        break;
    case 0x3:
        src = this.regEBX & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiBL;
        break;
    case 0x4:
        src = (this.regEAX >> 8) & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiAH;
        break;
    case 0x5:
        src = (this.regECX >> 8) & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiCH;
        break;
    case 0x6:
        src = (this.regEDX >> 8) & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiDH;
        break;
    case 0x7:
        src = (this.regEBX >> 8) & 0xff;
        if (BACKTRACK) this.backTrack.btiEALo = this.backTrack.btiBH;
        break;
    default:
        src = 0;
        break;
    }

    let b = fn.call(this, dst, src);

    switch(bModRM) {
    case 0xC0:
        this.regEAX = (this.regEAX & ~0xff) | b;
        if (BACKTRACK) this.backTrack.btiAL = this.backTrack.btiEALo;
        break;
    case 0xC1:
        this.regECX = (this.regECX & ~0xff) | b;
        if (BACKTRACK) this.backTrack.btiCL = this.backTrack.btiEALo;
        break;
    case 0xC2:
        this.regEDX = (this.regEDX & ~0xff) | b;
        if (BACKTRACK) this.backTrack.btiDL = this.backTrack.btiEALo;
        break;
    case 0xC3:
        this.regEBX = (this.regEBX & ~0xff) | b;
        if (BACKTRACK) this.backTrack.btiBL = this.backTrack.btiEALo;
        break;
    case 0xC4:
        this.regEAX = (this.regEAX & ~0xff00) | (b << 8);
        if (BACKTRACK) this.backTrack.btiAH = this.backTrack.btiEALo;
        break;
    case 0xC5:
        this.regECX = (this.regECX & ~0xff00) | (b << 8);
        if (BACKTRACK) this.backTrack.btiCH = this.backTrack.btiEALo;
        break;
    case 0xC6:
        this.regEDX = (this.regEDX & ~0xff00) | (b << 8);
        if (BACKTRACK) this.backTrack.btiDH = this.backTrack.btiEALo;
        break;
    case 0xC7:
        this.regEBX = (this.regEBX & ~0xff00) | (b << 8);
        if (BACKTRACK) this.backTrack.btiBH = this.backTrack.btiEALo;
        break;
    default:
        this.setEAByte(b);
        break;
    }
};

/**
 * modGrpByte32(afnGrp, fnSrc)
 *
 * @this {CPUx86}
 * @param {Array.<function(number,number)>} afnGrp
 * @param {function()} fnSrc
 */
X86.modGrpByte32 = function(afnGrp, fnSrc)
{
    let dst;
    let bModRM = (this.bModRM = this.getIPByte()) & 0xC7;

    switch(bModRM) {
    case 0x00:
        dst = this.getEAByteData(this.regEAX);
        this.regEAWrite = this.regEA;
        break;
    case 0x01:
        dst = this.getEAByteData(this.regECX);
        this.regEAWrite = this.regEA;
        break;
    case 0x02:
        dst = this.getEAByteData(this.regEDX);
        this.regEAWrite = this.regEA;
        break;
    case 0x03:
        dst = this.getEAByteData(this.regEBX);
        this.regEAWrite = this.regEA;
        break;
    case 0x04:
        dst = this.getEAByteData(X86.modSIB.call(this, 0));
        this.regEAWrite = this.regEA;
        break;
    case 0x05:
        dst = this.getEAByteData(this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x06:
        dst = this.getEAByteData(this.regESI);
        this.regEAWrite = this.regEA;
        break;
    case 0x07:
        dst = this.getEAByteData(this.regEDI);
        this.regEAWrite = this.regEA;
        break;
    case 0x40:
        dst = this.getEAByteData(this.regEAX + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x41:
        dst = this.getEAByteData(this.regECX + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x42:
        dst = this.getEAByteData(this.regEDX + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x43:
        dst = this.getEAByteData(this.regEBX + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x44:
        dst = this.getEAByteData(X86.modSIB.call(this, 1) + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x45:
        dst = this.getEAByteStack(this.regEBP + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x46:
        dst = this.getEAByteData(this.regESI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x47:
        dst = this.getEAByteData(this.regEDI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x80:
        dst = this.getEAByteData(this.regEAX + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x81:
        dst = this.getEAByteData(this.regECX + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x82:
        dst = this.getEAByteData(this.regEDX + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x83:
        dst = this.getEAByteData(this.regEBX + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x84:
        dst = this.getEAByteData(X86.modSIB.call(this, 2) + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x85:
        dst = this.getEAByteStack(this.regEBP + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x86:
        dst = this.getEAByteData(this.regESI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x87:
        dst = this.getEAByteData(this.regEDI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0xC0:
        dst = this.regEAX & 0xff;
        break;
    case 0xC1:
        dst = this.regECX & 0xff;
        break;
    case 0xC2:
        dst = this.regEDX & 0xff;
        break;
    case 0xC3:
        dst = this.regEBX & 0xff;
        break;
    case 0xC4:
        dst = (this.regEAX >> 8) & 0xff;
        break;
    case 0xC5:
        dst = (this.regECX >> 8) & 0xff;
        break;
    case 0xC6:
        dst = (this.regEDX >> 8) & 0xff;
        break;
    case 0xC7:
        dst = (this.regEBX >> 8) & 0xff;
        break;
    default:
        dst = 0;

        break;
    }

    let reg = (this.bModRM >> 3) & 0x7;

    let b = afnGrp[reg].call(this, dst, fnSrc.call(this));

    switch(bModRM) {
    case 0xC0:
        this.regEAX = (this.regEAX & ~0xff) | b;
        break;
    case 0xC1:
        this.regECX = (this.regECX & ~0xff) | b;
        break;
    case 0xC2:
        this.regEDX = (this.regEDX & ~0xff) | b;
        break;
    case 0xC3:
        this.regEBX = (this.regEBX & ~0xff) | b;
        break;
    case 0xC4:
        this.regEAX = (this.regEAX & ~0xff00) | (b << 8);
        break;
    case 0xC5:
        this.regECX = (this.regECX & ~0xff00) | (b << 8);
        break;
    case 0xC6:
        this.regEDX = (this.regEDX & ~0xff00) | (b << 8);
        break;
    case 0xC7:
        this.regEBX = (this.regEBX & ~0xff00) | (b << 8);
        break;
    default:
        this.setEAByte(b);
        break;
    }
};

/**
 * modRegShort32(fn)
 *
 * @this {CPUx86}
 * @param {function(number,number)} fn (dst,src)
 */
X86.modRegShort32 = function(fn)
{
    let dst, src;
    let bModRM = (this.bModRM = this.getIPByte()) & 0xC7;

    switch(bModRM) {
    case 0x00:
        src = this.getEAShortData(this.regEAX);
        break;
    case 0x01:
        src = this.getEAShortData(this.regECX);
        break;
    case 0x02:
        src = this.getEAShortData(this.regEDX);
        break;
    case 0x03:
        src = this.getEAShortData(this.regEBX);
        break;
    case 0x04:
        src = this.getEAShortData(X86.modSIB.call(this, 0));
        break;
    case 0x05:
        src = this.getEAShortData(this.getIPAddr());
        break;
    case 0x06:
        src = this.getEAShortData(this.regESI);
        break;
    case 0x07:
        src = this.getEAShortData(this.regEDI);
        break;
    case 0x40:
        src = this.getEAShortData(this.regEAX + this.getIPDisp());
        break;
    case 0x41:
        src = this.getEAShortData(this.regECX + this.getIPDisp());
        break;
    case 0x42:
        src = this.getEAShortData(this.regEDX + this.getIPDisp());
        break;
    case 0x43:
        src = this.getEAShortData(this.regEBX + this.getIPDisp());
        break;
    case 0x44:
        src = this.getEAShortData(X86.modSIB.call(this, 1) + this.getIPDisp());
        break;
    case 0x45:
        src = this.getEAShortStack(this.regEBP + this.getIPDisp());
        break;
    case 0x46:
        src = this.getEAShortData(this.regESI + this.getIPDisp());
        break;
    case 0x47:
        src = this.getEAShortData(this.regEDI + this.getIPDisp());
        break;
    case 0x80:
        src = this.getEAShortData(this.regEAX + this.getIPAddr());
        break;
    case 0x81:
        src = this.getEAShortData(this.regECX + this.getIPAddr());
        break;
    case 0x82:
        src = this.getEAShortData(this.regEDX + this.getIPAddr());
        break;
    case 0x83:
        src = this.getEAShortData(this.regEBX + this.getIPAddr());
        break;
    case 0x84:
        src = this.getEAShortData(X86.modSIB.call(this, 2) + this.getIPAddr());
        break;
    case 0x85:
        src = this.getEAShortStack(this.regEBP + this.getIPAddr());
        break;
    case 0x86:
        src = this.getEAShortData(this.regESI + this.getIPAddr());
        break;
    case 0x87:
        src = this.getEAShortData(this.regEDI + this.getIPAddr());
        break;
    case 0xC0:
        src = this.regEAX & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiAL; this.backTrack.btiEAHi = this.backTrack.btiAH;
        }
        break;
    case 0xC1:
        src = this.regECX & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiCL; this.backTrack.btiEAHi = this.backTrack.btiCH;
        }
        break;
    case 0xC2:
        src = this.regEDX & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiDL; this.backTrack.btiEAHi = this.backTrack.btiDH;
        }
        break;
    case 0xC3:
        src = this.regEBX & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiBL; this.backTrack.btiEAHi = this.backTrack.btiBH;
        }
        break;
    case 0xC4:
        src = this.getSP() & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = X86.BTINFO.SP_LO; this.backTrack.btiEAHi = X86.BTINFO.SP_HI;
        }
        break;
    case 0xC5:
        src = this.regEBP & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiBPLo; this.backTrack.btiEAHi = this.backTrack.btiBPHi;
        }
        break;
    case 0xC6:
        src = this.regESI & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiSILo; this.backTrack.btiEAHi = this.backTrack.btiSIHi;
        }
        break;
    case 0xC7:
        src = this.regEDI & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiDILo; this.backTrack.btiEAHi = this.backTrack.btiDIHi;
        }
        break;
    default:
        src = 0;

        break;
    }

    let reg = (this.bModRM >> 3) & 0x7;

    switch(reg) {
    case 0x0:
        dst = this.regEAX & 0xffff;
        break;
    case 0x1:
        dst = this.regECX & 0xffff;
        break;
    case 0x2:
        dst = this.regEDX & 0xffff;
        break;
    case 0x3:
        dst = this.regEBX & 0xffff;
        break;
    case 0x4:
        dst = this.getSP() & 0xffff;
        break;
    case 0x5:
        dst = this.regEBP & 0xffff;
        break;
    case 0x6:
        dst = this.regESI & 0xffff;
        break;
    case 0x7:
        dst = this.regEDI & 0xffff;
        break;
    default:
        dst = 0;
        break;
    }

    let w = fn.call(this, dst, src);

    switch(reg) {
    case 0x0:
        this.regEAX = (this.regEAX & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiAL = this.backTrack.btiEALo; this.backTrack.btiAH = this.backTrack.btiEAHi;
        }
        break;
    case 0x1:
        this.regECX = (this.regECX & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiCL = this.backTrack.btiEALo; this.backTrack.btiCH = this.backTrack.btiEAHi;
        }
        break;
    case 0x2:
        this.regEDX = (this.regEDX & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiDL = this.backTrack.btiEALo; this.backTrack.btiDH = this.backTrack.btiEAHi;
        }
        break;
    case 0x3:
        this.regEBX = (this.regEBX & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiBL = this.backTrack.btiEALo; this.backTrack.btiBH = this.backTrack.btiEAHi;
        }
        break;
    case 0x4:
        this.setSP((this.getSP() & ~0xffff) | w);
        break;
    case 0x5:
        this.regEBP = (this.regEBP & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiBPLo = this.backTrack.btiEALo; this.backTrack.btiBPHi = this.backTrack.btiEAHi;
        }
        break;
    case 0x6:
        this.regESI = (this.regESI & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiSILo = this.backTrack.btiEALo; this.backTrack.btiSIHi = this.backTrack.btiEAHi;
        }
        break;
    case 0x7:
        this.regEDI = (this.regEDI & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiDILo = this.backTrack.btiEALo; this.backTrack.btiDIHi = this.backTrack.btiEAHi;
        }
        break;
    }
};

/**
 * modMemShort32(fn)
 *
 * @this {CPUx86}
 * @param {function(number,number)} fn (dst,src)
 */
X86.modMemShort32 = function(fn)
{
    let dst, src;
    let bModRM = (this.bModRM = this.getIPByte()) & 0xC7;

    switch(bModRM) {
    case 0x00:
        dst = this.getEAShortData(this.regEAX);
        this.regEAWrite = this.regEA;
        break;
    case 0x01:
        dst = this.getEAShortData(this.regECX);
        this.regEAWrite = this.regEA;
        break;
    case 0x02:
        dst = this.getEAShortData(this.regEDX);
        this.regEAWrite = this.regEA;
        break;
    case 0x03:
        dst = this.getEAShortData(this.regEBX);
        this.regEAWrite = this.regEA;
        break;
    case 0x04:
        dst = this.getEAShortData(X86.modSIB.call(this, 0));
        this.regEAWrite = this.regEA;
        break;
    case 0x05:
        dst = this.getEAShortData(this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x06:
        dst = this.getEAShortData(this.regESI);
        this.regEAWrite = this.regEA;
        break;
    case 0x07:
        dst = this.getEAShortData(this.regEDI);
        this.regEAWrite = this.regEA;
        break;
    case 0x40:
        dst = this.getEAShortData(this.regEAX + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x41:
        dst = this.getEAShortData(this.regECX + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x42:
        dst = this.getEAShortData(this.regEDX + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x43:
        dst = this.getEAShortData(this.regEBX + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x44:
        dst = this.getEAShortData(X86.modSIB.call(this, 1) + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x45:
        dst = this.getEAShortStack(this.regEBP + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x46:
        dst = this.getEAShortData(this.regESI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x47:
        dst = this.getEAShortData(this.regEDI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x80:
        dst = this.getEAShortData(this.regEAX + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x81:
        dst = this.getEAShortData(this.regECX + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x82:
        dst = this.getEAShortData(this.regEDX + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x83:
        dst = this.getEAShortData(this.regEBX + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x84:
        dst = this.getEAShortData(X86.modSIB.call(this, 2) + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x85:
        dst = this.getEAShortStack(this.regEBP + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x86:
        dst = this.getEAShortData(this.regESI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x87:
        dst = this.getEAShortData(this.regEDI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0xC0:
        dst = this.regEAX & 0xffff;
        break;
    case 0xC1:
        dst = this.regECX & 0xffff;
        break;
    case 0xC2:
        dst = this.regEDX & 0xffff;
        break;
    case 0xC3:
        dst = this.regEBX & 0xffff;
        break;
    case 0xC4:
        dst = this.getSP() & 0xffff;
        break;
    case 0xC5:
        dst = this.regEBP & 0xffff;
        break;
    case 0xC6:
        dst = this.regESI & 0xffff;
        break;
    case 0xC7:
        dst = this.regEDI & 0xffff;
        break;
    default:
        dst = 0;

        break;
    }

    let reg = (this.bModRM >> 3) & 0x7;

    switch(reg) {
    case 0x0:
        src = this.regEAX & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiAL; this.backTrack.btiEAHi = this.backTrack.btiAH;
        }
        break;
    case 0x1:
        src = this.regECX & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiCL; this.backTrack.btiEAHi = this.backTrack.btiCH;
        }
        break;
    case 0x2:
        src = this.regEDX & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiDL; this.backTrack.btiEAHi = this.backTrack.btiDH;
        }
        break;
    case 0x3:
        src = this.regEBX & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiBL; this.backTrack.btiEAHi = this.backTrack.btiBH;
        }
        break;
    case 0x4:
        src = this.getSP() & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = X86.BTINFO.SP_LO; this.backTrack.btiEAHi = X86.BTINFO.SP_HI;
        }
        break;
    case 0x5:
        src = this.regEBP & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiBPLo; this.backTrack.btiEAHi = this.backTrack.btiBPHi;
        }
        break;
    case 0x6:
        src = this.regESI & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiSILo; this.backTrack.btiEAHi = this.backTrack.btiSIHi;
        }
        break;
    case 0x7:
        src = this.regEDI & 0xffff;
        if (BACKTRACK) {
            this.backTrack.btiEALo = this.backTrack.btiDILo; this.backTrack.btiEAHi = this.backTrack.btiDIHi;
        }
        break;
    default:
        src = 0;
        break;
    }

    let w = fn.call(this, dst, src);

    switch(bModRM) {
    case 0xC0:
        this.regEAX = (this.regEAX & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiAL = this.backTrack.btiEALo; this.backTrack.btiAH = this.backTrack.btiEAHi;
        }
        break;
    case 0xC1:
        this.regECX = (this.regECX & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiCL = this.backTrack.btiEALo; this.backTrack.btiCH = this.backTrack.btiEAHi;
        }
        break;
    case 0xC2:
        this.regEDX = (this.regEDX & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiDL = this.backTrack.btiEALo; this.backTrack.btiDH = this.backTrack.btiEAHi;
        }
        break;
    case 0xC3:
        this.regEBX = (this.regEBX & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiBL = this.backTrack.btiEALo; this.backTrack.btiBH = this.backTrack.btiEAHi;
        }
        break;
    case 0xC4:
        this.setSP((this.getSP() & ~0xffff) | w);
        break;
    case 0xC5:
        this.regEBP = (this.regEBP & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiBPLo = this.backTrack.btiEALo; this.backTrack.btiBPHi = this.backTrack.btiEAHi;
        }
        break;
    case 0xC6:
        this.regESI = (this.regESI & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiSILo = this.backTrack.btiEALo; this.backTrack.btiSIHi = this.backTrack.btiEAHi;
        }
        break;
    case 0xC7:
        this.regEDI = (this.regEDI & ~0xffff) | w;
        if (BACKTRACK) {
            this.backTrack.btiDILo = this.backTrack.btiEALo; this.backTrack.btiDIHi = this.backTrack.btiEAHi;
        }
        break;
    default:
        this.setEAShort(w);
        break;
    }
};

/**
 * modGrpShort32(afnGrp, fnSrc)
 *
 * @this {CPUx86}
 * @param {Array.<function(number,number)>} afnGrp
 * @param {function()} fnSrc
 */
X86.modGrpShort32 = function(afnGrp, fnSrc)
{
    let dst;
    let bModRM = (this.bModRM = this.getIPByte()) & 0xC7;

    switch(bModRM) {
    case 0x00:
        dst = this.getEAShortData(this.regEAX);
        this.regEAWrite = this.regEA;
        break;
    case 0x01:
        dst = this.getEAShortData(this.regECX);
        this.regEAWrite = this.regEA;
        break;
    case 0x02:
        dst = this.getEAShortData(this.regEDX);
        this.regEAWrite = this.regEA;
        break;
    case 0x03:
        dst = this.getEAShortData(this.regEBX);
        this.regEAWrite = this.regEA;
        break;
    case 0x04:
        dst = this.getEAShortData(X86.modSIB.call(this, 0));
        this.regEAWrite = this.regEA;
        break;
    case 0x05:
        dst = this.getEAShortData(this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x06:
        dst = this.getEAShortData(this.regESI);
        this.regEAWrite = this.regEA;
        break;
    case 0x07:
        dst = this.getEAShortData(this.regEDI);
        this.regEAWrite = this.regEA;
        break;
    case 0x40:
        dst = this.getEAShortData(this.regEAX + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x41:
        dst = this.getEAShortData(this.regECX + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x42:
        dst = this.getEAShortData(this.regEDX + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x43:
        dst = this.getEAShortData(this.regEBX + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x44:
        dst = this.getEAShortData(X86.modSIB.call(this, 1) + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x45:
        dst = this.getEAShortStack(this.regEBP + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x46:
        dst = this.getEAShortData(this.regESI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x47:
        dst = this.getEAShortData(this.regEDI + this.getIPDisp());
        this.regEAWrite = this.regEA;
        break;
    case 0x80:
        dst = this.getEAShortData(this.regEAX + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x81:
        dst = this.getEAShortData(this.regECX + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x82:
        dst = this.getEAShortData(this.regEDX + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x83:
        dst = this.getEAShortData(this.regEBX + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x84:
        dst = this.getEAShortData(X86.modSIB.call(this, 2) + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x85:
        dst = this.getEAShortStack(this.regEBP + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x86:
        dst = this.getEAShortData(this.regESI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0x87:
        dst = this.getEAShortData(this.regEDI + this.getIPAddr());
        this.regEAWrite = this.regEA;
        break;
    case 0xC0:
        dst = this.regEAX & 0xffff;
        break;
    case 0xC1:
        dst = this.regECX & 0xffff;
        break;
    case 0xC2:
        dst = this.regEDX & 0xffff;
        break;
    case 0xC3:
        dst = this.regEBX & 0xffff;
        break;
    case 0xC4:
        dst = this.getSP() & 0xffff;
        break;
    case 0xC5:
        dst = this.regEBP & 0xffff;
        break;
    case 0xC6:
        dst = this.regESI & 0xffff;
        break;
    case 0xC7:
        dst = this.regEDI & 0xffff;
        break;
    default:
        dst = 0;

        break;
    }

    let reg = (this.bModRM >> 3) & 0x7;

    let w = afnGrp[reg].call(this, dst, fnSrc.call(this));

    switch(bModRM) {
    case 0xC0:
        this.regEAX = (this.regEAX & ~0xffff) | w;
        break;
    case 0xC1:
        this.regECX = (this.regECX & ~0xffff) | w;
        break;
    case 0xC2:
        this.regEDX = (this.regEDX & ~0xffff) | w;
        break;
    case 0xC3:
        this.regEBX = (this.regEBX & ~0xffff) | w;
        break;
    case 0xC4:
        this.setSP((this.getSP() & ~0xffff) | w);
        break;
    case 0xC5:
        this.regEBP = (this.regEBP & ~0xffff) | w;
        break;
    case 0xC6:
        this.regESI = (this.regESI & ~0xffff) | w;
        break;
    case 0xC7:
        this.regEDI = (this.regEDI & ~0xffff) | w;
        break;
    default:
        this.setEAShort(w);
        break;
    }
};

/**
 * modRegLong32(fn)
 *
 * @this {CPUx86}
 * @param {function(number,number)} fn (dst,src)
 */
X86.modRegLong32 = function(fn)
{
    let dst, src, l;
    let bModRM = this.bModRM = this.getIPByte();

    switch(bModRM & 0xC7) {
    case 0x00:
        src = this.getEALongData(this.regEAX);
        break;
    case 0x01:
        src = this.getEALongData(this.regECX);
        break;
    case 0x02:
        src = this.getEALongData(this.regEDX);
        break;
    case 0x03:
        src = this.getEALongData(this.regEBX);
        break;
    case 0x04:
        src = this.getEALongData(X86.modSIB.call(this, 0));
        break;
    case 0x05:
        src = this.getEALongData(this.getIPAddr());
        break;
    case 0x06:
        src = this.getEALongData(this.regESI);
        break;
    case 0x07:
        src = this.getEALongData(this.regEDI);
        break;
    case 0x40:
        src = this.getEALongData(this.regEAX + this.getIPDisp());
        break;
    case 0x41:
        src = this.getEALongData(this.regECX + this.getIPDisp());
        break;
    case 0x42:
        src = this.getEALongData(this.regEDX + this.getIPDisp());
        break;
    case 0x43:
        src = this.getEALongData(this.regEBX + this.getIPDisp());
        break;
    case 0x44:
        src = this.getEALongData(X86.modSIB.call(this, 1) + this.getIPDisp());
        break;
    case 0x45:
        src = this.getEALongStack(this.regEBP + this.getIPDisp());
        break;
    case 0x46:
        src = this.getEALongData(this.regESI + this.getIPDisp());
        break;
    case 0x47:
        src = this.getEALongData(this.regEDI + this.getIPDisp());
        break;
    case 0x80:
        src = this.getEALongData(this.regEAX + this.getIPAddr());
        break;
    case 0x81:
        src = this.getEALongData(this.regECX + this.getIPAddr());
        break;
    case 0x82:
        src = this.getEALongData(this.regEDX + this.getIPAddr());
        break;
    case 0x83:
        src = this.getEALongData(this.regEBX + this.getIPAddr());
        break;
    case 0x84:
        src = this.getEALongData(X86.modSIB.call(this, 2) + this.getIPAddr());
        break;
    case 0x85:
        src = this.getEALongStack(this.regEBP + this.getIPAddr());
        break;
    case 0x86:
        src = this.getEALongData(this.regESI + this.getIPAddr());
        break;
    case 0x87:
        src = this.getEALongData(this.regEDI + this.getIPAddr());
        break;
    case 0xC0:
        src = this.regEAX;
        if (BACKTRACK) {this.backTrack.btiEALo = this.backTrack.btiAL; this.backTrack.btiEAHi = this.backTrack.btiAH;}
        break;
    case 0xC1:
        src = this.regECX;
        if (BACKTRACK) {this.backTrack.btiEALo = this.backTrack.btiCL; this.backTrack.btiEAHi = this.backTrack.btiCH;}
        break;
    case 0xC2:
        src = this.regEDX;
        if (BACKTRACK) {this.backTrack.btiEALo = this.backTrack.btiDL; this.backTrack.btiEAHi = this.backTrack.btiDH;}
        break;
    case 0xC3:
        src = this.regEBX;
        if (BACKTRACK) {this.backTrack.btiEALo = this.backTrack.btiBL; this.backTrack.btiEAHi = this.backTrack.btiBH;}
        break;
    case 0xC4:
        src = this.getSP();
        if (BACKTRACK) {this.backTrack.btiEALo = X86.BTINFO.SP_LO; this.backTrack.btiEAHi = X86.BTINFO.SP_HI;}
        break;
    case 0xC5:
        src = this.regEBP;
        if (BACKTRACK) {this.backTrack.btiEALo = this.backTrack.btiBPLo; this.backTrack.btiEAHi = this.backTrack.btiBPHi;}
        break;
    case 0xC6:
        src = this.regESI;
        if (BACKTRACK) {this.backTrack.btiEALo = this.backTrack.btiSILo; this.backTrack.btiEAHi = this.backTrack.btiSIHi;}
        break;
    case 0xC7:
        src = this.regEDI;
        if (BACKTRACK) {this.backTrack.btiEALo = this.backTrack.btiDILo; this.backTrack.btiEAHi = this.backTrack.btiDIHi;}
        break;
    }

    switch((bModRM >> 3) & 0x7) {
    case 0x0:
        dst = this.regEAX;
        l = fn.call(this, dst, src);
        this.regEAX = l;
        if (BACKTRACK) {this.backTrack.btiAL = this.backTrack.btiEALo; this.backTrack.btiAH = this.backTrack.btiEAHi;}
        break;
    case 0x1:
        dst = this.regECX;
        l = fn.call(this, dst, src);
        this.regECX = l;
        if (BACKTRACK) {this.backTrack.btiCL = this.backTrack.btiEALo; this.backTrack.btiCH = this.backTrack.btiEAHi;}
        break;
    case 0x2:
        dst = this.regEDX;
        l = fn.call(this, dst, src);
        this.regEDX = l;
        if (BACKTRACK) {this.backTrack.btiDL = this.backTrack.btiEALo; this.backTrack.btiDH = this.backTrack.btiEAHi;}
        break;
    case 0x3:
        dst = this.regEBX;
        l = fn.call(this, dst, src);
        this.regEBX = l;
        if (BACKTRACK) {this.backTrack.btiBL = this.backTrack.btiEALo; this.backTrack.btiBH = this.backTrack.btiEAHi;}
        break;
    case 0x4:
        dst = this.getSP();
        l = fn.call(this, dst, src);
        this.setSP(l);
        break;
    case 0x5:
        dst = this.regEBP;
        l = fn.call(this, dst, src);
        this.regEBP = l;
        if (BACKTRACK) {this.backTrack.btiBPLo = this.backTrack.btiEALo; this.backTrack.btiBPHi = this.backTrack.btiEAHi;}
        break;
    case 0x6:
        dst = this.regESI;
        l = fn.call(this, dst, src);
        this.regESI = l;
        if (BACKTRACK) {this.backTrack.btiSILo = this.backTrack.btiEALo; this.backTrack.btiSIHi = this.backTrack.btiEAHi;}
        break;
    case 0x7:
        dst = this.regEDI;
        l = fn.call(this, dst, src);
        this.regEDI = l;
        if (BACKTRACK) {this.backTrack.btiDILo = this.backTrack.btiEALo; this.backTrack.btiDIHi = this.backTrack.btiEAHi;}
        break;
    }
};

/**
 * modMemLong32(fn)
 *
 * @this {CPUx86}
 * @param {function(number,number)} fn (dst,src)
 */
X86.modMemLong32 = function(fn)
{
    let dst, src;
    let bModRM = this.bModRM = this.getIPByte();

    switch(bModRM & 0xC7) {
    case 0x00:
        dst = this.getEALongDataWrite(this.regEAX);
        break;
    case 0x01:
        dst = this.getEALongDataWrite(this.regECX);
        break;
    case 0x02:
        dst = this.getEALongDataWrite(this.regEDX);
        break;
    case 0x03:
        dst = this.getEALongDataWrite(this.regEBX);
        break;
    case 0x04:
        dst = this.getEALongDataWrite(X86.modSIB.call(this, 0));
        break;
    case 0x05:
        dst = this.getEALongDataWrite(this.getIPAddr());
        break;
    case 0x06:
        dst = this.getEALongDataWrite(this.regESI);
        break;
    case 0x07:
        dst = this.getEALongDataWrite(this.regEDI);
        break;
    case 0x40:
        dst = this.getEALongDataWrite(this.regEAX + this.getIPDisp());
        break;
    case 0x41:
        dst = this.getEALongDataWrite(this.regECX + this.getIPDisp());
        break;
    case 0x42:
        dst = this.getEALongDataWrite(this.regEDX + this.getIPDisp());
        break;
    case 0x43:
        dst = this.getEALongDataWrite(this.regEBX + this.getIPDisp());
        break;
    case 0x44:
        dst = this.getEALongDataWrite(X86.modSIB.call(this, 1) + this.getIPDisp());
        break;
    case 0x45:
        dst = this.getEALongStackWrite(this.regEBP + this.getIPDisp());
        break;
    case 0x46:
        dst = this.getEALongDataWrite(this.regESI + this.getIPDisp());
        break;
    case 0x47:
        dst = this.getEALongDataWrite(this.regEDI + this.getIPDisp());
        break;
    case 0x80:
        dst = this.getEALongDataWrite(this.regEAX + this.getIPAddr());
        break;
    case 0x81:
        dst = this.getEALongDataWrite(this.regECX + this.getIPAddr());
        break;
    case 0x82:
        dst = this.getEALongDataWrite(this.regEDX + this.getIPAddr());
        break;
    case 0x83:
        dst = this.getEALongDataWrite(this.regEBX + this.getIPAddr());
        break;
    case 0x84:
        dst = this.getEALongDataWrite(X86.modSIB.call(this, 2) + this.getIPAddr());
        break;
    case 0x85:
        dst = this.getEALongStackWrite(this.regEBP + this.getIPAddr());
        break;
    case 0x86:
        dst = this.getEALongDataWrite(this.regESI + this.getIPAddr());
        break;
    case 0x87:
        dst = this.getEALongDataWrite(this.regEDI + this.getIPAddr());
        break;
    case 0xC0:
        dst = this.regEAX;
        break;
    case 0xC1:
        dst = this.regECX;
        break;
    case 0xC2:
        dst = this.regEDX;
        break;
    case 0xC3:
        dst = this.regEBX;
        break;
    case 0xC4:
        dst = this.getSP();
        break;
    case 0xC5:
        dst = this.regEBP;
        break;
    case 0xC6:
        dst = this.regESI;
        break;
    case 0xC7:
        dst = this.regEDI;
        break;
    }

    switch((bModRM >> 3) & 0x7) {
    case 0x0:
        src = this.regEAX;
        if (BACKTRACK) {this.backTrack.btiEALo = this.backTrack.btiAL; this.backTrack.btiEAHi = this.backTrack.btiAH;}
        break;
    case 0x1:
        src = this.regECX;
        if (BACKTRACK) {this.backTrack.btiEALo = this.backTrack.btiCL; this.backTrack.btiEAHi = this.backTrack.btiCH;}
        break;
    case 0x2:
        src = this.regEDX;
        if (BACKTRACK) {this.backTrack.btiEALo = this.backTrack.btiDL; this.backTrack.btiEAHi = this.backTrack.btiDH;}
        break;
    case 0x3:
        src = this.regEBX;
        if (BACKTRACK) {this.backTrack.btiEALo = this.backTrack.btiBL; this.backTrack.btiEAHi = this.backTrack.btiBH;}
        break;
    case 0x4:
        src = this.getSP();
        if (BACKTRACK) {this.backTrack.btiEALo = X86.BTINFO.SP_LO; this.backTrack.btiEAHi = X86.BTINFO.SP_HI;}
        break;
    case 0x5:
        src = this.regEBP;
        if (BACKTRACK) {this.backTrack.btiEALo = this.backTrack.btiBPLo; this.backTrack.btiEAHi = this.backTrack.btiBPHi;}
        break;
    case 0x6:
        src = this.regESI;
        if (BACKTRACK) {this.backTrack.btiEALo = this.backTrack.btiSILo; this.backTrack.btiEAHi = this.backTrack.btiSIHi;}
        break;
    case 0x7:
        src = this.regEDI;
        if (BACKTRACK) {this.backTrack.btiEALo = this.backTrack.btiDILo; this.backTrack.btiEAHi = this.backTrack.btiDIHi;}
        break;
    }

    let l = fn.call(this, dst, src);

    switch(bModRM & 0xC7) {
    case 0xC0:
        this.regEAX = l;
        if (BACKTRACK) {this.backTrack.btiAL = this.backTrack.btiEALo; this.backTrack.btiAH = this.backTrack.btiEAHi;}
        break;
    case 0xC1:
        this.regECX = l;
        if (BACKTRACK) {this.backTrack.btiCL = this.backTrack.btiEALo; this.backTrack.btiCH = this.backTrack.btiEAHi;}
        break;
    case 0xC2:
        this.regEDX = l;
        if (BACKTRACK) {this.backTrack.btiDL = this.backTrack.btiEALo; this.backTrack.btiDH = this.backTrack.btiEAHi;}
        break;
    case 0xC3:
        this.regEBX = l;
        if (BACKTRACK) {this.backTrack.btiBL = this.backTrack.btiEALo; this.backTrack.btiBH = this.backTrack.btiEAHi;}
        break;
    case 0xC4:
        this.setSP(l);
        break;
    case 0xC5:
        this.regEBP = l;
        if (BACKTRACK) {this.backTrack.btiBPLo = this.backTrack.btiEALo; this.backTrack.btiBPHi = this.backTrack.btiEAHi;}
        break;
    case 0xC6:
        this.regESI = l;
        if (BACKTRACK) {this.backTrack.btiSILo = this.backTrack.btiEALo; this.backTrack.btiSIHi = this.backTrack.btiEAHi;}
        break;
    case 0xC7:
        this.regEDI = l;
        if (BACKTRACK) {this.backTrack.btiDILo = this.backTrack.btiEALo; this.backTrack.btiDIHi = this.backTrack.btiEAHi;}
        break;
    default:
        this.setEALong(l);
        break;
    }
};

/**
 * modGrpLong32(afnGrp, fnSrc)
 *
 * @this {CPUx86}
 * @param {Array.<function(number,number)>} afnGrp
 * @param {function()} fnSrc
 */
X86.modGrpLong32 = function(afnGrp, fnSrc)
{
    let dst;
    let bModRM = this.bModRM = this.getIPByte();

    switch(bModRM & 0xC7) {
    case 0x00:
        dst = this.getEALongDataWrite(this.regEAX);
        break;
    case 0x01:
        dst = this.getEALongDataWrite(this.regECX);
        break;
    case 0x02:
        dst = this.getEALongDataWrite(this.regEDX);
        break;
    case 0x03:
        dst = this.getEALongDataWrite(this.regEBX);
        break;
    case 0x04:
        dst = this.getEALongDataWrite(X86.modSIB.call(this, 0));
        break;
    case 0x05:
        dst = this.getEALongDataWrite(this.getIPAddr());
        break;
    case 0x06:
        dst = this.getEALongDataWrite(this.regESI);
        break;
    case 0x07:
        dst = this.getEALongDataWrite(this.regEDI);
        break;
    case 0x40:
        dst = this.getEALongDataWrite(this.regEAX + this.getIPDisp());
        break;
    case 0x41:
        dst = this.getEALongDataWrite(this.regECX + this.getIPDisp());
        break;
    case 0x42:
        dst = this.getEALongDataWrite(this.regEDX + this.getIPDisp());
        break;
    case 0x43:
        dst = this.getEALongDataWrite(this.regEBX + this.getIPDisp());
        break;
    case 0x44:
        dst = this.getEALongDataWrite(X86.modSIB.call(this, 1) + this.getIPDisp());
        break;
    case 0x45:
        dst = this.getEALongStackWrite(this.regEBP + this.getIPDisp());
        break;
    case 0x46:
        dst = this.getEALongDataWrite(this.regESI + this.getIPDisp());
        break;
    case 0x47:
        dst = this.getEALongDataWrite(this.regEDI + this.getIPDisp());
        break;
    case 0x80:
        dst = this.getEALongDataWrite(this.regEAX + this.getIPAddr());
        break;
    case 0x81:
        dst = this.getEALongDataWrite(this.regECX + this.getIPAddr());
        break;
    case 0x82:
        dst = this.getEALongDataWrite(this.regEDX + this.getIPAddr());
        break;
    case 0x83:
        dst = this.getEALongDataWrite(this.regEBX + this.getIPAddr());
        break;
    case 0x84:
        dst = this.getEALongDataWrite(X86.modSIB.call(this, 2) + this.getIPAddr());
        break;
    case 0x85:
        dst = this.getEALongStackWrite(this.regEBP + this.getIPAddr());
        break;
    case 0x86:
        dst = this.getEALongDataWrite(this.regESI + this.getIPAddr());
        break;
    case 0x87:
        dst = this.getEALongDataWrite(this.regEDI + this.getIPAddr());
        break;
    case 0xC0:
        dst = this.regEAX;
        break;
    case 0xC1:
        dst = this.regECX;
        break;
    case 0xC2:
        dst = this.regEDX;
        break;
    case 0xC3:
        dst = this.regEBX;
        break;
    case 0xC4:
        dst = this.getSP();
        break;
    case 0xC5:
        dst = this.regEBP;
        break;
    case 0xC6:
        dst = this.regESI;
        break;
    case 0xC7:
        dst = this.regEDI;
        break;
    }

    let l = afnGrp[(bModRM >> 3) & 0x7].call(this, dst, fnSrc.call(this));

    switch(bModRM & 0xC7) {
    case 0xC0:
        this.regEAX = l;
        break;
    case 0xC1:
        this.regECX = l;
        break;
    case 0xC2:
        this.regEDX = l;
        break;
    case 0xC3:
        this.regEBX = l;
        break;
    case 0xC4:
        this.setSP(l);
        break;
    case 0xC5:
        this.regEBP = l;
        break;
    case 0xC6:
        this.regESI = l;
        break;
    case 0xC7:
        this.regEDI = l;
        break;
    default:
        this.setEALong(l);
        break;
    }
};

/**
 * modSIB(mod)
 *
 * @this {CPUx86}
 * @param {number} mod
 * @return {number}
 */
X86.modSIB = function(mod)
{
    let bSIB = this.getIPByte();
    let scale = bSIB >> 6, index, base;

    switch((bSIB >> 3) & 0x7) {
    case 0:
        index = this.regEAX;
        break;
    case 1:
        index = this.regECX;
        break;
    case 2:
        index = this.regEDX;
        break;
    case 3:
        index = this.regEBX;
        break;
    case 4:
        index = 0;
        break;
    case 5:
        index = this.regEBP;
        break;
    case 6:
        index = this.regESI;
        break;
    case 7:
        index = this.regEDI;
        break;
    }

    switch(bSIB & 0x07) {
    case 0:
        base = this.regEAX;
        break;
    case 1:
        base = this.regECX;
        break;
    case 2:
        base = this.regEDX;
        break;
    case 3:
        base = this.regEBX;
        break;
    case 4:
        base = this.getSP();
        this.segData = this.segStack;
        break;
    case 5:
        if (mod) {
            base = this.regEBP;
            this.segData = this.segStack;
        } else {
            base = this.getIPAddr();
        }
        break;
    case 6:
        base = this.regESI;
        break;
    case 7:
        base = this.regEDI;
        break;
    }

    return ((index << scale) + base)|0;
};

/**
 * @copyright https://www.pcjs.org/machines/pcx86/lib/x86ops.js (C) 2012-2021 Jeff Parsons
 */


/**
 * op=0x00 (ADD byte,reg)
 *
 * @this {CPUx86}
 */
X86.opADDmb = function()
{
    this.decodeModMemByte.call(this, X86.fnADDb);
    /*
     * Opcode bytes 0x00 0x00 are sufficiently uncommon that it's more likely we've started
     * executing in the weeds, so if you're in DEBUG mode, we'll print a warning and stop the
     * CPU if a Debugger is available.
     *
     * Notice that we also test fRunning: this allows the Debugger to step over the instruction,
     * because its trace ("t") command doesn't "run" the CPU; it merely "steps" the CPU.
     */
    if (DEBUG && !this.bModRM && this.flags.running) {
        this.printMessage("suspicious opcode: 0x00 0x00", DEBUGGER || this.bitsMessage);
        if (DEBUGGER && this.dbg) this.dbg.stopCPU();
    }
};

/**
 * op=0x01 (ADD word,reg)
 *
 * @this {CPUx86}
 */
X86.opADDmw = function()
{
    this.decodeModMemWord.call(this, X86.fnADDw);
};

/**
 * op=0x02 (ADD reg,byte)
 *
 * @this {CPUx86}
 */
X86.opADDrb = function()
{
    this.decodeModRegByte.call(this, X86.fnADDb);
};

/**
 * op=0x03 (ADD reg,word)
 *
 * @this {CPUx86}
 */
X86.opADDrw = function()
{
    this.decodeModRegWord.call(this, X86.fnADDw);
};

/**
 * op=0x04 (ADD AL,imm8)
 *
 * @this {CPUx86}
 */
X86.opADDALb = function()
{
    this.regEAX = (this.regEAX & ~0xff) | X86.fnADDb.call(this, this.regEAX & 0xff, this.getIPByte());
    /*
     * NOTE: Whenever the result is "blended" value (eg, of btiAL and btiMem0), a new bti should be
     * allocated to reflect that fact; however, I'm leaving "perfect" BACKTRACK support for another day.
     */
    if (BACKTRACK) this.backTrack.btiAL = this.backTrack.btiMem0;
    this.nStepCycles--;         // in the absence of any EA calculations, we need deduct only one more cycle
};

/**
 * op=0x05 (ADD AX,imm16 or ADD EAX,imm32)
 *
 * @this {CPUx86}
 */
X86.opADDAX = function()
{
    this.regEAX = (this.regEAX & ~this.maskData) | X86.fnADDw.call(this, this.regEAX & this.maskData, this.getIPWord());
    if (BACKTRACK) {
        this.backTrack.btiAL = this.backTrack.btiMem0; this.backTrack.btiAH = this.backTrack.btiMem1;
    }
    this.nStepCycles--;         // in the absence of any EA calculations, we need deduct only one more cycle
};

/**
 * op=0x06 (PUSH ES)
 *
 * @this {CPUx86}
 */
X86.opPUSHES = function()
{
    /*
     * When the OPERAND size is 32 bits, the 80386 will decrement the stack pointer by 4, write the selector
     * into the 2 lower bytes, and leave the 2 upper bytes untouched; to properly emulate that, we must use the
     * more generic pushData() instead of pushWord().
     */
    if (!I386) {
        this.pushWord(this.segES.sel);
    } else {
        this.pushData(this.segES.sel, this.sizeData, 2);
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesPushSeg;
};

/**
 * op=0x07 (POP ES)
 *
 * @this {CPUx86}
 */
X86.opPOPES = function()
{
    /*
     * Any operation that modifies the stack before loading a new segment must snapshot regLSP first.
     */
    this.opLSP = this.regLSP;
    this.setES(this.popWord());
    this.nStepCycles -= this.cycleCounts.nOpCyclesPopReg;
    this.opLSP = X86.ADDR_INVALID;
};

/**
 * op=0x08 (OR byte,reg)
 *
 * @this {CPUx86}
 */
X86.opORmb = function()
{
    this.decodeModMemByte.call(this, X86.fnORb);
};

/**
 * op=0x09 (OR word,reg)
 *
 * @this {CPUx86}
 */
X86.opORmw = function()
{
    this.decodeModMemWord.call(this, X86.fnORw);
};

/**
 * op=0x0A (OR reg,byte)
 *
 * @this {CPUx86}
 */
X86.opORrb = function()
{
    this.decodeModRegByte.call(this, X86.fnORb);
};

/**
 * op=0x0B (OR reg,word)
 *
 * @this {CPUx86}
 */
X86.opORrw = function()
{
    this.decodeModRegWord.call(this, X86.fnORw);
};

/**
 * op=0x0C (OR AL,imm8)
 *
 * @this {CPUx86}
 */
X86.opORALb = function()
{
    this.regEAX = (this.regEAX & ~0xff) | X86.fnORb.call(this, this.regEAX & 0xff, this.getIPByte());
    if (BACKTRACK) this.backTrack.btiAL = this.backTrack.btiMem0;
    this.nStepCycles--;         // in the absence of any EA calculations, we need deduct only one more cycle
};

/**
 * op=0x0D (OR AX,imm16 or OR EAX,imm32)
 *
 * @this {CPUx86}
 */
X86.opORAX = function()
{
    this.regEAX = (this.regEAX & ~this.maskData) | X86.fnORw.call(this, this.regEAX & this.maskData, this.getIPWord());
    if (BACKTRACK) {
        this.backTrack.btiAL = this.backTrack.btiMem0; this.backTrack.btiAH = this.backTrack.btiMem1;
    }
    this.nStepCycles--;         // in the absence of any EA calculations, we need deduct only one more cycle
};

/**
 * op=0x0E (PUSH CS)
 *
 * @this {CPUx86}
 */
X86.opPUSHCS = function()
{
    /*
     * When the OPERAND size is 32 bits, the 80386 will decrement the stack pointer by 4, write the selector
     * into the 2 lower bytes, and leave the 2 upper bytes untouched; to properly emulate that, we must use the
     * more generic pushData() instead of pushWord().
     */
    if (!I386) {
        this.pushWord(this.segCS.sel);
    } else {
        this.pushData(this.segCS.sel, this.sizeData, 2);
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesPushSeg;
};

/**
 * op=0x0F (POP CS) (undocumented on 8086/8088; replaced with opInvalid() on 80186/80188, and op0F() on 80286 and up)
 *
 * @this {CPUx86}
 */
X86.opPOPCS = function()
{
    /*
     * Because this is an 8088-only operation, we don't have to worry about taking a snapshot of regLSP first.
     */
    this.setCS(this.popWord());
    this.nStepCycles -= this.cycleCounts.nOpCyclesPopReg;
};

/**
 * op=0x0F (handler for two-byte opcodes; 80286 and up)
 *
 * @this {CPUx86}
 */
X86.op0F = function()
{
    this.aOps0F[this.getIPByte()].call(this);
};

/**
 * op=0x10 (ADC byte,reg)
 *
 * @this {CPUx86}
 */
X86.opADCmb = function()
{
    this.decodeModMemByte.call(this, X86.fnADCb);
};

/**
 * op=0x11 (ADC word,reg)
 *
 * @this {CPUx86}
 */
X86.opADCmw = function()
{
    this.decodeModMemWord.call(this, X86.fnADCw);
};

/**
 * op=0x12 (ADC reg,byte)
 *
 * @this {CPUx86}
 */
X86.opADCrb = function()
{
    this.decodeModRegByte.call(this, X86.fnADCb);
};

/**
 * op=0x13 (ADC reg,word)
 *
 * @this {CPUx86}
 */
X86.opADCrw = function()
{
    this.decodeModRegWord.call(this, X86.fnADCw);
};

/**
 * op=0x14 (ADC AL,imm8)
 *
 * @this {CPUx86}
 */
X86.opADCALb = function()
{
    this.regEAX = (this.regEAX & ~0xff) | X86.fnADCb.call(this, this.regEAX & 0xff, this.getIPByte());
    if (BACKTRACK) this.backTrack.btiAL = this.backTrack.btiMem0;
    this.nStepCycles--;         // in the absence of any EA calculations, we need deduct only one more cycle
};

/**
 * op=0x15 (ADC AX,imm16 or ADC EAX,imm32)
 *
 * @this {CPUx86}
 */
X86.opADCAX = function()
{
    this.regEAX = (this.regEAX & ~this.maskData) | X86.fnADCw.call(this, this.regEAX & this.maskData, this.getIPWord());
    if (BACKTRACK) {
        this.backTrack.btiAL = this.backTrack.btiMem0; this.backTrack.btiAH = this.backTrack.btiMem1;
    }
    this.nStepCycles--;         // in the absence of any EA calculations, we need deduct only one more cycle
};

/**
 * op=0x16 (PUSH SS)
 *
 * @this {CPUx86}
 */
X86.opPUSHSS = function()
{
    /*
     * When the OPERAND size is 32 bits, the 80386 will decrement the stack pointer by 4, write the selector
     * into the 2 lower bytes, and leave the 2 upper bytes untouched; to properly emulate that, we must use the
     * more generic pushData() instead of pushWord().
     */
    if (!I386) {
        this.pushWord(this.segSS.sel);
    } else {
        this.pushData(this.segSS.sel, this.sizeData, 2);
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesPushSeg;
};

/**
 * op=0x17 (POP SS)
 *
 * @this {CPUx86}
 */
X86.opPOPSS = function()
{
    /*
     * Any operation that modifies the stack before loading a new segment must snapshot regLSP first.
     */
    this.opLSP = this.regLSP;
    this.setSS(this.popWord());
    this.nStepCycles -= this.cycleCounts.nOpCyclesPopReg;
    this.opLSP = X86.ADDR_INVALID;
};

/**
 * op=0x18 (SBB byte,reg)
 *
 * @this {CPUx86}
 */
X86.opSBBmb = function()
{
    this.decodeModMemByte.call(this, X86.fnSBBb);
};

/**
 * op=0x19 (SBB word,reg)
 *
 * @this {CPUx86}
 */
X86.opSBBmw = function()
{
    this.decodeModMemWord.call(this, X86.fnSBBw);
};

/**
 * op=0x1A (SBB reg,byte)
 *
 * @this {CPUx86}
 */
X86.opSBBrb = function()
{
    this.decodeModRegByte.call(this, X86.fnSBBb);
};

/**
 * op=0x1B (SBB reg,word)
 *
 * @this {CPUx86}
 */
X86.opSBBrw = function()
{
    this.decodeModRegWord.call(this, X86.fnSBBw);
};

/**
 * op=0x1C (SBB AL,imm8)
 *
 * @this {CPUx86}
 */
X86.opSBBALb = function()
{
    this.regEAX = (this.regEAX & ~0xff) | X86.fnSBBb.call(this, this.regEAX & 0xff, this.getIPByte());
    if (BACKTRACK) this.backTrack.btiAL = this.backTrack.btiMem0;
    this.nStepCycles--;         // in the absence of any EA calculations, we need deduct only one more cycle
};

/**
 * op=0x1D (SBB AX,imm16 or SBB EAX,imm32)
 *
 * @this {CPUx86}
 */
X86.opSBBAX = function()
{
    this.regEAX = (this.regEAX & ~this.maskData) | X86.fnSBBw.call(this, this.regEAX & this.maskData, this.getIPWord());
    if (BACKTRACK) {
        this.backTrack.btiAL = this.backTrack.btiMem0; this.backTrack.btiAH = this.backTrack.btiMem1;
    }
    this.nStepCycles--;         // in the absence of any EA calculations, we need deduct only one more cycle
};

/**
 * op=0x1E (PUSH DS)
 *
 * @this {CPUx86}
 */
X86.opPUSHDS = function()
{
    /*
     * When the OPERAND size is 32 bits, the 80386 will decrement the stack pointer by 4, write the selector
     * into the 2 lower bytes, and leave the 2 upper bytes untouched; to properly emulate that, we must use the
     * more generic pushData() instead of pushWord().
     */
    if (!I386) {
        this.pushWord(this.segDS.sel);
    } else {
        this.pushData(this.segDS.sel, this.sizeData, 2);
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesPushSeg;
};

/**
 * op=0x1F (POP DS)
 *
 * @this {CPUx86}
 */
X86.opPOPDS = function()
{
    /*
     * Any operation that modifies the stack before loading a new segment must snapshot regLSP first.
     */
    this.opLSP = this.regLSP;
    this.setDS(this.popWord());
    this.nStepCycles -= this.cycleCounts.nOpCyclesPopReg;
    this.opLSP = X86.ADDR_INVALID;
};

/**
 * op=0x20 (AND byte,reg)
 *
 * @this {CPUx86}
 */
X86.opANDmb = function()
{
    this.decodeModMemByte.call(this, X86.fnANDb);
};

/**
 * op=0x21 (AND word,reg)
 *
 * @this {CPUx86}
 */
X86.opANDmw = function()
{
    this.decodeModMemWord.call(this, X86.fnANDw);
};

/**
 * op=0x22 (AND reg,byte)
 *
 * @this {CPUx86}
 */
X86.opANDrb = function()
{
    this.decodeModRegByte.call(this, X86.fnANDb);
};

/**
 * op=0x23 (AND reg,word)
 *
 * @this {CPUx86}
 */
X86.opANDrw = function()
{
    this.decodeModRegWord.call(this, X86.fnANDw);
};

/**
 * op=0x24 (AND AL,imm8)
 *
 * @this {CPUx86}
 */
X86.opANDAL = function()
{
    this.regEAX = (this.regEAX & ~0xff) | X86.fnANDb.call(this, this.regEAX & 0xff, this.getIPByte());
    if (BACKTRACK) this.backTrack.btiAL = this.backTrack.btiMem0;
    this.nStepCycles--;         // in the absence of any EA calculations, we need deduct only one more cycle
};

/**
 * op=0x25 (AND AX,imm16 or AND EAX,imm32)
 *
 * @this {CPUx86}
 */
X86.opANDAX = function()
{
    this.regEAX = (this.regEAX & ~this.maskData) | X86.fnANDw.call(this, this.regEAX & this.maskData, this.getIPWord());
    if (BACKTRACK) {
        this.backTrack.btiAL = this.backTrack.btiMem0; this.backTrack.btiAH = this.backTrack.btiMem1;
    }
    this.nStepCycles--;         // in the absence of any EA calculations, we need deduct only one more cycle
};

/**
 * op=0x26 (ES:)
 *
 * @this {CPUx86}
 */
X86.opES = function()
{
    this.opFlags |= X86.OPFLAG.SEG | X86.OPFLAG.NOINTR;
    this.segData = this.segStack = this.segES;
    this.nStepCycles -= this.cycleCounts.nOpCyclesPrefix;
};

/**
 * op=0x27 (DAA)
 *
 * @this {CPUx86}
 */
X86.opDAA = function()
{
    let AL = this.regEAX & 0xff;
    let AF = this.getAF();
    let CF = this.getCF();
    if ((AL & 0xf) > 9 || AF) {
        AL += 0x6;
        AF = X86.PS.AF;
    } else {
        AF = 0;
    }
    if (AL > 0x9f || CF) {
        AL += 0x60;
        CF = X86.PS.CF;
    } else {
        CF = 0;
    }
    let b = (AL & 0xff);
    this.regEAX = (this.regEAX & ~0xff) | b;
    this.setLogicResult(b, X86.RESULT.BYTE);
    if (CF) this.setCF(); else this.clearCF();
    if (AF) this.setAF(); else this.clearAF();
    this.nStepCycles -= this.cycleCounts.nOpCyclesAAA;          // AAA and DAA have the same cycle times
};

/**
 * op=0x28 (SUB byte,reg)
 *
 * @this {CPUx86}
 */
X86.opSUBmb = function()
{
    this.decodeModMemByte.call(this, X86.fnSUBb);
};

/**
 * op=0x29 (SUB word,reg)
 *
 * @this {CPUx86}
 */
X86.opSUBmw = function()
{
    this.decodeModMemWord.call(this, X86.fnSUBw);
};

/**
 * op=0x2A (SUB reg,byte)
 *
 * @this {CPUx86}
 */
X86.opSUBrb = function()
{
    this.decodeModRegByte.call(this, X86.fnSUBb);
};

/**
 * op=0x2B (SUB reg,word)
 *
 * @this {CPUx86}
 */
X86.opSUBrw = function()
{
    this.decodeModRegWord.call(this, X86.fnSUBw);
};

/**
 * op=0x2C (SUB AL,imm8)
 *
 * @this {CPUx86}
 */
X86.opSUBALb = function()
{
    this.regEAX = (this.regEAX & ~0xff) | X86.fnSUBb.call(this, this.regEAX & 0xff, this.getIPByte());
    if (BACKTRACK) this.backTrack.btiAL = this.backTrack.btiMem0;
    this.nStepCycles--;         // in the absence of any EA calculations, we need deduct only one more cycle
};

/**
 * op=0x2D (SUB AX,imm16 or SUB EAX,imm32)
 *
 * @this {CPUx86}
 */
X86.opSUBAX = function()
{
    this.regEAX = (this.regEAX & ~this.maskData) | X86.fnSUBw.call(this, this.regEAX & this.maskData, this.getIPWord());
    if (BACKTRACK) {
        this.backTrack.btiAL = this.backTrack.btiMem0; this.backTrack.btiAH = this.backTrack.btiMem1;
    }
    this.nStepCycles--;         // in the absence of any EA calculations, we need deduct only one more cycle
};

/**
 * op=0x2E (CS:)
 *
 * @this {CPUx86}
 */
X86.opCS = function()
{
    this.opFlags |= X86.OPFLAG.SEG | X86.OPFLAG.NOINTR;
    this.segData = this.segStack = this.segCS;
    this.nStepCycles -= this.cycleCounts.nOpCyclesPrefix;
};

/**
 * op=0x2F (DAS)
 *
 * @this {CPUx86}
 */
X86.opDAS = function()
{
    let AL = this.regEAX & 0xff;
    let AF = this.getAF();
    let CF = this.getCF();
    if ((AL & 0xf) > 9 || AF) {
        AL -= 0x6;
        AF = X86.PS.AF;
    } else {
        AF = 0;
    }
    if (AL > 0x9f || CF) {
        AL -= 0x60;
        CF = X86.PS.CF;
    } else {
        CF = 0;
    }
    let b = (AL & 0xff);
    this.regEAX = (this.regEAX & ~0xff) | b;
    this.setLogicResult(b, X86.RESULT.BYTE);
    if (CF) this.setCF(); else this.clearCF();
    if (AF) this.setAF(); else this.clearAF();
    this.nStepCycles -= this.cycleCounts.nOpCyclesAAA;          // AAA and DAS have the same cycle times
};

/**
 * op=0x30 (XOR byte,reg)
 *
 * @this {CPUx86}
 */
X86.opXORmb = function()
{
    this.decodeModMemByte.call(this, X86.fnXORb);
};

/**
 * op=0x31 (XOR word,reg)
 *
 * @this {CPUx86}
 */
X86.opXORmw = function()
{
    this.decodeModMemWord.call(this, X86.fnXORw);
};

/**
 * op=0x32 (XOR reg,byte)
 *
 * @this {CPUx86}
 */
X86.opXORrb = function()
{
    this.decodeModRegByte.call(this, X86.fnXORb);
};

/**
 * op=0x33 (XOR reg,word)
 *
 * @this {CPUx86}
 */
X86.opXORrw = function()
{
    this.decodeModRegWord.call(this, X86.fnXORw);
};

/**
 * op=0x34 (XOR AL,imm8)
 *
 * @this {CPUx86}
 */
X86.opXORALb = function()
{
    this.regEAX = (this.regEAX & ~0xff) | X86.fnXORb.call(this, this.regEAX & 0xff, this.getIPByte());
    if (BACKTRACK) this.backTrack.btiAL = this.backTrack.btiMem0;
    this.nStepCycles--;         // in the absence of any EA calculations, we need deduct only one more cycle
};

/**
 * op=0x35 (XOR AX,imm16 or XOR EAX,imm32)
 *
 * @this {CPUx86}
 */
X86.opXORAX = function()
{
    this.regEAX = (this.regEAX & ~this.maskData) | X86.fnXORw.call(this, this.regEAX & this.maskData, this.getIPWord());
    if (BACKTRACK) {
        this.backTrack.btiAL = this.backTrack.btiMem0; this.backTrack.btiAH = this.backTrack.btiMem1;
    }
    this.nStepCycles--;         // in the absence of any EA calculations, we need deduct only one more cycle
};

/**
 * op=0x36 (SS:)
 *
 * @this {CPUx86}
 */
X86.opSS = function()
{
    this.opFlags |= X86.OPFLAG.SEG | X86.OPFLAG.NOINTR;
    this.segData = this.segStack = this.segSS;      // QUESTION: Is there a case where segStack would not already be segSS? (eg, multiple segment overrides?)
    this.nStepCycles -= this.cycleCounts.nOpCyclesPrefix;
};

/**
 * op=0x37 (AAA)
 *
 * @this {CPUx86}
 */
X86.opAAA = function()
{
    let CF, AF;
    let AL = this.regEAX & 0xff;
    let AH = (this.regEAX >> 8) & 0xff;
    if ((AL & 0xf) > 9 || this.getAF()) {
        AL += 6;
        /*
         * Simulate the fact that the 80286 and higher add 6 to AX rather than AL.
         */
        if (this.model >= X86.MODEL_80286 && AL > 0xff) AH++;
        AH++;
        CF = AF = 1;
    } else {
        CF = AF = 0;
    }
    this.regEAX = (this.regEAX & ~0xffff) | (((AH << 8) | AL) & 0xff0f);
    if (CF) this.setCF(); else this.clearCF();
    if (AF) this.setAF(); else this.clearAF();
    this.nStepCycles -= this.cycleCounts.nOpCyclesAAA;
};

/**
 * op=0x38 (CMP byte,reg)
 *
 * @this {CPUx86}
 */
X86.opCMPmb = function()
{
    this.decodeModMemByte.call(this, X86.fnCMPb);
};

/**
 * op=0x39 (CMP word,reg)
 *
 * @this {CPUx86}
 */
X86.opCMPmw = function()
{
    this.decodeModMemWord.call(this, X86.fnCMPw);
};

/**
 * op=0x3A (CMP reg,byte)
 *
 * @this {CPUx86}
 */
X86.opCMPrb = function()
{
    this.decodeModRegByte.call(this, X86.fnCMPb);
};

/**
 * op=0x3B (CMP reg,word)
 *
 * @this {CPUx86}
 */
X86.opCMPrw = function()
{
    this.decodeModRegWord.call(this, X86.fnCMPw);
};

/**
 * op=0x3C (CMP AL,imm8)
 *
 * @this {CPUx86}
 */
X86.opCMPALb = function()
{
    X86.fnCMPb.call(this, this.regEAX & 0xff, this.getIPByte());
    this.nStepCycles--;         // in the absence of any EA calculations, we need deduct only one more cycle
};

/**
 * op=0x3D (CMP AX,imm16 or CMP EAX,imm32)
 *
 * @this {CPUx86}
 */
X86.opCMPAX = function()
{
    X86.fnCMPw.call(this, this.regEAX & this.maskData, this.getIPWord());
    this.nStepCycles--;         // in the absence of any EA calculations, we need deduct only one more cycle
};

/**
 * op=0x3E (DS:)
 *
 * @this {CPUx86}
 */
X86.opDS = function()
{
    this.opFlags |= X86.OPFLAG.SEG | X86.OPFLAG.NOINTR;
    this.segData = this.segStack = this.segDS;      // QUESTION: Is there a case where segData would not already be segDS? (eg, multiple segment overrides?)
    this.nStepCycles -= this.cycleCounts.nOpCyclesPrefix;
};

/**
 * op=0x3D (AAS)
 *
 * @this {CPUx86}
 */
X86.opAAS = function()
{
    let CF, AF;
    let AL = this.regEAX & 0xff;
    let AH = (this.regEAX >> 8) & 0xff;
    if ((AL & 0xf) > 9 || this.getAF()) {
        AL = (AL - 0x6) & 0xf;
        AH = (AH - 1) & 0xff;
        CF = AF = 1;
    } else {
        CF = AF = 0;
    }
    this.regEAX = (this.regEAX & ~0xffff) | ((AH << 8) | AL);
    if (CF) this.setCF(); else this.clearCF();
    if (AF) this.setAF(); else this.clearAF();
    this.nStepCycles -= this.cycleCounts.nOpCyclesAAA;   // AAA and AAS have the same cycle times
};

/**
 * op=0x40 (INC [E]AX)
 *
 * @this {CPUx86}
 */
X86.opINCAX = function()
{
    this.regEAX = X86.helpINCreg.call(this, this.regEAX);
};

/**
 * op=0x41 (INC [E]CX)
 *
 * @this {CPUx86}
 */
X86.opINCCX = function()
{
    this.regECX = X86.helpINCreg.call(this, this.regECX);
};

/**
 * op=0x42 (INC [E]DX)
 *
 * @this {CPUx86}
 */
X86.opINCDX = function()
{
    this.regEDX = X86.helpINCreg.call(this, this.regEDX);
};

/**
 * op=0x43 (INC [E]BX)
 *
 * @this {CPUx86}
 */
X86.opINCBX = function()
{
    this.regEBX = X86.helpINCreg.call(this, this.regEBX);
};

/**
 * op=0x44 (INC [E]SP)
 *
 * @this {CPUx86}
 */
X86.opINCSP = function()
{
    this.setSP(X86.helpINCreg.call(this, this.getSP()));
};

/**
 * op=0x45 (INC [E]BP)
 *
 * @this {CPUx86}
 */
X86.opINCBP = function()
{
    this.regEBP = X86.helpINCreg.call(this, this.regEBP);
};

/**
 * op=0x46 (INC [E]SI)
 *
 * @this {CPUx86}
 */
X86.opINCSI = function()
{
    this.regESI = X86.helpINCreg.call(this, this.regESI);
};

/**
 * op=0x47 (INC [E]DI)
 *
 * @this {CPUx86}
 */
X86.opINCDI = function()
{
    this.regEDI = X86.helpINCreg.call(this, this.regEDI);
};

/**
 * op=0x48 (DEC [E]AX)
 *
 * @this {CPUx86}
 */
X86.opDECAX = function()
{
    this.regEAX = X86.helpDECreg.call(this, this.regEAX);
};

/**
 * op=0x49 (DEC [E]CX)
 *
 * @this {CPUx86}
 */
X86.opDECCX = function()
{
    this.regECX = X86.helpDECreg.call(this, this.regECX);
};

/**
 * op=0x4A (DEC [E]DX)
 *
 * @this {CPUx86}
 */
X86.opDECDX = function()
{
    this.regEDX = X86.helpDECreg.call(this, this.regEDX);
};

/**
 * op=0x4B (DEC [E]BX)
 *
 * @this {CPUx86}
 */
X86.opDECBX = function()
{
    this.regEBX = X86.helpDECreg.call(this, this.regEBX);
};

/**
 * op=0x4C (DEC [E]SP)
 *
 * @this {CPUx86}
 */
X86.opDECSP = function()
{
    this.setSP(X86.helpDECreg.call(this, this.getSP()));
};

/**
 * op=0x4D (DEC [E]BP)
 *
 * @this {CPUx86}
 */
X86.opDECBP = function()
{
    this.regEBP = X86.helpDECreg.call(this, this.regEBP);
};

/**
 * op=0x4E (DEC [E]SI)
 *
 * @this {CPUx86}
 */
X86.opDECSI = function()
{
    this.regESI = X86.helpDECreg.call(this, this.regESI);
};

/**`
 * op=0x4F (DEC [E]DI)
 *
 * @this {CPUx86}
 */
X86.opDECDI = function()
{
    this.regEDI = X86.helpDECreg.call(this, this.regEDI);
};

/**
 * op=0x50 (PUSH [E]AX)
 *
 * @this {CPUx86}
 */
X86.opPUSHAX = function()
{
    if (BACKTRACK) {
        this.backTrack.btiMem0 = this.backTrack.btiAL; this.backTrack.btiMem1 = this.backTrack.btiAH;
    }
    this.pushWord(this.regEAX & this.maskData);
    this.nStepCycles -= this.cycleCounts.nOpCyclesPushReg;
};

/**
 * op=0x51 (PUSH [E]CX)
 *
 * @this {CPUx86}
 */
X86.opPUSHCX = function()
{
    if (BACKTRACK) {
        this.backTrack.btiMem0 = this.backTrack.btiCL; this.backTrack.btiMem1 = this.backTrack.btiCH;
    }
    this.pushWord(this.regECX & this.maskData);
    this.nStepCycles -= this.cycleCounts.nOpCyclesPushReg;
};

/**
 * op=0x52 (PUSH [E]DX)
 *
 * @this {CPUx86}
 */
X86.opPUSHDX = function()
{
    if (BACKTRACK) {
        this.backTrack.btiMem0 = this.backTrack.btiDL; this.backTrack.btiMem1 = this.backTrack.btiDH;
    }
    this.pushWord(this.regEDX & this.maskData);
    this.nStepCycles -= this.cycleCounts.nOpCyclesPushReg;
};

/**
 * op=0x53 (PUSH [E]BX)
 *
 * @this {CPUx86}
 */
X86.opPUSHBX = function()
{
    if (BACKTRACK) {
        this.backTrack.btiMem0 = this.backTrack.btiBL; this.backTrack.btiMem1 = this.backTrack.btiBH;
    }
    this.pushWord(this.regEBX & this.maskData);
    this.nStepCycles -= this.cycleCounts.nOpCyclesPushReg;
};

/**
 * op=0x54 (PUSH SP)
 *
 * NOTE: Having an accurate implementation of "PUSH SP" for the 8086/8088 isn't just a nice idea, it affects real
 * code.  Case in point: early Microsoft C floating-point libraries relied on "PUSH SP" behavior to quickly determine
 * whether an 8088 (and therefore presumably an 8087) or an 80286 (and presumably an 80287) was being used; eg:
 *
 *      &0910:1E82 D93E1709        FSTCW    WORD [0917]
 *      &0910:1E86 CD3D            INT      3D
 *      &0E4E:06D3 50              PUSH     AX
 *      &0E4E:06D4 B83DA2          MOV      AX,A23D
 *      &0E4E:06D7 EB04            JMP      06DD
 *      &0E4E:06DD 55              PUSH     BP
 *      &0E4E:06DE 1E              PUSH     DS
 *      &0E4E:06DF 56              PUSH     SI
 *      &0E4E:06E0 8BEC            MOV      BP,SP
 *      &0E4E:06E2 C57608          LDS      SI,[BP+08]
 *      &0E4E:06E5 4E              DEC      SI
 *      &0E4E:06E6 4E              DEC      SI
 *      &0E4E:06E7 897608          MOV      [BP+08],SI
 *      &0E4E:06EA 2904            SUB      [SI],AX
 *      &0E4E:06EC 53              PUSH     BX
 *      &0E4E:06ED 33DB            XOR      BX,BX
 *      &0E4E:06EF 54              PUSH     SP          ; beginning of processor check
 *      &0E4E:06F0 58              POP      AX
 *      &0E4E:06F1 3BC4            CMP      AX,SP
 *      &0E4E:06F3 7528            JNZ      071D        ; jump if 8086/8088/80186/80188, no jump if 80286 or later
 *      &0E4E:06F5 8B4001          MOV      AX,[BX+SI+01]
 *      &0E4E:06F8 25FB30          AND      AX,30FB
 *      &0E4E:06FB 3DD930          CMP      AX,30D9
 *      &0E4E:06FE 7507            JNZ      0707
 *      &0E4E:0700 8A4002          MOV      AL,[BX+SI+02]
 *      &0E4E:0703 3CF0            CMP      AL,F0
 *      &0E4E:0705 7216            JC       071D
 *      &0E4E:0707 8B4001          MOV      AX,[BX+SI+01]
 *      &0E4E:070A 25FFFE          AND      AX,FEFF
 *      &0E4E:070D 3DDBE2          CMP      AX,E2DB
 *      &0E4E:0710 740B            JZ       071D
 *      &0E4E:0712 8B4001          MOV      AX,[BX+SI+01]
 *      &0E4E:0715 3DDFE0          CMP      AX,E0DF
 *      &0E4E:0718 7403            JZ       071D
 *      &0E4E:071A C60490          MOV      [SI],90
 *      &0E4E:071D 5B              POP      BX
 *      &0E4E:071E 5E              POP      SI
 *      &0E4E:071F 1F              POP      DS
 *      &0E4E:0720 5D              POP      BP
 *      &0E4E:0721 58              POP      AX
 *      &0E4E:0722 CF              IRET
 *
 * @this {CPUx86}
 */
X86.opPUSHSP_8086 = function()
{
    let w = (this.getSP() - 2) & 0xffff;
    this.pushWord(w);
    this.nStepCycles -= this.cycleCounts.nOpCyclesPushReg;
};

/**
 * op=0x54 (PUSH [E]SP)
 *
 * @this {CPUx86}
 */
X86.opPUSHSP = function()
{
    this.pushWord(this.getSP() & this.maskData);
    this.nStepCycles -= this.cycleCounts.nOpCyclesPushReg;
};

/**
 * op=0x55 (PUSH [E]BP)
 *
 * @this {CPUx86}
 */
X86.opPUSHBP = function()
{
    if (BACKTRACK) {
        this.backTrack.btiMem0 = this.backTrack.btiBPLo; this.backTrack.btiMem1 = this.backTrack.btiBPHi;
    }
    this.pushWord(this.regEBP & this.maskData);
    this.nStepCycles -= this.cycleCounts.nOpCyclesPushReg;
};

/**
 * op=0x56 (PUSH [E]SI)
 *
 * @this {CPUx86}
 */
X86.opPUSHSI = function()
{
    if (BACKTRACK) {
        this.backTrack.btiMem0 = this.backTrack.btiSILo; this.backTrack.btiMem1 = this.backTrack.btiSIHi;
    }
    this.pushWord(this.regESI & this.maskData);
    this.nStepCycles -= this.cycleCounts.nOpCyclesPushReg;
};

/**
 * op=0x57 (PUSH [E]DI)
 *
 * @this {CPUx86}
 */
X86.opPUSHDI = function()
{
    if (BACKTRACK) {
        this.backTrack.btiMem0 = this.backTrack.btiDILo; this.backTrack.btiMem1 = this.backTrack.btiDIHi;
    }
    this.pushWord(this.regEDI & this.maskData);
    this.nStepCycles -= this.cycleCounts.nOpCyclesPushReg;
};

/**
 * op=0x58 (POP [E]AX)
 *
 * @this {CPUx86}
 */
X86.opPOPAX = function()
{
    this.regEAX = (this.regEAX & ~this.maskData) | this.popWord();
    if (BACKTRACK) {
        this.backTrack.btiAL = this.backTrack.btiMem0; this.backTrack.btiAH = this.backTrack.btiMem1;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesPopReg;
};

/**
 * op=0x59 (POP [E]CX)
 *
 * @this {CPUx86}
 */
X86.opPOPCX = function()
{
    this.regECX = (this.regECX & ~this.maskData) | this.popWord();
    if (BACKTRACK) {
        this.backTrack.btiCL = this.backTrack.btiMem0; this.backTrack.btiCH = this.backTrack.btiMem1;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesPopReg;
};

/**
 * op=0x5A (POP [E]DX)
 *
 * @this {CPUx86}
 */
X86.opPOPDX = function()
{
    this.regEDX = (this.regEDX & ~this.maskData) | this.popWord();
    if (BACKTRACK) {
        this.backTrack.btiDL = this.backTrack.btiMem0; this.backTrack.btiDH = this.backTrack.btiMem1;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesPopReg;
};

/**
 * op=0x5B (POP [E]BX)
 *
 * @this {CPUx86}
 */
X86.opPOPBX = function()
{
    this.regEBX = (this.regEBX & ~this.maskData) | this.popWord();
    if (BACKTRACK) {
        this.backTrack.btiBL = this.backTrack.btiMem0; this.backTrack.btiBH = this.backTrack.btiMem1;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesPopReg;
};

/**
 * op=0x5C (POP [E]SP)
 *
 * @this {CPUx86}
 */
X86.opPOPSP = function()
{
    this.setSP((this.getSP() & ~this.maskData) | this.popWord());
    this.nStepCycles -= this.cycleCounts.nOpCyclesPopReg;
};

/**
 * op=0x5D (POP [E]BP)
 *
 * @this {CPUx86}
 */
X86.opPOPBP = function()
{
    this.regEBP = (this.regEBP & ~this.maskData) | this.popWord();
    if (BACKTRACK) {
        this.backTrack.btiBPLo = this.backTrack.btiMem0; this.backTrack.btiBPHi = this.backTrack.btiMem1;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesPopReg;
};

/**
 * op=0x5E (POP [E]SI)
 *
 * @this {CPUx86}
 */
X86.opPOPSI = function()
{
    this.regESI = (this.regESI & ~this.maskData) | this.popWord();
    if (BACKTRACK) {
        this.backTrack.btiSILo = this.backTrack.btiMem0; this.backTrack.btiSIHi = this.backTrack.btiMem1;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesPopReg;
};

/**
 * op=0x5F (POP [E]DI)
 *
 * @this {CPUx86}
 */
X86.opPOPDI = function()
{
    this.regEDI = (this.regEDI & ~this.maskData) | this.popWord();
    if (BACKTRACK) {
        this.backTrack.btiDILo = this.backTrack.btiMem0; this.backTrack.btiDIHi = this.backTrack.btiMem1;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesPopReg;
};

/**
 * op=0x60 (PUSHA) (80186/80188 and up)
 *
 * @this {CPUx86}
 */
X86.opPUSHA = function()
{
    /*
     * Any operation that performs multiple stack modifications must snapshot regLSP first.
     */
    this.opLSP = this.regLSP;

    /*
     * TODO: regLSP needs to be pre-bounds-checked against regLSPLimitLow
     */
    let temp = this.getSP() & this.maskData;
    if (BACKTRACK) {
        this.backTrack.btiMem0 = this.backTrack.btiAL; this.backTrack.btiMem1 = this.backTrack.btiAH;
    }
    this.pushWord(this.regEAX & this.maskData);
    if (BACKTRACK) {
        this.backTrack.btiMem0 = this.backTrack.btiCL; this.backTrack.btiMem1 = this.backTrack.btiCH;
    }
    this.pushWord(this.regECX & this.maskData);
    if (BACKTRACK) {
        this.backTrack.btiMem0 = this.backTrack.btiDL; this.backTrack.btiMem1 = this.backTrack.btiDH;
    }
    this.pushWord(this.regEDX & this.maskData);
    if (BACKTRACK) {
        this.backTrack.btiMem0 = this.backTrack.btiBL; this.backTrack.btiMem1 = this.backTrack.btiBH;
    }
    this.pushWord(this.regEBX & this.maskData);
    this.pushWord(temp);
    if (BACKTRACK) {
        this.backTrack.btiMem0 = this.backTrack.btiBPLo; this.backTrack.btiMem1 = this.backTrack.btiBPHi;
    }
    this.pushWord(this.regEBP & this.maskData);
    if (BACKTRACK) {
        this.backTrack.btiMem0 = this.backTrack.btiSILo; this.backTrack.btiMem1 = this.backTrack.btiSIHi;
    }
    this.pushWord(this.regESI & this.maskData);
    if (BACKTRACK) {
        this.backTrack.btiMem0 = this.backTrack.btiDILo; this.backTrack.btiMem1 = this.backTrack.btiDIHi;
    }
    this.pushWord(this.regEDI & this.maskData);
    this.nStepCycles -= this.cycleCounts.nOpCyclesPushAll;

    this.opLSP = X86.ADDR_INVALID;
};

/**
 * op=0x61 (POPA) (80186/80188 and up)
 *
 * @this {CPUx86}
 */
X86.opPOPA = function()
{
    /*
     * Any operation that performs multiple stack modifications must snapshot regLSP first.
     */
    this.opLSP = this.regLSP;

    this.regEDI = (this.regEDI & ~this.maskData) | this.popWord();
    if (BACKTRACK) {
        this.backTrack.btiDILo = this.backTrack.btiMem0; this.backTrack.btiDIHi = this.backTrack.btiMem1;
    }
    this.regESI = (this.regESI & ~this.maskData) | this.popWord();
    if (BACKTRACK) {
        this.backTrack.btiSILo = this.backTrack.btiMem0; this.backTrack.btiSIHi = this.backTrack.btiMem1;
    }
    this.regEBP = (this.regEBP & ~this.maskData) | this.popWord();
    if (BACKTRACK) {
        this.backTrack.btiBPLo = this.backTrack.btiMem0; this.backTrack.btiBPHi = this.backTrack.btiMem1;
    }
    /*
     * TODO: regLSP needs to be pre-bounds-checked against regLSPLimit at the start
     */
    this.setSP(this.getSP() + this.sizeData);
    // this.regLSP += (I386? this.sizeData : 2);
    this.regEBX = (this.regEBX & ~this.maskData) | this.popWord();
    if (BACKTRACK) {
        this.backTrack.btiBL = this.backTrack.btiMem0; this.backTrack.btiBH = this.backTrack.btiMem1;
    }
    this.regEDX = (this.regEDX & ~this.maskData) | this.popWord();
    if (BACKTRACK) {
        this.backTrack.btiDL = this.backTrack.btiMem0; this.backTrack.btiDH = this.backTrack.btiMem1;
    }
    this.regECX = (this.regECX & ~this.maskData) | this.popWord();
    if (BACKTRACK) {
        this.backTrack.btiCL = this.backTrack.btiMem0; this.backTrack.btiCH = this.backTrack.btiMem1;
    }
    this.regEAX = (this.regEAX & ~this.maskData) | this.popWord();
    if (BACKTRACK) {
        this.backTrack.btiAL = this.backTrack.btiMem0; this.backTrack.btiAH = this.backTrack.btiMem1;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesPopAll;

    this.opLSP = X86.ADDR_INVALID;
};

/**
 * op=0x62 (BOUND reg,word) (80186/80188 and up)
 *
 * @this {CPUx86}
 */
X86.opBOUND = function()
{
    this.decodeModRegWord.call(this, X86.fnBOUND);
};

/**
 * op=0x63 (ARPL word,reg) (80286 and up)
 *
 * @this {CPUx86}
 */
X86.opARPL = function()
{
    /*
     * ARPL is one of several protected-mode instructions that are meaningless and not allowed in either real-mode
     * or V86-mode; others include LAR, LSL, VERR and VERW.  More meaningful but potentially harmful protected-mode
     * instructions that ARE allowed in real-mode but NOT in V86-mode include LIDT, LGDT, LMSW, CLTS, HLT, and
     * control register MOV instructions.
     *
     * ARPL is somewhat more noteworthy because enhanced-mode Windows (going back to at least Windows 3.00, and
     * possibly even the earliest versions of Windows/386) selected the ARPL opcode as a controlled means of exiting
     * V86-mode via the UD_FAULT exception.  Windows would use the same ARPL for all controlled exits, using different
     * segment:offset pointers to the ARPL to differentiate them.  ARPL was probably chosen because it could trigger
     * a UD_FAULT with a single byte (0x63); any subsequent address bytes would be irrelevant.
     *
     * Which is WHY we must perform the CPU mode tests below rather than in the fnARPL() worker; otherwise we could
     * generate additional (bogus) faults, based on the address of the first operand.
     *
     * TODO: You may have noticed that setProtMode() already swaps out a 0x0F opcode dispatch table for another based
     * on the mode, because none of the "GRP6" 0x0F opcodes (eg, SLDT, STR, LLDT, LTR, VERR and VERW) are allowed in
     * real-mode, and it was easy to swap all those handlers in/out with a single update.  We've extended that particular
     * swap to include V86-mode as well, but we might want to consider swapping out more opcode handlers in a similar
     * fashion, instead of using these in-line mode tests.
     */
    if (!(this.regCR0 & X86.CR0.MSW.PE) || I386 && (this.regPS & X86.PS.VM)) {
        X86.opInvalid.call(this);
        return;
    }
    this.decodeModMemWord.call(this, X86.fnARPL);
};

/**
 * op=0x64 (FS:)
 *
 * @this {CPUx86}
 */
X86.opFS = function()
{
    this.opFlags |= X86.OPFLAG.SEG | X86.OPFLAG.NOINTR;
    this.segData = this.segStack = this.segFS;
    this.nStepCycles -= this.cycleCounts.nOpCyclesPrefix;
};

/**
 * op=0x65 (GS:)
 *
 * @this {CPUx86}
 */
X86.opGS = function()
{
    this.opFlags |= X86.OPFLAG.SEG | X86.OPFLAG.NOINTR;
    this.segData = this.segStack = this.segGS;
    this.nStepCycles -= this.cycleCounts.nOpCyclesPrefix;
};

/**
 * op=0x66 (OS:) (80386 and up)
 *
 * TODO: Review other effective operand-size criteria, cycle count, etc.
 *
 * @this {CPUx86}
 */
X86.opOS = function()
{
    if (I386) {
        /*
         * See opAS() for a discussion of multiple prefixes, which applies equally to both
         * operand-size and address-size prefixes.
         *
         * The simple fix here is to skip the bulk of the operation if the prefix is redundant.
         */
        this.opFlags |= X86.OPFLAG.DATASIZE;
        if (!(this.opPrefixes & X86.OPFLAG.DATASIZE)) {
            this.sizeData ^= 0x6;               // that which is 2 shall become 4, and vice versa
            this.maskData ^= (0xffff0000|0);    // that which is 0x0000ffff shall become 0xffffffff, and vice versa
            this.updateDataSize();
        }
        this.nStepCycles -= this.cycleCounts.nOpCyclesPrefix;
    }
};

/**
 * op=0x67 (AS:) (80386 and up)
 *
 * TODO: Review other effective address-size criteria, cycle count, etc.
 *
 * @this {CPUx86}
 */
X86.opAS = function()
{
    if (I386) {
        /*
         * Live and learn: multiple address-size prefixes can and do occur on a single instruction,
         * and contrary to my original assumption that the prefixes act independently, they do not.
         * During Windows 95 SETUP, the following instruction is executed:
         *
         *      06AF:1B4D 67672E          CS:
         *      06AF:1B50 FFA25A1B        JMP      [BP+SI+1B5A]
         *
         * which is in fact:
         *
         *      06AF:1B4D 67672E          CS:
         *      06AF:1B50 FFA25A1B0000    JMP      [EDX+00001B5A]
         *
         * The other interesting question is: why/how did this instruction get encoded that way?
         * All I can say is, there were no explicit prefixes in the source (BSG.ASM), so we'll chalk
         * it up to a glitch in MASM.
         *
         * The simple fix here is to skip the bulk of the operation if the prefix is redundant.
         */
        this.opFlags |= X86.OPFLAG.ADDRSIZE;
        if (!(this.opPrefixes & X86.OPFLAG.ADDRSIZE)) {
            this.sizeAddr ^= 0x06;              // that which is 2 shall become 4, and vice versa
            this.maskAddr ^= (0xffff0000|0);    // that which is 0x0000ffff shall become 0xffffffff, and vice versa
            this.updateAddrSize();
        }
        this.nStepCycles -= this.cycleCounts.nOpCyclesPrefix;
    }
};

/**
 * op=0x68 (PUSH imm) (80186/80188 and up)
 *
 * @this {CPUx86}
 */
X86.opPUSHn = function()
{
    this.pushWord(this.getIPWord());
    this.nStepCycles -= this.cycleCounts.nOpCyclesPushReg;
};

/**
 * op=0x69 (IMUL reg,word,imm) (80186/80188 and up)
 *
 * @this {CPUx86}
 */
X86.opIMULn = function()
{
    this.decodeModRegWord.call(this, X86.fnIMULn);
};

/**
 * op=0x6A (PUSH imm8) (80186/80188 and up)
 *
 * @this {CPUx86}
 */
X86.opPUSH8 = function()
{
    if (BACKTRACK) this.backTrack.btiMem1 = 0;
    this.pushWord(this.getIPDisp());
    this.nStepCycles -= this.cycleCounts.nOpCyclesPushReg;
};

/**
 * op=0x6B (IMUL reg,word,imm8) (80186/80188 and up)
 *
 * @this {CPUx86}
 */
X86.opIMUL8 = function()
{
    this.decodeModRegWord.call(this, X86.fnIMUL8);
};

/**
 * op=0x6C (INSB) (80186/80188 and up)
 *
 * NOTE: Segment overrides are ignored for this instruction, so we must use segES instead of segData.
 *
 * @this {CPUx86}
 */
X86.opINSb = function()
{
    let nReps = 1;
    let nDelta = 0;
    let maskAddr = this.maskAddr;

    /*
     * NOTE: 5 + 4n is the cycle time for the 80286; the 80186/80188 has different values: 14 cycles for
     * an unrepeated INS, and 8 + 8n for a repeated INS.  However, accurate cycle times for the 80186/80188 is
     * low priority.
     */
    let nCycles = 5;

    /*
     * The (normal) REP prefix, if used, is REPNZ (0xf2), but either one works....
     */
    if (this.opPrefixes & (X86.OPFLAG.REPZ | X86.OPFLAG.REPNZ)) {
        nReps = this.regECX & maskAddr;
        nDelta = 1;
        if (this.opPrefixes & X86.OPFLAG.REPEAT) nCycles = 4;
    }

    if (nReps--) {
        let port = this.regEDX & 0xffff;
        if (!this.checkIOPM(port, 1, true)) return;
        let b = this.bus.checkPortInputNotify(port, 1, this.regLIP - nDelta - 1);
        this.setSOByte(this.segES, this.regEDI & maskAddr, b);
        /*
         * helpFault() throws exceptions now, so inline checks of X86.OPFLAG.FAULT should no longer be necessary.
         *
         *      if (this.opFlags & X86.OPFLAG.FAULT) return;
         */
        if (BACKTRACK) this.backTrack.btiMem0 = this.backTrack.btiIO;
        this.regEDI = (this.regEDI & ~maskAddr) | ((this.regEDI + ((this.regPS & X86.PS.DF)? -1 : 1)) & maskAddr);
        this.regECX = (this.regECX & ~maskAddr) | ((this.regECX - nDelta) & maskAddr);
        this.nStepCycles -= nCycles;
        if (nReps) this.rewindIP();
    }
};

/**
 * op=0x6D (INSW) (80186/80188 and up)
 *
 * NOTE: Segment overrides are ignored for this instruction, so we must use segDS instead of segData.
 *
 * @this {CPUx86}
 */
X86.opINSw = function()
{
    let nReps = 1;
    let nDelta = 0;
    let maskAddr = this.maskAddr;

    /*
     * NOTE: 5 + 4n is the cycle time for the 80286; the 80186/80188 has different values: 14 cycles for
     * an unrepeated INS, and 8 + 8n for a repeated INS.  However, accurate cycle times for the 80186/80188 is
     * low priority.
     */
    let nCycles = 5;

    /*
     * The (normal) REP prefix, if used, is REPNZ (0xf2), but either one works....
     */
    if (this.opPrefixes & (X86.OPFLAG.REPZ | X86.OPFLAG.REPNZ)) {
        nReps = this.regECX & maskAddr;
        nDelta = 1;
        if (this.opPrefixes & X86.OPFLAG.REPEAT) nCycles = 4;
    }
    if (nReps--) {
        let port = this.regEDX & 0xffff;
        if (!this.checkIOPM(port, this.sizeData, true)) return;
        let w = this.bus.checkPortInputNotify(port, this.sizeData, this.regLIP - nDelta - 1);
        if (BACKTRACK) {
            this.backTrack.btiMem0 = this.backTrack.btiIO;
            this.backTrack.btiMem1 = this.backTrack.btiIO;
        }
        this.setSOWord(this.segES, this.regEDI & maskAddr, w);
        /*
         * helpFault() throws exceptions now, so inline checks of X86.OPFLAG.FAULT should no longer be necessary.
         *
         *      if (this.opFlags & X86.OPFLAG.FAULT) return;
         */
        this.regEDI = (this.regEDI & ~maskAddr) | ((this.regEDI + ((this.regPS & X86.PS.DF)? -this.sizeData : this.sizeData)) & maskAddr);
        this.regECX = (this.regECX & ~maskAddr) | ((this.regECX - nDelta) & maskAddr);
        this.nStepCycles -= nCycles;
        if (nReps) this.rewindIP();
    }
};

/**
 * op=0x6E (OUTSB) (80186/80188 and up)
 *
 * NOTE: Segment overrides are ignored for this instruction, so we must use segDS instead of segData.
 *
 * @this {CPUx86}
 */
X86.opOUTSb = function()
{
    let nReps = 1;
    let nDelta = 0;
    let maskAddr = this.maskAddr;

    /*
     * NOTE: 5 + 4n is the cycle time for the 80286; the 80186/80188 has different values: 14 cycles for
     * an unrepeated INS, and 8 + 8n for a repeated INS.  TODO: Fix this someday.
     */
    let nCycles = 5;

    /*
     * The (normal) REP prefix, if used, is REPNZ (0xf2), but either one works....
     */
    if (this.opPrefixes & (X86.OPFLAG.REPZ | X86.OPFLAG.REPNZ)) {
        nReps = this.regECX & maskAddr;
        nDelta = 1;
        if (this.opPrefixes & X86.OPFLAG.REPEAT) nCycles = 4;
    }
    if (nReps--) {
        let port = this.regEDX & 0xffff;
        if (!this.checkIOPM(port, 1, false)) return;
        let b = this.getSOByte(this.segDS, this.regESI & maskAddr);
        /*
         * helpFault() throws exceptions now, so inline checks of X86.OPFLAG.FAULT should no longer be necessary.
         *
         *      if (this.opFlags & X86.OPFLAG.FAULT) return;
         */
        if (BACKTRACK) this.backTrack.btiIO = this.backTrack.btiMem0;
        this.bus.checkPortOutputNotify(port, 1, b, this.regLIP - nDelta - 1);
        this.regESI = (this.regESI & ~maskAddr) | ((this.regESI + ((this.regPS & X86.PS.DF)? -1 : 1)) & maskAddr);
        this.regECX = (this.regECX & ~maskAddr) | ((this.regECX - nDelta) & maskAddr);
        this.nStepCycles -= nCycles;
        if (nReps) this.rewindIP();
    }
};

/**
 * op=0x6F (OUTSW) (80186/80188 and up)
 *
 * NOTE: Segment overrides are ignored for this instruction, so we must use segDS instead of segData.
 *
 * @this {CPUx86}
 */
X86.opOUTSw = function()
{
    let nReps = 1;
    let nDelta = 0;
    let maskAddr = this.maskAddr;

    /*
     * NOTE: 5 + 4n is the cycle time for the 80286; the 80186/80188 has different values: 14 cycles for
     * an unrepeated INS, and 8 + 8n for a repeated INS.  TODO: Fix this someday.
     */
    let nCycles = 5;

    /*
     * The (normal) REP prefix, if used, is REPNZ (0xf2), but either one works....
     */
    if (this.opPrefixes & (X86.OPFLAG.REPZ | X86.OPFLAG.REPNZ)) {
        nReps = this.regECX & maskAddr;
        nDelta = 1;
        if (this.opPrefixes & X86.OPFLAG.REPEAT) nCycles = 4;
    }
    if (nReps--) {
        let w = this.getSOWord(this.segDS, this.regESI & maskAddr);
        /*
         * helpFault() throws exceptions now, so inline checks of X86.OPFLAG.FAULT should no longer be necessary.
         *
         *      if (this.opFlags & X86.OPFLAG.FAULT) return;
         */
        let port = this.regEDX & 0xffff;
        if (!this.checkIOPM(port, this.sizeData, false)) return;
        if (BACKTRACK) {
            this.backTrack.btiIO = this.backTrack.btiMem0;
            this.backTrack.btiIO = this.backTrack.btiMem1;
        }
        this.bus.checkPortOutputNotify(port, this.sizeData, w, this.regLIP - nDelta - 1);
        this.regESI = (this.regESI & ~maskAddr) | ((this.regESI + ((this.regPS & X86.PS.DF)? -this.sizeData : this.sizeData)) & maskAddr);
        this.regECX = (this.regECX & ~maskAddr) | ((this.regECX - nDelta) & maskAddr);
        this.nStepCycles -= nCycles;
        if (nReps) this.rewindIP();
    }
};

/**
 * op=0x70 (JO disp)
 *
 * @this {CPUx86}
 */
X86.opJO = function()
{
    let disp = this.getIPDisp();
    if (this.getOF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * op=0x71 (JNO disp)
 *
 * @this {CPUx86}
 */
X86.opJNO = function()
{
    let disp = this.getIPDisp();
    if (!this.getOF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * op=0x72 (JC disp, aka JB disp)
 *
 * @this {CPUx86}
 */
X86.opJC = function()
{
    let disp = this.getIPDisp();
    if (this.getCF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * op=0x73 (JNC disp, aka JAE disp)
 *
 * @this {CPUx86}
 */
X86.opJNC = function()
{
    let disp = this.getIPDisp();
    if (!this.getCF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * op=0x74 (JZ disp)
 *
 * @this {CPUx86}
 */
X86.opJZ = function()
{
    let disp = this.getIPDisp();
    if (this.getZF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * op=0x75 (JNZ disp)
 *
 * @this {CPUx86}
 */
X86.opJNZ = function()
{
    let disp = this.getIPDisp();
    if (!this.getZF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * op=0x76 (JBE disp)
 *
 * @this {CPUx86}
 */
X86.opJBE = function()
{
    let disp = this.getIPDisp();
    if (this.getCF() || this.getZF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * op=0x77 (JNBE disp, JA disp)
 *
 * @this {CPUx86}
 */
X86.opJNBE = function()
{
    let disp = this.getIPDisp();
    if (!this.getCF() && !this.getZF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * op=0x78 (JS disp)
 *
 * @this {CPUx86}
 */
X86.opJS = function()
{
    let disp = this.getIPDisp();
    if (this.getSF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * op=0x79 (JNS disp)
 *
 * @this {CPUx86}
 */
X86.opJNS = function()
{
    let disp = this.getIPDisp();
    if (!this.getSF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * op=0x7A (JP disp)
 *
 * @this {CPUx86}
 */
X86.opJP = function()
{
    let disp = this.getIPDisp();
    if (this.getPF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * op=0x7B (JNP disp)
 *
 * @this {CPUx86}
 */
X86.opJNP = function()
{
    let disp = this.getIPDisp();
    if (!this.getPF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * op=0x7C (JL disp)
 *
 * @this {CPUx86}
 */
X86.opJL = function()
{
    let disp = this.getIPDisp();
    if (!this.getSF() != !this.getOF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * op=0x7D (JNL disp, aka JGE disp)
 *
 * @this {CPUx86}
 */
X86.opJNL = function()
{
    let disp = this.getIPDisp();
    if (!this.getSF() == !this.getOF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * op=0x7E (JLE disp)
 *
 * @this {CPUx86}
 */
X86.opJLE = function()
{
    let disp = this.getIPDisp();
    if (this.getZF() || !this.getSF() != !this.getOF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * op=0x7F (JNLE disp, aka JG disp)
 *
 * @this {CPUx86}
 */
X86.opJNLE = function()
{
    let disp = this.getIPDisp();
    if (!this.getZF() && !this.getSF() == !this.getOF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * op=0x80/0x82 (GRP1 byte,imm8)
 *
 * @this {CPUx86}
 */
X86.opGRP1b = function()
{
    this.decodeModGrpByte.call(this, X86.aOpGrp1b, this.getIPByte);
    this.nStepCycles -= (this.regEAWrite === X86.ADDR_INVALID? 1 : this.cycleCounts.nOpCyclesArithMID);
};

/**
 * op=0x81 (GRP1 word,imm)
 *
 * @this {CPUx86}
 */
X86.opGRP1w = function()
{
    this.decodeModGrpWord.call(this, X86.aOpGrp1w, this.getIPWord);
    this.nStepCycles -= (this.regEAWrite === X86.ADDR_INVALID? 1 : this.cycleCounts.nOpCyclesArithMID);
};

/**
 * op=0x83 (GRP1 word,disp)
 *
 * WARNING: This passes getIPDisp() as the fnSrc parameter, which returns a 32-bit signed value,
 * so the worker functions (ie, the functions listed in aOpGrp1w[]) MUST mask their result with maskData,
 * to avoid setting bits beyond the current operand size.
 *
 * @this {CPUx86}
 */
X86.opGRP1sw = function()
{
    this.decodeModGrpWord.call(this, X86.aOpGrp1w, this.getIPDisp);
    this.nStepCycles -= (this.regEAWrite === X86.ADDR_INVALID? 1 : this.cycleCounts.nOpCyclesArithMID);
};

/**
 * op=0x84 (TEST reg,byte)
 *
 * @this {CPUx86}
 */
X86.opTESTrb = function()
{
    this.decodeModMemByte.call(this, X86.fnTESTb);
};

/**
 * op=0x85 (TEST reg,word)
 *
 * @this {CPUx86}
 */
X86.opTESTrw = function()
{
    this.decodeModMemWord.call(this, X86.fnTESTw);
};

/**
 * op=0x86 (XCHG reg,byte)
 *
 * NOTE: The XCHG instruction is unique in that both src and dst are both read and written;
 * see fnXCHGrb() for how we deal with this special case.
 *
 * @this {CPUx86}
 */
X86.opXCHGrb = function()
{
    /*
     * If the second operand is a register, then the ModRegByte decoder must use separate "get" and
     * "set" assignments, otherwise instructions like "XCHG DH,DL" will end up using a stale DL instead of
     * the updated DL.
     *
     * To be clear, a single assignment like this will fail:
     *
     *      opModRegByteF2: function(fn)
     *      {
     *          this.regEDX = (this.regEDX & 0xff) | (fn.call(this, this.regEDX >> 8, this.regEDX & 0xff) << 8);
     *      }
     *
     * which is why all affected decoders now use separate assignments; eg:
     *
     *      opModRegByteF2: function(fn)
     *      {
     *          let b = fn.call(this, this.regEDX >> 8, this.regEDX & 0xff);
     *          this.regEDX = (this.regEDX & 0xff) | (b << 8);
     *      }
     */
    this.decodeModRegByte.call(this, X86.fnXCHGrb);
};

/**
 * op=0x87 (XCHG reg,word)
 *
 * NOTE: The XCHG instruction is unique in that both src and dst are both read and written;
 * see fnXCHGrw() for how we deal with this special case.
 *
 * @this {CPUx86}
 */
X86.opXCHGrw = function()
{
    this.decodeModRegWord.call(this, X86.fnXCHGrw);
};

/**
 * op=0x88 (MOV byte,reg)
 *
 * @this {CPUx86}
 */
X86.opMOVmb = function()
{
    /*
     * Like other MOV operations, the destination does not need to be read, just written.
     */
    this.opFlags |= X86.OPFLAG.NOREAD;
    this.decodeModMemByte.call(this, X86.fnMOV);
};

/**
 * op=0x89 (MOV word,reg)
 *
 * @this {CPUx86}
 */
X86.opMOVmw = function()
{
    /*
     * Like other MOV operations, the destination does not need to be read, just written.
     */
    this.opFlags |= X86.OPFLAG.NOREAD;
    this.decodeModMemWord.call(this, X86.fnMOV);
};

/**
 * op=0x8A (MOV reg,byte)
 *
 * @this {CPUx86}
 */
X86.opMOVrb = function()
{
    this.decodeModRegByte.call(this, X86.fnMOV);
};

/**
 * op=0x8B (MOV reg,word)
 *
 * @this {CPUx86}
 */
X86.opMOVrw = function()
{
    this.decodeModRegWord.call(this, X86.fnMOV);
};

/**
 * op=0x8C (MOV word,sreg)
 *
 * NOTE: Since the ModRM decoders deal only with general-purpose registers, we rely on our helper
 * function (fnMOVwsr) to select the appropriate segment register and replace the decoder's src operand.
 *
 * @this {CPUx86}
 */
X86.opMOVwsr = function()
{
    /*
     * Like other MOV operations, the destination does not need to be read, just written.
     */
    this.opFlags |= X86.OPFLAG.NOREAD;
    this.decodeModMemWord.call(this, X86.fnMOVwsr);
};

/**
 * op=0x8D (LEA reg,word)
 *
 * @this {CPUx86}
 */
X86.opLEA = function()
{
    this.opFlags |= X86.OPFLAG.NOREAD;
    this.segData = this.segStack = this.segNULL;    // we can't have the EA calculation, if any, "polluted" by segment arithmetic
    this.decodeModRegWord.call(this, X86.fnLEA);
};

/**
 * op=0x8E (MOV sreg,word)
 *
 * NOTE: Since the ModRM decoders deal only with general-purpose registers, we rely on our
 * helper function (fnMOVsrw) to make a note of which general-purpose register will be overwritten,
 * so that we can restore it after moving the updated value to the correct segment register.
 *
 * @this {CPUx86}
 */
X86.opMOVsrw = function()
{
    let sel;
    this.decodeModRegWord.call(this, X86.fnMOVsrw);
    switch ((this.bModRM >> 3) & 0x7) {
    case 0x0:
        sel = this.regEAX;
        this.regEAX = this.regXX;
        this.setES(sel);
        break;
    case 0x1:
        sel = this.regECX;
        this.regECX = this.regXX;
        this.setCS(sel);
        break;
    case 0x2:
        sel = this.regEDX;
        this.regEDX = this.regXX;
        this.setSS(sel);
        break;
    case 0x3:
        sel = this.regEBX;
        this.regEBX = this.regXX;
        this.setDS(sel);
        break;
    case 0x4:
        sel = this.getSP();
        this.setSP(this.regXX);
        if (I386 && this.model >= X86.MODEL_80386) {
            this.setFS(sel);
        } else {
            this.setES(sel);
        }
        break;
    case 0x5:
        sel = this.regEBP;
        this.regEBP = this.regXX;
        if (I386 && this.model >= X86.MODEL_80386) {
            this.setGS(sel);
        } else {
            this.setCS(sel);
        }
        break;
    case 0x6:
        sel = this.regESI;
        this.regESI = this.regXX;
        this.setSS(sel);
        break;
    case 0x7:
        sel = this.regEDI;
        this.regEDI = this.regXX;
        this.setDS(sel);
        break;
    }
};

/**
 * op=0x8F (POP word)
 *
 * @this {CPUx86}
 */
X86.opPOPmw = function()
{
    /*
     * Like other MOV operations, the destination does not need to be read, just written.
     */
    this.opFlags |= X86.OPFLAG.NOREAD;

    /*
     * If the word we're about to pop FROM the stack gets popped INTO a not-present page, this
     * instruction will not be restartable unless we snapshot regLSP first.
     */
    this.opLSP = this.regLSP;

    /*
     * A "clever" instruction like this:
     *
     *      #0117:651C 67668F442408    POP      DWORD [ESP+08]
     *
     * pops the DWORD from the top of the stack and places it at ESP+08, where ESP is the value
     * AFTER the pop, not before.  We used to (incorrectly) pass "popWord" as the fnSrc parameter
     * below; we now pop the word first, saving it in regXX, and then pass "helpSRCxx" as fnSrc,
     * which simply returns the contents of regXX.
     *
     * Also, in case you're wondering, fnPUSHw() (in aOpGrp4w) is the complement to this instruction,
     * but it doesn't require a similar work-around, because a push from memory accesses that memory
     * BEFORE the push, which occurs through our normal ModRM processing.
     */
    this.regXX = this.popWord();

    this.decodeModGrpWord.call(this, X86.aOpGrpPOPw, X86.helpSRCxx);

    this.opLSP = X86.ADDR_INVALID;
};

/**
 * op=0x90 (NOP, aka XCHG AX,AX)
 *
 * @this {CPUx86}
 */
X86.opNOP = function()
{
    this.nStepCycles -= 3;                          // this form of XCHG takes 3 cycles on all CPUs
};

/**
 * op=0x91 (XCHG AX,CX)
 *
 * @this {CPUx86}
 */
X86.opXCHGCX = function()
{
    let temp = this.regEAX;
    this.regEAX = (I386? (this.regEAX & ~this.maskData) | (this.regECX & this.maskData) : this.regECX);
    this.regECX = (I386? (this.regECX & ~this.maskData) | (temp & this.maskData) : temp);
    if (BACKTRACK) {
        temp = this.backTrack.btiAL; this.backTrack.btiAL = this.backTrack.btiCL; this.backTrack.btiCL = temp;
        temp = this.backTrack.btiAH; this.backTrack.btiAH = this.backTrack.btiCH; this.backTrack.btiCH = temp;
    }
    this.nStepCycles -= 3;                          // this form of XCHG takes 3 cycles on all CPUs
};

/**
 * op=0x92 (XCHG AX,DX)
 *
 * @this {CPUx86}
 */
X86.opXCHGDX = function()
{
    let temp = this.regEAX;
    this.regEAX = (I386? (this.regEAX & ~this.maskData) | (this.regEDX & this.maskData) : this.regEDX);
    this.regEDX = (I386? (this.regEDX & ~this.maskData) | (temp & this.maskData) : temp);
    if (BACKTRACK) {
        temp = this.backTrack.btiAL; this.backTrack.btiAL = this.backTrack.btiDL; this.backTrack.btiDL = temp;
        temp = this.backTrack.btiAH; this.backTrack.btiAH = this.backTrack.btiDH; this.backTrack.btiDH = temp;
    }
    this.nStepCycles -= 3;                          // this form of XCHG takes 3 cycles on all CPUs
};

/**
 * op=0x93 (XCHG AX,BX)
 *
 * @this {CPUx86}
 */
X86.opXCHGBX = function()
{
    let temp = this.regEAX;
    this.regEAX = (I386? (this.regEAX & ~this.maskData) | (this.regEBX & this.maskData) : this.regEBX);
    this.regEBX = (I386? (this.regEBX & ~this.maskData) | (temp & this.maskData) : temp);
    if (BACKTRACK) {
        temp = this.backTrack.btiAL; this.backTrack.btiAL = this.backTrack.btiBL; this.backTrack.btiBL = temp;
        temp = this.backTrack.btiAH; this.backTrack.btiAH = this.backTrack.btiBH; this.backTrack.btiBH = temp;
    }
    this.nStepCycles -= 3;                          // this form of XCHG takes 3 cycles on all CPUs
};

/**
 * op=0x94 (XCHG AX,SP)
 *
 * @this {CPUx86}
 */
X86.opXCHGSP = function()
{
    let temp = this.regEAX;
    let regESP = this.getSP();
    this.regEAX = (I386? (this.regEAX & ~this.maskData) | (regESP & this.maskData) : regESP);
    this.setSP((I386? (regESP & ~this.maskData) | (temp & this.maskData) : temp));
    if (BACKTRACK) this.backTrack.btiAL = this.backTrack.btiAH = 0;
    this.nStepCycles -= 3;                          // this form of XCHG takes 3 cycles on all CPUs
};

/**
 * op=0x95 (XCHG AX,BP)
 *
 * @this {CPUx86}
 */
X86.opXCHGBP = function()
{
    let temp = this.regEAX;
    this.regEAX = (I386? (this.regEAX & ~this.maskData) | (this.regEBP & this.maskData) : this.regEBP);
    this.regEBP = (I386? (this.regEBP & ~this.maskData) | (temp & this.maskData) : temp);
    if (BACKTRACK) {
        temp = this.backTrack.btiAL; this.backTrack.btiAL = this.backTrack.btiBPLo; this.backTrack.btiBPLo = temp;
        temp = this.backTrack.btiAH; this.backTrack.btiAH = this.backTrack.btiBPHi; this.backTrack.btiBPHi = temp;
    }
    this.nStepCycles -= 3;                          // this form of XCHG takes 3 cycles on all CPUs
};

/**
 * op=0x96 (XCHG AX,SI)
 *
 * @this {CPUx86}
 */
X86.opXCHGSI = function()
{
    let temp = this.regEAX;
    this.regEAX = (I386? (this.regEAX & ~this.maskData) | (this.regESI & this.maskData) : this.regESI);
    this.regESI = (I386? (this.regESI & ~this.maskData) | (temp & this.maskData) : temp);
    if (BACKTRACK) {
        temp = this.backTrack.btiAL; this.backTrack.btiAL = this.backTrack.btiSILo; this.backTrack.btiSILo = temp;
        temp = this.backTrack.btiAH; this.backTrack.btiAH = this.backTrack.btiSIHi; this.backTrack.btiSIHi = temp;
    }
    this.nStepCycles -= 3;                          // this form of XCHG takes 3 cycles on all CPUs
};

/**
 * op=0x97 (XCHG AX,DI)
 *
 * @this {CPUx86}
 */
X86.opXCHGDI = function()
{
    let temp = this.regEAX;
    this.regEAX = (I386? (this.regEAX & ~this.maskData) | (this.regEDI & this.maskData) : this.regEDI);
    this.regEDI = (I386? (this.regEDI & ~this.maskData) | (temp & this.maskData) : temp);
    if (BACKTRACK) {
        temp = this.backTrack.btiAL; this.backTrack.btiAL = this.backTrack.btiDILo; this.backTrack.btiDILo = temp;
        temp = this.backTrack.btiAH; this.backTrack.btiAH = this.backTrack.btiDIHi; this.backTrack.btiDIHi = temp;
    }
    this.nStepCycles -= 3;                          // this form of XCHG takes 3 cycles on all CPUs
};

/**
 * op=0x98 (CBW/CWDE)
 *
 * NOTE: The 16-bit form (CBW) sign-extends AL into AX, whereas the 32-bit form (CWDE) sign-extends AX into EAX;
 * CWDE is similar to CWD, except that the destination is EAX rather than DX:AX.
 *
 * @this {CPUx86}
 */
X86.opCBW = function()
{
    if (this.sizeData == 2) {   // CBW
        this.regEAX = (this.regEAX & ~0xffff) | (((this.regEAX << 24) >> 24) & 0xffff);
        if (BACKTRACK) this.backTrack.btiAH = this.backTrack.btiAL;
    }
    else {                      // CWDE
        this.regEAX = ((this.regEAX << 16) >> 16);
    }
    this.nStepCycles -= 2;                          // CBW takes 2 cycles on all CPUs through 80286
};

/**
 * op=0x99 (CWD/CDQ)
 *
 * NOTE: The 16-bit form (CWD) sign-extends AX, producing a 32-bit result in DX:AX, while the 32-bit form (CDQ)
 * sign-extends EAX, producing a 64-bit result in EDX:EAX.
 *
 * @this {CPUx86}
 */
X86.opCWD = function()
{
    if (this.sizeData == 2) {   // CWD
        this.regEDX = (this.regEDX & ~0xffff) | ((this.regEAX & 0x8000)? 0xffff : 0);
        if (BACKTRACK) this.backTrack.btiDL = this.backTrack.btiDH = this.backTrack.btiAH;
    }
    else {                      // CDQ
        this.regEDX = (this.regEAX & (0x80000000|0))? -1 : 0;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesCWD;
};

/**
 * op=0x9A (CALL seg:off)
 *
 * @this {CPUx86}
 */
X86.opCALLF = function()
{
    X86.helpCALLF.call(this, this.getIPWord(), this.getIPShort());
    this.nStepCycles -= this.cycleCounts.nOpCyclesCallF;
};

/**
 * op=0x9B (WAIT)
 *
 * @this {CPUx86}
 */
X86.opWAIT = function()
{
    if (!this.fpu || !this.fpu.opWAIT()) {
        this.nStepCycles -= 3;     // FPUx86.opWAIT() is required to charge some number of cycles if it returns true
    }
};

/**
 * op=0x9C (PUSHF/PUSHFD)
 *
 * @this {CPUx86}
 */
X86.opPUSHF = function()
{
    /*
     * TODO: Consider swapping out this function whenever setProtMode() changes the mode to V86-mode.
     */
    let regPS = this.getPS();
    if (I386) {
        if ((regPS & X86.PS.VM) && this.nIOPL < 3) {
            if (DEBUG) this.printMessage("PUSHF in v86-mode (IOPL < 3)", this.bitsMessage, true);
            X86.helpFault.call(this, X86.EXCEPTION.GP_FAULT, 0);
            return;
        }
        /*
         * It doesn't matter whether this is PUSHF or PUSHFD: the VM and RF flags are never pushed, so
         * we should always clear them.  NOTE: This contradicts what the "INTEL 80386 PROGRAMMER'S REFERENCE
         * MANUAL 1986" says on page 81 (which we assume is wrong):
         *
         *      SYSTEMS FLAGS (INCLUDING THE IOPL FIELD, AND THE VM, RF, AND IF FLAGS) ARE PUSHED AND ARE
         *      VISIBLE TO APPLICATIONS PROGRAMS. HOWEVER, WHEN AN APPLICATIONS PROGRAM POPS THE FLAGS,
         *      THESE ITEMS ARE NOT CHANGED, REGARDLESS OF THE VALUES POPPED INTO THEM.
         *
         * This does, however, beg the question: how does code running in V86-mode detect that's in V86-mode
         * and not real-mode?  By using the SMSW instruction and checking the PE (protected-mode enabled) bit.
         * The SMSW instruction returns a subset of the CR0 bits, and unlike the MOV reg,CR0 instruction, is
         * allowed in V86-mode.  See fnSMSW() for more information.
         */
        regPS &= ~(X86.PS.VM | X86.PS.RF);
    }
    this.pushWord(regPS);
    this.nStepCycles -= this.cycleCounts.nOpCyclesPushReg;
};

/**
 * op=0x9D (POPF/POPFD)
 *
 * @this {CPUx86}
 */
X86.opPOPF = function()
{
    /*
     * TODO: Consider swapping out this function whenever setProtMode() changes the mode to V86-mode.
     */
    if (I386 && (this.regPS & X86.PS.VM) && this.nIOPL < 3) {
        if (DEBUG) this.printMessage("POPF in v86-mode (IOPL < 3)", this.bitsMessage, true);
        X86.helpFault.call(this, X86.EXCEPTION.GP_FAULT, 0);
        return;
    }
    /*
     * Regardless of mode, VM and RF (the only defined EFLAGS bit above bit 15) are never changed by POPFD.
     */
    let newPS = this.popWord();
    if (I386) newPS = (newPS & 0xffff) | (this.regPS & ~0xffff);
    this.setPS(newPS);
    /*
     * NOTE: I'm assuming that neither POPF nor IRET are required to set NOINTR like STI does.
     */
    this.nStepCycles -= this.cycleCounts.nOpCyclesPopReg;
};

/**
 * op=0x9E (SAHF)
 *
 * @this {CPUx86}
 */
X86.opSAHF = function()
{
    /*
     * NOTE: While it make seem more efficient to do this:
     *
     *      this.setPS((this.getPS() & ~X86.PS_SAHF) | ((this.regEAX >> 8) & X86.PS_SAHF));
     *
     * getPS() forces any "cached" flags to be resolved first, and setPS() must do extra work above
     * and beyond setting the arithmetic and logical flags, so on balance, the code below may be more
     * efficient, and may also avoid unexpected side-effects of updating the entire PS register.
     */
    let ah = (this.regEAX >> 8) & 0xff;
    if (ah & X86.PS.CF) this.setCF(); else this.clearCF();
    if (ah & X86.PS.PF) this.setPF(); else this.clearPF();
    if (ah & X86.PS.AF) this.setAF(); else this.clearAF();
    if (ah & X86.PS.ZF) this.setZF(); else this.clearZF();
    if (ah & X86.PS.SF) this.setSF(); else this.clearSF();
    this.nStepCycles -= this.cycleCounts.nOpCyclesLAHF;

};

/**
 * op=0x9F (LAHF)
 *
 * @this {CPUx86}
 */
X86.opLAHF = function()
{
    /*
     * Apparently, this simply uses the low 8 bits of PS as-is (ie, we don't need to mask with PS_SAHF).
     */
    this.regEAX = (this.regEAX & ~0xff00) | (this.getPS() & 0xff) << 8;
    this.nStepCycles -= this.cycleCounts.nOpCyclesLAHF;
};

/**
 * op=0xA0 (MOV AL,mem)
 *
 * @this {CPUx86}
 */
X86.opMOVALm = function()
{
    this.regEAX = (this.regEAX & ~0xff) | this.getSOByte(this.segData, this.getIPAddr());
    if (BACKTRACK) this.backTrack.btiAL = this.backTrack.btiMem0;
    this.nStepCycles -= this.cycleCounts.nOpCyclesMovAM;
};

/**
 * op=0xA1 (MOV [E]AX,mem)
 *
 * @this {CPUx86}
 */
X86.opMOVAXm = function()
{
    this.regEAX = (this.regEAX & ~this.maskData) | this.getSOWord(this.segData, this.getIPAddr());
    if (BACKTRACK) {
        this.backTrack.btiAL = this.backTrack.btiMem0; this.backTrack.btiAH = this.backTrack.btiMem1;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesMovAM;
};

/**
 * op=0xA2 (MOV mem,AL)
 *
 * @this {CPUx86}
 */
X86.opMOVmAL = function()
{
    if (BACKTRACK) this.backTrack.btiMem0 = this.backTrack.btiAL;
    /*
     * setSOByte() truncates the value as appropriate
     */
    this.setSOByte(this.segData, this.getIPAddr(), this.regEAX);
    this.nStepCycles -= this.cycleCounts.nOpCyclesMovMA;
};

/**
 * op=0xA3 (MOV mem,AX)
 *
 * @this {CPUx86}
 */
X86.opMOVmAX = function()
{
    if (BACKTRACK) {
        this.backTrack.btiMem0 = this.backTrack.btiAL; this.backTrack.btiMem1 = this.backTrack.btiAH;
    }
    /*
     * setSOWord() truncates the value as appropriate
     */
    this.setSOWord(this.segData, this.getIPAddr(), this.regEAX);
    this.nStepCycles -= this.cycleCounts.nOpCyclesMovMA;
};

/**
 * op=0xA4 (MOVSB)
 *
 * @this {CPUx86}
 */
X86.opMOVSb = function()
{
    let nReps = 1;
    let nDelta = 0;
    let maskAddr = this.maskAddr;

    let nCycles = this.cycleCounts.nOpCyclesMovS;
    if (this.opPrefixes & (X86.OPFLAG.REPZ | X86.OPFLAG.REPNZ)) {
        nReps = this.regECX & maskAddr;
        nDelta = 1;
        nCycles = this.cycleCounts.nOpCyclesMovSrn;
        if (!(this.opPrefixes & X86.OPFLAG.REPEAT)) this.nStepCycles -= this.cycleCounts.nOpCyclesMovSr0;
    }
    if (nReps--) {
        this.setSOByte(this.segES, this.regEDI & maskAddr, this.getSOByte(this.segData, this.regESI & maskAddr));
        /*
         * helpFault() throws exceptions now, so inline checks of X86.OPFLAG.FAULT should no longer be necessary.
         *
         *      if (this.opFlags & X86.OPFLAG.FAULT) return;
         */
        let nInc = ((this.regPS & X86.PS.DF)? -1 : 1);
        this.regESI = (this.regESI & ~maskAddr) | ((this.regESI + nInc) & maskAddr);
        this.regEDI = (this.regEDI & ~maskAddr) | ((this.regEDI + nInc) & maskAddr);
        this.nStepCycles -= nCycles;
        this.regECX = (this.regECX & ~maskAddr) | ((this.regECX - nDelta) & maskAddr);
        if (nReps) this.rewindIP(true);
    }
};

/**
 * op=0xA5 (MOVSW)
 *
 * @this {CPUx86}
 */
X86.opMOVSw = function()
{
    let nReps = 1;
    let nDelta = 0;
    let maskAddr = this.maskAddr;

    let nCycles = this.cycleCounts.nOpCyclesMovS;
    if (this.opPrefixes & (X86.OPFLAG.REPZ | X86.OPFLAG.REPNZ)) {
        nReps = this.regECX & maskAddr;
        nDelta = 1;
        nCycles = this.cycleCounts.nOpCyclesMovSrn;
        if (!(this.opPrefixes & X86.OPFLAG.REPEAT)) this.nStepCycles -= this.cycleCounts.nOpCyclesMovSr0;
    }
    if (nReps--) {
        this.setSOWord(this.segES, this.regEDI & maskAddr, this.getSOWord(this.segData, this.regESI & maskAddr));
        /*
         * helpFault() throws exceptions now, so inline checks of X86.OPFLAG.FAULT should no longer be necessary.
         *
         *      if (this.opFlags & X86.OPFLAG.FAULT) return;
         */
        let nInc = ((this.regPS & X86.PS.DF)? -this.sizeData : this.sizeData);
        this.regESI = (this.regESI & ~maskAddr) | ((this.regESI + nInc) & maskAddr);
        this.regEDI = (this.regEDI & ~maskAddr) | ((this.regEDI + nInc) & maskAddr);
        this.nStepCycles -= nCycles;
        this.regECX = (this.regECX & ~maskAddr) | ((this.regECX - nDelta) & maskAddr);
        if (nReps) this.rewindIP(true);
    }
};

/**
 * op=0xA6 (CMPSB)
 *
 * @this {CPUx86}
 */
X86.opCMPSb = function()
{
    let nReps = 1;
    let nDelta = 0;
    let maskAddr = this.maskAddr;

    let nCycles = this.cycleCounts.nOpCyclesCmpS;
    if (this.opPrefixes & (X86.OPFLAG.REPZ | X86.OPFLAG.REPNZ)) {
        nReps = this.regECX & maskAddr;
        nDelta = 1;
        nCycles = this.cycleCounts.nOpCyclesCmpSrn;
        if (!(this.opPrefixes & X86.OPFLAG.REPEAT)) this.nStepCycles -= this.cycleCounts.nOpCyclesCmpSr0;
    }
    if (nReps--) {
        let bDst = this.getEAByte(this.segData, this.regESI);
        let bSrc = this.getEAByte(this.segES, this.regEDI);
        this.regEAWrite = this.regEA;           // TODO: Is this necessary?
        /*
         * helpFault() throws exceptions now, so inline checks of X86.OPFLAG.FAULT should no longer be necessary.
         *
         *      if (this.opFlags & X86.OPFLAG.FAULT) return;
         */
        X86.fnCMPb.call(this, bDst, bSrc);
        let nInc = ((this.regPS & X86.PS.DF)? -1 : 1);
        this.regESI = (this.regESI & ~maskAddr) | ((this.regESI + nInc) & maskAddr);
        this.regEDI = (this.regEDI & ~maskAddr) | ((this.regEDI + nInc) & maskAddr);
        this.regECX = (this.regECX & ~maskAddr) | ((this.regECX - nDelta) & maskAddr);
        /*
         * NOTE: As long as we're calling fnCMPb(), all our cycle times must be reduced by nOpCyclesArithRM
         */
        this.nStepCycles -= nCycles - this.cycleCounts.nOpCyclesArithRM;
        /*
         * Repetition continues while ZF matches bit 0 of the REP prefix.  getZF() returns 0x40 if ZF is
         * set, and OP_REPZ (which represents the REP prefix whose bit 0 is set) is 0x40 as well, so when those
         * two values are equal, we must continue.
         */
        if (nReps && this.getZF() == (this.opPrefixes & X86.OPFLAG.REPZ)) this.rewindIP(true);
    }
};

/**
 * op=0xA7 (CMPSW)
 *
 * @this {CPUx86}
 */
X86.opCMPSw = function()
{
    let nReps = 1;
    let nDelta = 0;
    let maskAddr = this.maskAddr;

    let nCycles = this.cycleCounts.nOpCyclesCmpS;
    if (this.opPrefixes & (X86.OPFLAG.REPZ | X86.OPFLAG.REPNZ)) {
        nReps = this.regECX & maskAddr;
        nDelta = 1;
        nCycles = this.cycleCounts.nOpCyclesCmpSrn;
        if (!(this.opPrefixes & X86.OPFLAG.REPEAT)) this.nStepCycles -= this.cycleCounts.nOpCyclesCmpSr0;
    }
    if (nReps--) {
        let wDst = this.getEAWord(this.segData, this.regESI & maskAddr);
        let wSrc = this.getEAWord(this.segES, this.regEDI & maskAddr);
        this.regEAWrite = this.regEA;           // TODO: Is this necessary?
        /*
         * helpFault() throws exceptions now, so inline checks of X86.OPFLAG.FAULT should no longer be necessary.
         *
         *      if (this.opFlags & X86.OPFLAG.FAULT) return;
         */
        X86.fnCMPw.call(this, wDst, wSrc);
        let nInc = ((this.regPS & X86.PS.DF)? -this.sizeData : this.sizeData);
        this.regESI = (this.regESI & ~maskAddr) | ((this.regESI + nInc) & maskAddr);
        this.regEDI = (this.regEDI & ~maskAddr) | ((this.regEDI + nInc) & maskAddr);
        this.regECX = (this.regECX & ~maskAddr) | ((this.regECX - nDelta) & maskAddr);
        /*
         * NOTE: As long as we're calling fnCMPw(), all our cycle times must be reduced by nOpCyclesArithRM
         */
        this.nStepCycles -= nCycles - this.cycleCounts.nOpCyclesArithRM;
        /*
         * Repetition continues while ZF matches bit 0 of the REP prefix.  getZF() returns 0x40 if ZF is
         * set, and OP_REPZ (which represents the REP prefix whose bit 0 is set) is 0x40 as well, so when those
         * two values are equal, we must continue.
         */
        if (nReps && this.getZF() == (this.opPrefixes & X86.OPFLAG.REPZ)) this.rewindIP(true);
    }
};

/**
 * op=0xA8 (TEST AL,imm8)
 *
 * @this {CPUx86}
 */
X86.opTESTALb = function()
{
    this.setLogicResult(this.regEAX & this.getIPByte(), X86.RESULT.BYTE);
    this.nStepCycles -= this.cycleCounts.nOpCyclesAAA;
};

/**
 * op=0xA9 (TEST [E]AX,imm)
 *
 * @this {CPUx86}
 */
X86.opTESTAX = function()
{
    this.setLogicResult(this.regEAX & this.getIPWord(), this.typeData);
    this.nStepCycles -= this.cycleCounts.nOpCyclesAAA;
};

/**
 * op=0xAA (STOSB)
 *
 * NOTES: Segment overrides are ignored for this instruction, so we must use segES instead of segData.
 *
 * @this {CPUx86}
 */
X86.opSTOSb = function()
{
    let nReps = 1;
    let nDelta = 0;
    let maskAddr = this.maskAddr;

    let nCycles = this.cycleCounts.nOpCyclesStoS;
    if (this.opPrefixes & (X86.OPFLAG.REPZ | X86.OPFLAG.REPNZ)) {
        nReps = this.regECX & maskAddr;
        nDelta = 1;
        nCycles = this.cycleCounts.nOpCyclesStoSrn;
        if (!(this.opPrefixes & X86.OPFLAG.REPEAT)) this.nStepCycles -= this.cycleCounts.nOpCyclesStoSr0;
    }
    if (nReps--) {
        this.setSOByte(this.segES, this.regEDI & maskAddr, this.regEAX);
        /*
         * helpFault() throws exceptions now, so inline checks of X86.OPFLAG.FAULT should no longer be necessary.
         *
         *      if (this.opFlags & X86.OPFLAG.FAULT) return;
         */
        if (BACKTRACK) this.backTrack.btiMem0 = this.backTrack.btiAL;

        this.regECX = (this.regECX & ~maskAddr) | ((this.regECX - nDelta) & maskAddr);

        /*
         * Implement 80386 B1 Errata #7, to the extent that Windows 95 checked for it.  This test doesn't
         * detect every possible variation (for example, the ADDRESS override on the next instruction, if
         * it exists, may not be the first prefix byte), but it's adequate for our limited purpose.
         *
         * Note that this code alters maskAddr AFTER it's been used to update ECX, because in the case
         * of STOS, the errata reportedly affects only EDI.  The other instructions mentioned in the errata
         * trash different registers, so read the errata carefully.
         *
         * TODO: Extend this errata to STOSW, as well as MOVSB, MOVSW, INSB, and INSW.  Also, verify the
         * extent to which this errata existed on earlier 80386 steppings (I'm currently assuming A0-B1).
         */
        if (this.stepping >= X86.STEPPING_80386_A0 && this.stepping <= X86.STEPPING_80386_B2) {
            if (!(this.opPrefixes & X86.OPFLAG.ADDRSIZE) != (this.getByte(this.regLIP) != X86.OPCODE.AS)) {
                maskAddr ^= (0xffff0000|0);
            }
        }
        this.regEDI = (this.regEDI & ~maskAddr) | ((this.regEDI + ((this.regPS & X86.PS.DF)? -1 : 1)) & maskAddr);

        this.nStepCycles -= nCycles;
        if (nReps) this.rewindIP();
    }
};

/**
 * op=0xAB (STOSW)
 *
 * NOTES: Segment overrides are ignored for this instruction, so we must use segES instead of segData.
 *
 * @this {CPUx86}
 */
X86.opSTOSw = function()
{
    let nReps = 1;
    let nDelta = 0;
    let maskAddr = this.maskAddr;

    let nCycles = this.cycleCounts.nOpCyclesStoS;
    if (this.opPrefixes & (X86.OPFLAG.REPZ | X86.OPFLAG.REPNZ)) {
        nReps = this.regECX & maskAddr;
        nDelta = 1;
        nCycles = this.cycleCounts.nOpCyclesStoSrn;
        if (!(this.opPrefixes & X86.OPFLAG.REPEAT)) this.nStepCycles -= this.cycleCounts.nOpCyclesStoSr0;
    }
    if (nReps--) {
        this.setSOWord(this.segES, this.regEDI & maskAddr, this.regEAX);
        /*
         * helpFault() throws exceptions now, so inline checks of X86.OPFLAG.FAULT should no longer be necessary.
         *
         *      if (this.opFlags & X86.OPFLAG.FAULT) return;
         */
        if (BACKTRACK) {
            this.backTrack.btiMem0 = this.backTrack.btiAL; this.backTrack.btiMem1 = this.backTrack.btiAH;
        }
        this.regEDI = (this.regEDI & ~maskAddr) | ((this.regEDI + ((this.regPS & X86.PS.DF)? -this.sizeData : this.sizeData)) & maskAddr);
        this.regECX = (this.regECX & ~maskAddr) | ((this.regECX - nDelta) & maskAddr);
        this.nStepCycles -= nCycles;
        if (nReps) this.rewindIP();
    }
};

/**
 * op=0xAC (LODSB)
 *
 * @this {CPUx86}
 */
X86.opLODSb = function()
{
    let nReps = 1;
    let nDelta = 0;
    let maskAddr = this.maskAddr;

    let nCycles = this.cycleCounts.nOpCyclesLodS;
    if (this.opPrefixes & (X86.OPFLAG.REPZ | X86.OPFLAG.REPNZ)) {
        nReps = this.regECX & maskAddr;
        nDelta = 1;
        nCycles = this.cycleCounts.nOpCyclesLodSrn;
        if (!(this.opPrefixes & X86.OPFLAG.REPEAT)) this.nStepCycles -= this.cycleCounts.nOpCyclesLodSr0;
    }
    if (nReps--) {
        let b = this.getSOByte(this.segData, this.regESI & maskAddr);
        /*
         * helpFault() throws exceptions now, so inline checks of X86.OPFLAG.FAULT should no longer be necessary.
         *
         *      if (this.opFlags & X86.OPFLAG.FAULT) return;
         */
        this.regEAX = (this.regEAX & ~0xff) | b;
        if (BACKTRACK) this.backTrack.btiAL = this.backTrack.btiMem0;
        this.regESI = (this.regESI & ~maskAddr) | ((this.regESI + ((this.regPS & X86.PS.DF)? -1 : 1)) & maskAddr);
        this.regECX = (this.regECX & ~maskAddr) | ((this.regECX - nDelta) & maskAddr);
        this.nStepCycles -= nCycles;
        if (nReps) this.rewindIP(true);
    }
};

/**
 * op=0xAD (LODSW)
 *
 * @this {CPUx86}
 */
X86.opLODSw = function()
{
    let nReps = 1;
    let nDelta = 0;
    let maskAddr = this.maskAddr;

    let nCycles = this.cycleCounts.nOpCyclesLodS;
    if (this.opPrefixes & (X86.OPFLAG.REPZ | X86.OPFLAG.REPNZ)) {
        nReps = this.regECX & maskAddr;
        nDelta = 1;
        nCycles = this.cycleCounts.nOpCyclesLodSrn;
        if (!(this.opPrefixes & X86.OPFLAG.REPEAT)) this.nStepCycles -= this.cycleCounts.nOpCyclesLodSr0;
    }
    if (nReps--) {
        let w = this.getSOWord(this.segData, this.regESI & maskAddr);
        /*
         * helpFault() throws exceptions now, so inline checks of X86.OPFLAG.FAULT should no longer be necessary.
         *
         *      if (this.opFlags & X86.OPFLAG.FAULT) return;
         */
        this.regEAX = (this.regEAX & ~this.maskData) | w;
        if (BACKTRACK) {
            this.backTrack.btiAL = this.backTrack.btiMem0; this.backTrack.btiAH = this.backTrack.btiMem1;
        }
        this.regESI = (this.regESI & ~maskAddr) | ((this.regESI + ((this.regPS & X86.PS.DF)? -this.sizeData : this.sizeData)) & maskAddr);
        this.regECX = (this.regECX & ~maskAddr) | ((this.regECX - nDelta) & maskAddr);
        this.nStepCycles -= nCycles;
        if (nReps) this.rewindIP(true);
    }
};

/**
 * op=0xAE (SCASB)
 *
 * @this {CPUx86}
 */
X86.opSCASb = function()
{
    let nReps = 1;
    let nDelta = 0;
    let maskAddr = this.maskAddr;

    let nCycles = this.cycleCounts.nOpCyclesScaS;
    if (this.opPrefixes & (X86.OPFLAG.REPZ | X86.OPFLAG.REPNZ)) {
        nReps = this.regECX & maskAddr;
        nDelta = 1;
        nCycles = this.cycleCounts.nOpCyclesScaSrn;
        if (!(this.opPrefixes & X86.OPFLAG.REPEAT)) this.nStepCycles -= this.cycleCounts.nOpCyclesScaSr0;
    }
    if (nReps--) {
        let bDst = this.regEAX & 0xff;
        let bSrc = this.getEAByte(this.segES, this.regEDI);
        this.regEAWrite = this.regEA;           // TODO: Is this necessary?
        X86.fnCMPb.call(this, bDst, bSrc);
        /*
         * helpFault() throws exceptions now, so inline checks of X86.OPFLAG.FAULT should no longer be necessary.
         *
         *      if (this.opFlags & X86.OPFLAG.FAULT) return;
         */
        this.regEDI = (this.regEDI & ~maskAddr) | ((this.regEDI + ((this.regPS & X86.PS.DF)? -1 : 1)) & maskAddr);
        this.regECX = (this.regECX & ~maskAddr) | ((this.regECX - nDelta) & maskAddr);
        /*
         * NOTE: As long as we're calling fnCMPb(), all our cycle times must be reduced by nOpCyclesArithRM
         */
        this.nStepCycles -= nCycles - this.cycleCounts.nOpCyclesArithRM;
        /*
         * Repetition continues while ZF matches bit 0 of the REP prefix.  getZF() returns 0x40 if ZF is
         * set, and OP_REPZ (which represents the REP prefix whose bit 0 is set) is 0x40 as well, so when those
         * two values are equal, we must continue.
         */
        if (nReps && this.getZF() == (this.opPrefixes & X86.OPFLAG.REPZ)) this.rewindIP();
    }
};

/**
 * op=0xAF (SCASW)
 *
 * @this {CPUx86}
 */
X86.opSCASw = function()
{
    let nReps = 1;
    let nDelta = 0;
    let maskAddr = this.maskAddr;

    let nCycles = this.cycleCounts.nOpCyclesScaS;
    if (this.opPrefixes & (X86.OPFLAG.REPZ | X86.OPFLAG.REPNZ)) {
        nReps = this.regECX & maskAddr;
        nDelta = 1;
        nCycles = this.cycleCounts.nOpCyclesScaSrn;
        if (!(this.opPrefixes & X86.OPFLAG.REPEAT)) this.nStepCycles -= this.cycleCounts.nOpCyclesScaSr0;
    }
    if (nReps--) {
        let wDst = this.regEAX & this.maskData;
        let wSrc = this.getEAWord(this.segES, this.regEDI & maskAddr);
        this.regEAWrite = this.regEA;           // TODO: Is this necessary?
        X86.fnCMPw.call(this, wDst, wSrc);
        /*
         * helpFault() throws exceptions now, so inline checks of X86.OPFLAG.FAULT should no longer be necessary.
         *
         *      if (this.opFlags & X86.OPFLAG.FAULT) return;
         */
        this.regEDI = (this.regEDI & ~maskAddr) | ((this.regEDI + ((this.regPS & X86.PS.DF)? -this.sizeData : this.sizeData)) & maskAddr);
        this.regECX = (this.regECX & ~maskAddr) | ((this.regECX - nDelta) & maskAddr);
        /*
         * NOTE: As long as we're calling fnCMPw(), all our cycle times must be reduced by nOpCyclesArithRM
         */
        this.nStepCycles -= nCycles - this.cycleCounts.nOpCyclesArithRM;
        /*
         * Repetition continues while ZF matches bit 0 of the REP prefix.  getZF() returns 0x40 if ZF is
         * set, and OP_REPZ (which represents the REP prefix whose bit 0 is set) is 0x40 as well, so when those
         * two values are equal, we must continue.
         */
        if (nReps && this.getZF() == (this.opPrefixes & X86.OPFLAG.REPZ)) this.rewindIP();
    }
};

/**
 * op=0xB0 (MOV AL,imm8)
 *
 * @this {CPUx86}
 */
X86.opMOVALb = function()
{
    this.regEAX = (this.regEAX & ~0xff) | this.getIPByte();
    if (BACKTRACK) this.backTrack.btiAL = this.backTrack.btiMem0;
    this.nStepCycles -= this.cycleCounts.nOpCyclesLAHF;
};

/**
 * op=0xB1 (MOV CL,imm8)
 *
 * @this {CPUx86}
 */
X86.opMOVCLb = function()
{
    this.regECX = (this.regECX & ~0xff) | this.getIPByte();
    if (BACKTRACK) this.backTrack.btiCL = this.backTrack.btiMem0;
    this.nStepCycles -= this.cycleCounts.nOpCyclesLAHF;
};

/**
 * op=0xB2 (MOV DL,imm8)
 *
 * @this {CPUx86}
 */
X86.opMOVDLb = function()
{
    this.regEDX = (this.regEDX & ~0xff) | this.getIPByte();
    if (BACKTRACK) this.backTrack.btiDL = this.backTrack.btiMem0;
    this.nStepCycles -= this.cycleCounts.nOpCyclesLAHF;
};

/**
 * op=0xB3 (MOV BL,imm8)
 *
 * @this {CPUx86}
 */
X86.opMOVBLb = function()
{
    this.regEBX = (this.regEBX & ~0xff) | this.getIPByte();
    if (BACKTRACK) this.backTrack.btiBL = this.backTrack.btiMem0;
    this.nStepCycles -= this.cycleCounts.nOpCyclesLAHF;
};

/**
 * op=0xB4 (MOV AH,imm8)
 *
 * @this {CPUx86}
 */
X86.opMOVAHb = function()
{
    this.regEAX = (this.regEAX & ~0xff00) | (this.getIPByte() << 8);
    if (BACKTRACK) this.backTrack.btiAH = this.backTrack.btiMem0;
    this.nStepCycles -= this.cycleCounts.nOpCyclesLAHF;
};

/**
 * op=0xB5 (MOV CH,imm8)
 *
 * @this {CPUx86}
 */
X86.opMOVCHb = function()
{
    this.regECX = (this.regECX & ~0xff00) | (this.getIPByte() << 8);
    if (BACKTRACK) this.backTrack.btiCH = this.backTrack.btiMem0;
    this.nStepCycles -= this.cycleCounts.nOpCyclesLAHF;
};

/**
 * op=0xB6 (MOV DH,imm8)
 *
 * @this {CPUx86}
 */
X86.opMOVDHb = function()
{
    this.regEDX = (this.regEDX & ~0xff00) | (this.getIPByte() << 8);
    if (BACKTRACK) this.backTrack.btiDH = this.backTrack.btiMem0;
    this.nStepCycles -= this.cycleCounts.nOpCyclesLAHF;
};

/**
 * op=0xB7 (MOV BH,imm8)
 *
 * @this {CPUx86}
 */
X86.opMOVBHb = function()
{
    this.regEBX = (this.regEBX & ~0xff00) | (this.getIPByte() << 8);
    if (BACKTRACK) this.backTrack.btiBH = this.backTrack.btiMem0;
    this.nStepCycles -= this.cycleCounts.nOpCyclesLAHF;
};

/**
 * op=0xB8 (MOV [E]AX,imm)
 *
 * @this {CPUx86}
 */
X86.opMOVAX = function()
{
    this.regEAX = (this.regEAX & ~this.maskData) | this.getIPWord();
    if (BACKTRACK) {
        this.backTrack.btiAL = this.backTrack.btiMem0; this.backTrack.btiAH = this.backTrack.btiMem1;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesLAHF;
};

/**
 * op=0xB9 (MOV [E]CX,imm)
 *
 * @this {CPUx86}
 */
X86.opMOVCX = function()
{
    this.regECX = (this.regECX & ~this.maskData) | this.getIPWord();
    if (BACKTRACK) {
        this.backTrack.btiCL = this.backTrack.btiMem0; this.backTrack.btiCH = this.backTrack.btiMem1;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesLAHF;
};

/**
 * op=0xBA (MOV [E]DX,imm)
 *
 * @this {CPUx86}
 */
X86.opMOVDX = function()
{
    this.regEDX = (this.regEDX & ~this.maskData) | this.getIPWord();
    if (BACKTRACK) {
        this.backTrack.btiDL = this.backTrack.btiMem0; this.backTrack.btiDH = this.backTrack.btiMem1;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesLAHF;
};

/**
 * op=0xBB (MOV [E]BX,imm)
 *
 * @this {CPUx86}
 */
X86.opMOVBX = function()
{
    this.regEBX = (this.regEBX & ~this.maskData) | this.getIPWord();
    if (BACKTRACK) {
        this.backTrack.btiBL = this.backTrack.btiMem0; this.backTrack.btiBH = this.backTrack.btiMem1;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesLAHF;
};

/**
 * op=0xBC (MOV [E]SP,imm)
 *
 * @this {CPUx86}
 */
X86.opMOVSP = function()
{
    this.setSP((this.getSP() & ~this.maskData) | this.getIPWord());
    this.nStepCycles -= this.cycleCounts.nOpCyclesLAHF;
};

/**
 * op=0xBD (MOV [E]BP,imm)
 *
 * @this {CPUx86}
 */
X86.opMOVBP = function()
{
    this.regEBP = (this.regEBP & ~this.maskData) | this.getIPWord();
    if (BACKTRACK) {
        this.backTrack.btiBPLo = this.backTrack.btiMem0; this.backTrack.btiBPHi = this.backTrack.btiMem1;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesLAHF;
};

/**
 * op=0xBE (MOV [E]SI,imm)
 *
 * @this {CPUx86}
 */
X86.opMOVSI = function()
{
    this.regESI = (this.regESI & ~this.maskData) | this.getIPWord();
    if (BACKTRACK) {
        this.backTrack.btiSILo = this.backTrack.btiMem0; this.backTrack.btiSIHi = this.backTrack.btiMem1;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesLAHF;
};

/**
 * op=0xBF (MOV [E]DI,imm)
 *
 * @this {CPUx86}
 */
X86.opMOVDI = function()
{
    this.regEDI = (this.regEDI & ~this.maskData) | this.getIPWord();
    if (BACKTRACK) {
        this.backTrack.btiDILo = this.backTrack.btiMem0; this.backTrack.btiDIHi = this.backTrack.btiMem1;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesLAHF;
};

/**
 * op=0xC0 (GRP2 byte,imm8) (80186/80188 and up)
 *
 * @this {CPUx86}
 */
X86.opGRP2bn = function()
{
    this.decodeModGrpByte.call(this, X86.aOpGrp2b, X86.helpSRCByte);
};

/**
 * op=0xC1 (GRP2 word,imm) (80186/80188 and up)
 *
 * @this {CPUx86}
 */
X86.opGRP2wn = function()
{
    this.decodeModGrpWord.call(this, this.sizeData == 2? X86.aOpGrp2w : X86.aOpGrp2d, X86.helpSRCByte);
};

/**
 * op=0xC2 (RET n)
 *
 * @this {CPUx86}
 */
X86.opRETn = function()
{
    let n = this.getIPShort();
    let newIP = this.popWord();
    this.setIP(newIP);
    if (n) this.setSP(this.getSP() + n);            // TODO: optimize
    this.nStepCycles -= this.cycleCounts.nOpCyclesRetn;
};

/**
 * op=0xC3 (RET)
 *
 * @this {CPUx86}
 */
X86.opRET = function()
{
    let newIP = this.popWord();
    this.setIP(newIP);
    this.nStepCycles -= this.cycleCounts.nOpCyclesRet;
};

/**
 * op=0xC4 (LES reg,word)
 *
 * This is like a "MOV reg,rm" operation, but it also loads ES from the next word.
 *
 * @this {CPUx86}
 */
X86.opLES = function()
{
    this.decodeModRegWord.call(this, X86.fnLES);
};

/**
 * op=0xC5 (LDS reg,word)
 *
 * This is like a "MOV reg,rm" operation, but it also loads DS from the next word.
 *
 * @this {CPUx86}
 */
X86.opLDS = function()
{
    this.decodeModRegWord.call(this, X86.fnLDS);
};

/**
 * op=0xC6 (MOV byte,imm8)
 *
 * @this {CPUx86}
 */
X86.opMOVb = function()
{
    /*
     * Like other MOV operations, the destination does not need to be read, just written.
     */
    this.opFlags |= X86.OPFLAG.NOREAD;
    this.decodeModGrpByte.call(this, X86.aOpGrpMOVn, this.getIPByte);
};

/**
 * op=0xC7 (MOV word,imm)
 *
 * @this {CPUx86}
 */
X86.opMOVw = function()
{
    /*
     * Like other MOV operations, the destination does not need to be read, just written.
     */
    this.opFlags |= X86.OPFLAG.NOREAD;
    this.decodeModGrpWord.call(this, X86.aOpGrpMOVn, this.getIPWord);
};

/**
 * op=0xC8 (ENTER imm16,imm8) (80186/80188 and up)
 *
 * @this {CPUx86}
 */
X86.opENTER = function()
{
    /*
     * Any operation that performs multiple stack modifications must snapshot regLSP first.
     */
    this.opLSP = this.regLSP;

    let wLocal = this.getIPShort();
    let bLevel = this.getIPByte() & 0x1f;
    /*
     * NOTE: 11 is the minimum cycle time for the 80286; the 80186/80188 has different cycle times: 15, 25 and
     * 22 + 16 * (bLevel - 1) for bLevel 0, 1 and > 1, respectively.  TODO: Fix this someday.
     */
    this.nStepCycles -= 11;
    this.pushWord(this.regEBP);
    let wFrame = this.getSP() & this.maskData;
    if (bLevel > 0) {
        this.nStepCycles -= (bLevel << 2) + (bLevel > 1? 1 : 0);
        while (--bLevel) {
            this.regEBP = (this.regEBP & ~this.maskData) | ((this.regEBP - this.sizeData) & this.maskData);
            this.pushWord(this.getSOWord(this.segSS, this.regEBP & this.maskData));
        }
        this.pushWord(wFrame);
    }
    this.regEBP = (this.regEBP & ~this.maskData) | wFrame;
    this.setSP((this.getSP() & ~this.segSS.maskAddr) | ((this.getSP() - wLocal) & this.segSS.maskAddr));

    this.opLSP = X86.ADDR_INVALID;
};

/**
 * op=0xC9 (LEAVE) (80186/80188 and up)
 *
 * @this {CPUx86}
 */
X86.opLEAVE = function()
{
    /*
     * Any operation that performs multiple stack modifications must snapshot regLSP first.
     */
    this.opLSP = this.regLSP;

    this.setSP((this.getSP() & ~this.segSS.maskAddr) | (this.regEBP & this.segSS.maskAddr));

    this.regEBP = (this.regEBP & ~this.maskData) | (this.popWord() & this.maskData);
    /*
     * NOTE: 5 is the cycle time for the 80286; the 80186/80188 has a cycle time of 8.  TODO: Fix this someday.
     */
    this.nStepCycles -= 5;

    this.opLSP = X86.ADDR_INVALID;
};

/**
 * op=0xCA (RETF n)
 *
 * @this {CPUx86}
 */
X86.opRETFn = function()
{
    X86.helpRETF.call(this, this.getIPShort());
    this.nStepCycles -= this.cycleCounts.nOpCyclesRetFn;
};

/**
 * op=0xCB (RETF)
 *
 * @this {CPUx86}
 */
X86.opRETF = function()
{
    X86.helpRETF.call(this, 0);
    this.nStepCycles -= this.cycleCounts.nOpCyclesRetF;
};

/**
 * op=0xCC (INT 3)
 *
 * @this {CPUx86}
 */
X86.opINT3 = function()
{
    /*
     * TODO: Consider swapping out this function whenever setProtMode() changes the mode to V86-mode.
     */
    if (I386 && (this.regPS & X86.PS.VM) && this.nIOPL < 3) {
        if (DEBUG) this.printMessage("INT 0x03 in v86-mode (IOPL < 3)", this.bitsMessage, true);
        X86.helpFault.call(this, X86.EXCEPTION.GP_FAULT, 0);
        return;
    }
    /*
     * Because INT3 is a trap, not a fault, we must use helpTrap() rather than helpFault().  Unfortunately, that
     * means you can't rely on the Debugger logic instead helpFault() to conditionally stop execution on an INT3,
     * so I've changed the Debugger's checkBreakpoint() function to stop execution on INT3 whenever both the
     * INT and HALT message bits are set; a simple "g" command allows you to continue.
     */
    X86.helpTrap.call(this, X86.EXCEPTION.BP_TRAP, this.cycleCounts.nOpCyclesInt3D);
};

/**
 * op=0xCD (INT n)
 *
 * @this {CPUx86}
 */
X86.opINTn = function()
{
    let nInt = this.getIPByte();
    /*
     * TODO: Consider swapping out this function whenever setProtMode() changes the mode to V86-mode.
     */
    if (I386 && (this.regPS & X86.PS.VM) && this.nIOPL < 3) {
        if (DEBUG && this.messageEnabled()) this.printMessage("INT " + Str.toHexByte(nInt) + " in v86-mode (IOPL < 3)", true, true);
        X86.helpFault.call(this, X86.EXCEPTION.GP_FAULT, 0);
        return;
    }
    /*
     * checkIntNotify() checks for any notification handlers registered via addIntNotify(), calls them,
     * and returns false ONLY if a notification handler returned false (ie, requesting the interrupt be skipped).
     */
    if (this.checkIntNotify(nInt)) {
        X86.helpTrap.call(this, nInt, 0);
        return;
    }
    this.nStepCycles--;     // we don't need to assess the full cost of nOpCyclesInt, but we need to assess something...
};

/**
 * op=0xCE (INTO: INT 4 if OF set)
 *
 * @this {CPUx86}
 */
X86.opINTO = function()
{
    if (this.getOF()) {
        /*
         * TODO: Consider swapping out this function whenever setProtMode() changes the mode to V86-mode.
         */
        if (I386 && (this.regPS & X86.PS.VM) && this.nIOPL < 3) {
            if (DEBUG) this.printMessage("INTO in v86-mode (IOPL < 3)", this.bitsMessage, true);
            X86.helpFault.call(this, X86.EXCEPTION.GP_FAULT, 0);
            return;
        }
        X86.helpTrap.call(this, X86.EXCEPTION.OF_TRAP, this.cycleCounts.nOpCyclesIntOD);
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesIntOFall;
};

/**
 * op=0xCF (IRET)
 *
 * @this {CPUx86}
 */
X86.opIRET = function()
{
    /*
     * TODO: Consider swapping out this function whenever setProtMode() changes the mode to V86-mode.
     */
    if (I386 && (this.regPS & X86.PS.VM) && this.nIOPL < 3) {
        if (DEBUG) this.printMessage("IRET in v86-mode (IOPL < 3)", this.bitsMessage, true);
        X86.helpFault.call(this, X86.EXCEPTION.GP_FAULT, 0);
        return;
    }
    this.opFlags |= X86.OPFLAG.IRET;
    X86.helpIRET.call(this);
};

/**
 * op=0xD0 (GRP2 byte,1)
 *
 * @this {CPUx86}
 */
X86.opGRP2b1 = function()
{
    this.decodeModGrpByte.call(this, X86.aOpGrp2b, X86.helpSRC1);
};

/**
 * op=0xD1 (GRP2 word,1)
 *
 * @this {CPUx86}
 */
X86.opGRP2w1 = function()
{
    this.decodeModGrpWord.call(this, this.sizeData == 2? X86.aOpGrp2w : X86.aOpGrp2d, X86.helpSRC1);
};

/**
 * op=0xD2 (GRP2 byte,CL)
 *
 * @this {CPUx86}
 */
X86.opGRP2bCL = function()
{
    this.decodeModGrpByte.call(this, X86.aOpGrp2b, X86.helpSRCCL);
};

/**
 * op=0xD3 (GRP2 word,CL)
 *
 * @this {CPUx86}
 */
X86.opGRP2wCL = function()
{
    this.decodeModGrpWord.call(this, this.sizeData == 2? X86.aOpGrp2w : X86.aOpGrp2d, X86.helpSRCCL);
};

/**
 * op=0xD4 0x0A (AAM)
 *
 * From "The 8086 Book":
 *
 *      1. Divide AL by 0x0A; store the quotient in AH and the remainder in AL
 *      2. Set PF, SF, and ZF based on the AL register (CF, OF, and AF are undefined)
 *
 * From "Undocumented Opcodes" (http://www.rcollins.org/secrets/opcodes/AAM.html):
 *
 *      AAM is shown as a two byte encoding used to divide AL by 10, putting the quotient in AH, and the remainder in AL.
 *      However, AAM is listed in the op code map as a single byte instruction. This leads one to wonder why a two-byte
 *      opcode is listed in the single-byte opcode map. In reality, the second byte is an undocumented operand to AAM.
 *      The operand is the divisor. In its documented incarnation, AAM is encoded as D4 0A. The operand 0A is the divisor.
 *      This divisor can be changed to any value between 0 and FF.
 *
 *      Using AAM in this manner is useful -- as it extends the CPU instruction set to include a DIV IMM8 instruction
 *      that is not available from any other form of the DIV instruction. The extended form of the AAM instruction is also
 *      useful because it sets the flags register according to the results, unlike the DIV or IDIV instruction.
 *
 *      According to Intel documentation, SF, ZF, and PF flags are set according to the result, while OF, AF, and CF
 *      are undefined. However, if AAM were used strictly as documented, then the Sign Flag (SF) could not be set under
 *      any circumstances, since anything divided by 10 will leave a remainder between 0 and 9. Obviously the remainder
 *      could never be between 128 and 255 (or -1 and -128 if you prefer) if used only as documented. Since AAM divides
 *      an 8 bit number by another 8-bit number, a carry or overflow could never occur. Therefore CF and OF always=0.
 *      Intel claims they are undefined, but my observations are consistent with my theory.
 *
 *      Contrary to documentation, AAM will generate exceptions in real mode, protected mode, and V86 mode. AAM can only
 *      generate Exception 0 -- divide by 0.
 *
 *      Finally, in the Pentium User's Manual, this heretofore undocumented form of AMM is described. Intel says:
 *
 *          Note: imm8 has the value of the instruction's second byte. The second byte under normally assembly [sic] of
 *          this instruction will be 0A, however, explicit modification of this byte will result in the operation described
 *          above and may alter results.
 *
 *      This instruction exists in this form on all Intel x86 processors. See the file [AAM.ASM](/docs/x86/ops/AAM/AAM.ASM)
 *      for diagnostics source code for this instruction.
 *
 * @this {CPUx86}
 */
X86.opAAM = function()
{
    let b = this.getIPByte();
    if (!b) {
        X86.helpDIVOverflow.call(this);
        return;
    }
    let AL = this.regEAX & 0xff;
    this.regEAX = (this.regEAX & ~0xffff) | ((AL / b) << 8) | (AL % b);
    /*
     * setLogicResult() is perfect, because it ensures that CF and OF are cleared as well (see above for why).
     */
    this.setLogicResult(this.regEAX, X86.RESULT.BYTE);
    this.nStepCycles -= this.cycleCounts.nOpCyclesAAM;
};

/**
 * op=0xD5 (AAD)
 *
 * From "The 8086 Book":
 *
 *      1. Multiply AH by 0x0A, add AH to AL, and store 0x00 in AH
 *      2. Set PF, SF, and ZF based on the AL register (CF, OF, and AF are undefined)
 *
 * From "Undocumented Opcodes" (http://www.rcollins.org/secrets/opcodes/AAD.html):
 *
 *      This instruction is the multiplication counterpart to AAM. As is the case with AAM, AAD uses the second
 *      byte as an operand. This operand is the multiplicand for AAD. Like AAM, AAD provides a way to execute a MUL
 *      IMM8 that is unavailable through any other means in the CPU.
 *
 *      Unlike MUL, or IMUL, AAD sets all of the CPU status flags according to the result. Intel states that the
 *      Overflow Flag (OF), Auxiliary carry Flag (AF), and Carry Flag (CF) are undefined. This assertion is incorrect.
 *      These flags are fully defined, and are set consistently with respect to any other integer operations.
 *
 *      And again, like AMM, beginning with the Pentium, Intel has finally acknowledged the existence of the second
 *      byte of this instruction as its operand. Intel says:
 *
 *          Note: imm8 has the value of the instruction's second byte. The second byte under normally assembly [sic]
 *          of this instruction will be 0A, however, explicit modification of this byte will result in the operation
 *          described above and may alter results.
 *
 *      This instruction exists in this form on all Intel x86 processors. See the file [AAD.ASM](/docs/x86/ops/AAD/AAD.ASM)
 *      for diagnostics source code for this instruction.
 *
 * TODO: Confirm on real hardware that flags reflect the result of the final addition (ie, that the result of the
 * intermediate multiplication is irrelevant); it also might be nice to confirm that an operand override has no effect.
 *
 * @this {CPUx86}
 */
X86.opAAD = function()
{
    let dst = (this.regEAX & 0xff);
    let src = (((this.regEAX >> 8) & 0xff) * this.getIPByte())|0;
    let result = (dst + src)|0;
    this.regEAX = (this.regEAX & ~0xffff) | (result & 0xff);
    this.setArithResult(dst, src, result, X86.RESULT.BYTE | X86.RESULT.ALL);
    this.nStepCycles -= this.cycleCounts.nOpCyclesAAD;
};

/**
 * op=0xD6 (SALC aka SETALC) (undocumented until Pentium Pro)
 *
 * Sets AL to 0xFF if CF=1, 0x00 otherwise; no flags are affected (similar to SBB AL,AL, but without side-effects)
 *
 * WARNING: I have no idea how many clocks this instruction originally required, so for now, I'm going with a minimum of 2.
 *
 * @this {CPUx86}
 */
X86.opSALC = function()
{
    this.regEAX = (this.regEAX & ~0xff) | (this.getCF()? 0xFF : 0);
    this.nStepCycles -= 2;
};

/**
 * op=0xD7 (XLAT)
 *
 * @this {CPUx86}
 */
X86.opXLAT = function()
{
    /*
     * TODO: Verify whether XLAT wraps its address calculation....
     */
    this.regEAX = (this.regEAX & ~0xff) | this.getEAByte(this.segData, (this.regEBX + (this.regEAX & 0xff)));
    this.nStepCycles -= this.cycleCounts.nOpCyclesXLAT;
};

/**
 * opESC()
 *
 * @this {CPUx86}
 * @param {number} bOpcode
 */
X86.opESC = function(bOpcode)
{
    this.bOpcode = bOpcode;
    this.decodeModRegWord.call(this, X86.fnESC);
};

/**
 * op=0xD8 (ESC0)
 *
 * @this {CPUx86}
 */
X86.opESC0 = function()
{
    X86.opESC.call(this, X86.OPCODE.ESC0);
};

/**
 * op=0xD9 (ESC1)
 *
 * @this {CPUx86}
 */
X86.opESC1 = function()
{
    X86.opESC.call(this, X86.OPCODE.ESC1);
};

/**
 * op=0xDA (ESC2)
 *
 * @this {CPUx86}
 */
X86.opESC2 = function()
{
    X86.opESC.call(this, X86.OPCODE.ESC2);
};

/**
 * op=0xDB (ESC3)
 *
 * @this {CPUx86}
 */
X86.opESC3 = function()
{
    X86.opESC.call(this, X86.OPCODE.ESC3);
};

/**
 * op=0xDC (ESC4)
 *
 * @this {CPUx86}
 */
X86.opESC4 = function()
{
    X86.opESC.call(this, X86.OPCODE.ESC4);
};

/**
 * op=0xDD (ESC5)
 *
 * @this {CPUx86}
 */
X86.opESC5 = function()
{
    X86.opESC.call(this, X86.OPCODE.ESC5);
};

/**
 * op=0xDE (ESC6)
 *
 * @this {CPUx86}
 */
X86.opESC6 = function()
{
    X86.opESC.call(this, X86.OPCODE.ESC6);
};

/**
 * op=0xDF (ESC7)
 *
 * @this {CPUx86}
 */
X86.opESC7 = function()
{
    X86.opESC.call(this, X86.OPCODE.ESC7);
};

/**
 * op=0xE0 (LOOPNZ disp)
 *
 * NOTE: All the instructions in this group (LOOPNZ, LOOPZ, LOOP, and JCXZ) actually
 * rely on the ADDRESS override setting for determining whether CX or ECX will be used,
 * even though it seems counter-intuitive; ditto for the REP prefix.
 *
 * @this {CPUx86}
 */
X86.opLOOPNZ = function()
{
    let disp = this.getIPDisp();
    let n = (this.regECX - 1) & this.maskAddr;
    this.regECX = (this.regECX & ~this.maskAddr) | n;
    if (n && !this.getZF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesLoopNZ;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesLoopFall;
};

/**
 * op=0xE1 (LOOPZ disp)
 *
 * NOTE: All the instructions in this group (LOOPNZ, LOOPZ, LOOP, and JCXZ) actually
 * rely on the ADDRESS override setting for determining whether CX or ECX will be used,
 * even though it seems counter-intuitive; ditto for the REP prefix.
 *
 * @this {CPUx86}
 */
X86.opLOOPZ = function()
{
    let disp = this.getIPDisp();
    let n = (this.regECX - 1) & this.maskAddr;
    this.regECX = (this.regECX & ~this.maskAddr) | n;
    if (n && this.getZF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesLoopZ;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesLoopZFall;
};

/**
 * op=0xE2 (LOOP disp)
 *
 * NOTE: All the instructions in this group (LOOPNZ, LOOPZ, LOOP, and JCXZ) actually
 * rely on the ADDRESS override setting for determining whether CX or ECX will be used,
 * even though it seems counter-intuitive; ditto for the REP prefix.
 *
 * @this {CPUx86}
 */
X86.opLOOP = function()
{
    let disp = this.getIPDisp();
    let n = (this.regECX - 1) & this.maskAddr;
    this.regECX = (this.regECX & ~this.maskAddr) | n;
    if (n) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesLoop;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesLoopFall;
};

/**
 * op=0xE3 (JCXZ/JECXZ disp)
 *
 * NOTE: All the instructions in this group (LOOPNZ, LOOPZ, LOOP, and JCXZ) actually
 * rely on the ADDRESS override setting for determining whether CX or ECX will be used,
 * even though it seems counter-intuitive; ditto for the REP prefix.
 *
 * @this {CPUx86}
 */
X86.opJCXZ = function()
{
    let disp = this.getIPDisp();
    if (!(this.regECX & this.maskAddr)) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesLoopZ;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesLoopZFall;
};

/**
 * op=0xE4 (IN AL,port)
 *
 * @this {CPUx86}
 */
X86.opINb = function()
{
    let port = this.getIPByte();
    if (!this.checkIOPM(port, 1, true)) return;
    this.regEAX = (this.regEAX & ~0xff) | (this.bus.checkPortInputNotify(port, 1, this.regLIP - 2) & 0xff);
    if (BACKTRACK) this.backTrack.btiAL = this.backTrack.btiIO;
    this.nStepCycles -= this.cycleCounts.nOpCyclesInP;
};

/**
 * op=0xE5 (IN AX,port)
 *
 * @this {CPUx86}
 */
X86.opINw = function()
{
    let port = this.getIPByte();
    if (!this.checkIOPM(port, this.sizeData, true)) return;
    this.regEAX = (this.regEAX & ~this.maskData) | (this.bus.checkPortInputNotify(port, this.sizeData, this.regLIP - 2) & this.maskData);
    if (BACKTRACK) {
        this.backTrack.btiAL = this.backTrack.btiIO;
        this.backTrack.btiAH = this.backTrack.btiIO;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesInP;
};

/**
 * op=0xE6 (OUT port,AL)
 *
 * @this {CPUx86}
 */
X86.opOUTb = function()
{
    let port = this.getIPByte();
    if (!this.checkIOPM(port, 1, false)) return;
    this.bus.checkPortOutputNotify(port, 1, this.regEAX & 0xff, this.regLIP - 2);
    this.nStepCycles -= this.cycleCounts.nOpCyclesOutP;
};

/**
 * op=0xE7 (OUT port,AX)
 *
 * @this {CPUx86}
 */
X86.opOUTw = function()
{
    let port = this.getIPByte();
    if (!this.checkIOPM(port, this.sizeData, false)) return;
    this.bus.checkPortOutputNotify(port, this.sizeData, this.regEAX & this.maskData, this.regLIP - 2);
    this.nStepCycles -= this.cycleCounts.nOpCyclesOutP;
};

/**
 * op=0xE8 (CALL disp16)
 *
 * @this {CPUx86}
 */
X86.opCALL = function()
{
    let disp = this.getIPWord();
    let oldIP = this.getIP();
    let newIP = oldIP + disp;
    this.pushWord(oldIP);
    this.setIP(newIP);
    this.nStepCycles -= this.cycleCounts.nOpCyclesCall;
};

/**
 * op=0xE9 (JMP disp16)
 *
 * @this {CPUx86}
 */
X86.opJMP = function()
{
    let disp = this.getIPWord();
    this.setIP(this.getIP() + disp);
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmp;
};

/**
 * op=0xEA (JMP seg:off)
 *
 * @this {CPUx86}
 */
X86.opJMPF = function()
{
    this.setCSIP(this.getIPWord(), this.getIPShort());
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpF;
};

/**
 * op=0xEB (JMP short disp8)
 *
 * @this {CPUx86}
 */
X86.opJMPs = function()
{
    let disp = this.getIPDisp();
    this.setIP(this.getIP() + disp);
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmp;
};

/**
 * op=0xEC (IN AL,dx)
 *
 * @this {CPUx86}
 */
X86.opINDXb = function()
{
    let port = this.regEDX & 0xffff;
    if (!this.checkIOPM(port, 1, true)) return;
    this.regEAX = (this.regEAX & ~0xff) | (this.bus.checkPortInputNotify(port, 1, this.regLIP - 1) & 0xff);
    if (BACKTRACK) this.backTrack.btiAL = this.backTrack.btiIO;
    this.nStepCycles -= this.cycleCounts.nOpCyclesInDX;
};

/**
 * op=0xED (IN AX,dx)
 *
 * @this {CPUx86}
 */
X86.opINDXw = function()
{
    let port = this.regEDX & 0xffff;
    if (!this.checkIOPM(port, this.sizeData, true)) return;
    this.regEAX = (this.regEAX & ~this.maskData) | (this.bus.checkPortInputNotify(port, this.sizeData, this.regLIP - 1) & this.maskData);
    if (BACKTRACK) {
        this.backTrack.btiAL = this.backTrack.btiIO;
        this.backTrack.btiAH = this.backTrack.btiIO;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesInDX;
};

/**
 * op=0xEE (OUT dx,AL)
 *
 * @this {CPUx86}
 */
X86.opOUTDXb = function()
{
    let port = this.regEDX & 0xffff;
    if (!this.checkIOPM(port, 1, false)) return;
    if (BACKTRACK) this.backTrack.btiIO = this.backTrack.btiAL;
    this.bus.checkPortOutputNotify(port, 1, this.regEAX & 0xff, this.regLIP - 1);
    this.nStepCycles -= this.cycleCounts.nOpCyclesOutDX;
};

/**
 * op=0xEF (OUT dx,AX)
 *
 * @this {CPUx86}
 */
X86.opOUTDXw = function()
{
    let port = this.regEDX & 0xffff;
    if (!this.checkIOPM(port, 2, false)) return;
    if (BACKTRACK) {
        this.backTrack.btiIO = this.backTrack.btiAL;
        this.backTrack.btiIO = this.backTrack.btiAH;
    }
    this.bus.checkPortOutputNotify(port, this.sizeData, this.regEAX & this.maskData, this.regLIP - 1);
    this.nStepCycles -= this.cycleCounts.nOpCyclesOutDX;
};

/**
 * op=0xF0 (LOCK:)
 *
 * @this {CPUx86}
 */
X86.opLOCK = function()
{
    this.opFlags |= X86.OPFLAG.LOCK | X86.OPFLAG.NOINTR;
    this.nStepCycles -= this.cycleCounts.nOpCyclesPrefix;
};

/**
 * op=0xF1 (INT1; undocumented; 80386 and up)
 *
 * For the 8086/8088, we treat opcode 0xF1 as an alias for LOCK (0xF0).
 *
 * For the 80186 and 80286, and we treat it as undefined.  Starting with the 80386, this opcode is known as INT1
 * or ICEBP, since it effectively performs an INT 0x01 but is normally only performed with an ICE.
 *
 * @this {CPUx86}
 */
X86.opINT1 = function()
{
    /*
     * TODO: Verify this instruction's behavior.
     */
    X86.helpTrap.call(this, X86.EXCEPTION.DB_EXC, this.cycleCounts.nOpCyclesInt3D);
};

/**
 * op=0xF2 (REPNZ:) (repeat CMPS or SCAS until NZ; repeat MOVS, LODS, or STOS unconditionally)
 *
 * @this {CPUx86}
 */
X86.opREPNZ = function()
{
    this.opFlags |= X86.OPFLAG.REPNZ | X86.OPFLAG.NOINTR;
    this.nStepCycles -= this.cycleCounts.nOpCyclesPrefix;
};

/**
 * op=0xF3 (REPZ:) (repeat CMPS or SCAS until Z; repeat MOVS, LODS, or STOS unconditionally)
 *
 * @this {CPUx86}
 */
X86.opREPZ = function()
{
    this.opFlags |= X86.OPFLAG.REPZ | X86.OPFLAG.NOINTR;
    this.nStepCycles -= this.cycleCounts.nOpCyclesPrefix;
};

/**
 * op=0xF4 (HLT)
 *
 * @this {CPUx86}
 */
X86.opHLT = function()
{
    if (I386 && (this.regPS & X86.PS.VM)) {
        X86.helpFault.call(this, X86.EXCEPTION.GP_FAULT, 0);
        return;
    }
    /*
     * The CPU is never REALLY halted by a HLT instruction; instead, by setting X86.INTFLAG.HALT,
     * we are signalling to stepCPU() that it's free to end the current burst AND that it should not
     * execute any more instructions until checkINTR() indicates a hardware interrupt is requested.
     */
    this.intFlags |= X86.INTFLAG.HALT;
    this.nStepCycles -= 2;
    /*
     * If a Debugger is present and both the CPU and HALT message categories are enabled, then we
     * REALLY halt the CPU, on the theory that whoever's using the Debugger would like to see HLTs.
     */
    if (DEBUGGER && this.dbg && this.messageEnabled(Messages.CPU + Messages.HALT)) {
        this.resetIP();         // this is purely for the Debugger's benefit, to show the HLT
        this.dbg.stopCPU();
        return;
    }
    /*
     * We also REALLY halt the machine if interrupts have been disabled, since that means it's dead in
     * the water (yes, we support NMIs, but none of our devices are going to generate an NMI at this point).
     */
    if (!this.getIF()) {
        if (DEBUGGER && this.dbg) this.resetIP();
        this.stopCPU();
    }
};

/**
 * op=0xF5 (CMC)
 *
 * @this {CPUx86}
 */
X86.opCMC = function()
{
    if (this.getCF()) this.clearCF(); else this.setCF();
    this.nStepCycles -= 2;                          // CMC takes 2 cycles on all CPUs
};

/**
 * op=0xF6 (GRP3 byte)
 *
 * The MUL byte instruction is problematic in two cases:
 *
 *      0xF6 0xE0:  MUL AL
 *      0xF6 0xE4:  MUL AH
 *
 * because the OpModGrpByte decoder function will attempt to put the fnMULb() function's
 * return value back into AL or AH, undoing fnMULb's update of AX.  And since fnMULb doesn't
 * know what the target is (only the target's value), it cannot easily work around the problem.
 *
 * A simple, albeit kludgy, solution is for fnMULb to always save its result in a special
 * "register" (eg, regMDLo), which we will then put back into regEAX if it's been updated.
 * This also relieves us from having to decode any part of the ModRM byte, so maybe it's not
 * such a bad work-around after all.
 *
 * Similar issues with IMUL (and DIV and IDIV) are resolved using the same special variable(s).
 *
 * @this {CPUx86}
 */
X86.opGRP3b = function()
{
    this.fMDSet = false;
    this.decodeModGrpByte.call(this, X86.aOpGrp3b, X86.helpSRCNone);
    if (this.fMDSet) this.regEAX = (this.regEAX & ~this.maskData) | (this.regMDLo & this.maskData);
};

/**
 * op=0xF7 (GRP3 word)
 *
 * The MUL word instruction is problematic in two cases:
 *
 *      0xF7 0xE0:  MUL AX
 *      0xF7 0xE2:  MUL DX
 *
 * because the OpModGrpWord decoder function will attempt to put the fnMULw() function's
 * return value back into AX or DX, undoing fnMULw's update of DX:AX.  And since fnMULw doesn't
 * know what the target is (only the target's value), it cannot easily work around the problem.
 *
 * A simple, albeit kludgy, solution is for fnMULw to always save its result in a special
 * "register" (eg, regMDLo/regMDHi), which we will then put back into regEAX/regEDX if it's been
 * updated.  This also relieves us from having to decode any part of the ModRM byte, so maybe
 * it's not such a bad work-around after all.
 *
 * @this {CPUx86}
 */
X86.opGRP3w = function()
{
    this.fMDSet = false;
    this.decodeModGrpWord.call(this, X86.aOpGrp3w, X86.helpSRCNone);
    if (this.fMDSet) {
        this.regEAX = (this.regEAX & ~this.maskData) | (this.regMDLo & this.maskData);
        this.regEDX = (this.regEDX & ~this.maskData) | (this.regMDHi & this.maskData);
    }
};

/**
 * op=0xF8 (CLC)
 *
 * @this {CPUx86}
 */
X86.opCLC = function()
{
    this.clearCF();
    this.nStepCycles -= 2;                              // CLC takes 2 cycles on all CPUs
};

/**
 * op=0xF9 (STC)
 *
 * @this {CPUx86}
 */
X86.opSTC = function()
{
    this.setCF();
    this.nStepCycles -= 2;                              // STC takes 2 cycles on all CPUs
};

/**
 * op=0xFA (CLI)
 *
 * @this {CPUx86}
 */
X86.opCLI = function()
{
    /*
     * The following code should be sufficient for all modes, because in real-mode, CPL is always zero,
     * and in V86-mode, CPL is always 3.
     */
    if (this.nCPL > this.nIOPL) {
        if (DEBUG && (this.regPS & X86.PS.VM)) this.printMessage("CLI in v86-mode (IOPL < 3)", this.bitsMessage, true);
        X86.helpFault.call(this, X86.EXCEPTION.GP_FAULT, 0);
        return;
    }
    this.clearIF();
    this.nStepCycles -= this.cycleCounts.nOpCyclesCLI;  // CLI takes LONGER on an 80286
};

/**
 * op=0xFB (STI)
 *
 * @this {CPUx86}
 */
X86.opSTI = function()
{
    /*
     * The following code should be sufficient for all modes, because in real-mode, CPL is always zero,
     * and in V86-mode, CPL is always 3.
     */
    if (this.nCPL > this.nIOPL) {
        if (DEBUG && (this.regPS & X86.PS.VM)) this.printMessage("STI in v86-mode (IOPL < 3)", this.bitsMessage, true);
        X86.helpFault.call(this, X86.EXCEPTION.GP_FAULT, 0);
        return;
    }
    this.setIF();
    this.opFlags |= X86.OPFLAG.NOINTR;
    this.nStepCycles -= 2;                              // STI takes 2 cycles on all CPUs
};

/**
 * op=0xFC (CLD)
 *
 * @this {CPUx86}
 */
X86.opCLD = function()
{
    this.clearDF();
    this.nStepCycles -= 2;                              // CLD takes 2 cycles on all CPUs
};

/**
 * op=0xFD (STD)
 *
 * @this {CPUx86}
 */
X86.opSTD = function()
{
    this.setDF();
    this.nStepCycles -= 2;                              // STD takes 2 cycles on all CPUs
};

/**
 * op=0xFE (GRP4 byte)
 *
 * @this {CPUx86}
 */
X86.opGRP4b = function()
{
    this.decodeModGrpByte.call(this, X86.aOpGrp4b, X86.helpSRCNone);
};

/**
 * op=0xFF (GRP4 word)
 *
 * @this {CPUx86}
 */
X86.opGRP4w = function()
{
    this.decodeModGrpWord.call(this, X86.aOpGrp4w, X86.helpSRCNone);
};

/**
 * opInvalid()
 *
 * @this {CPUx86}
 */
X86.opInvalid = function()
{
    X86.helpFault.call(this, X86.EXCEPTION.UD_FAULT);
};

/**
 * opUndefined()
 *
 * @this {CPUx86}
 */
X86.opUndefined = function()
{
    this.setIP(this.opLIP - this.segCS.base);
    this.setError("Undefined opcode " + Str.toHexByte(this.getByte(this.regLIP)) + " at " + Str.toHexLong(this.regLIP));
    this.stopCPU();
};

/**
 * opTBD()
 *
 * @this {CPUx86}
 */
X86.opTBD = function()
{
    this.setIP(this.opLIP - this.segCS.base);
    this.printMessage("unimplemented 80386 opcode", true);
    this.stopCPU();
};

/*
 * This 256-entry array of opcode functions is at the heart of the CPU engine: stepCPU(n).
 *
 * It might be worth trying a switch() statement instead, to see how the performance compares,
 * but I suspect that would vary quite a bit across JavaScript engines; for now, I'm putting my
 * money on array lookup.
 */
X86.aOps = [
    X86.opADDmb,            X86.opADDmw,            X86.opADDrb,            X86.opADDrw,        // 0x00-0x03
    X86.opADDALb,           X86.opADDAX,            X86.opPUSHES,           X86.opPOPES,        // 0x04-0x07
    X86.opORmb,             X86.opORmw,             X86.opORrb,             X86.opORrw,         // 0x08-0x0B
    X86.opORALb,            X86.opORAX,             X86.opPUSHCS,           X86.opPOPCS,        // 0x0C-0x0F
    X86.opADCmb,            X86.opADCmw,            X86.opADCrb,            X86.opADCrw,        // 0x10-0x13
    X86.opADCALb,           X86.opADCAX,            X86.opPUSHSS,           X86.opPOPSS,        // 0x14-0x17
    X86.opSBBmb,            X86.opSBBmw,            X86.opSBBrb,            X86.opSBBrw,        // 0x18-0x1B
    X86.opSBBALb,           X86.opSBBAX,            X86.opPUSHDS,           X86.opPOPDS,        // 0x1C-0x1F
    X86.opANDmb,            X86.opANDmw,            X86.opANDrb,            X86.opANDrw,        // 0x20-0x23
    X86.opANDAL,            X86.opANDAX,            X86.opES,               X86.opDAA,          // 0x24-0x27
    X86.opSUBmb,            X86.opSUBmw,            X86.opSUBrb,            X86.opSUBrw,        // 0x28-0x2B
    X86.opSUBALb,           X86.opSUBAX,            X86.opCS,               X86.opDAS,          // 0x2C-0x2F
    X86.opXORmb,            X86.opXORmw,            X86.opXORrb,            X86.opXORrw,        // 0x30-0x33
    X86.opXORALb,           X86.opXORAX,            X86.opSS,               X86.opAAA,          // 0x34-0x37
    X86.opCMPmb,            X86.opCMPmw,            X86.opCMPrb,            X86.opCMPrw,        // 0x38-0x3B
    X86.opCMPALb,           X86.opCMPAX,            X86.opDS,               X86.opAAS,          // 0x3C-0x3F
    X86.opINCAX,            X86.opINCCX,            X86.opINCDX,            X86.opINCBX,        // 0x40-0x43
    X86.opINCSP,            X86.opINCBP,            X86.opINCSI,            X86.opINCDI,        // 0x44-0x47
    X86.opDECAX,            X86.opDECCX,            X86.opDECDX,            X86.opDECBX,        // 0x48-0x4B
    X86.opDECSP,            X86.opDECBP,            X86.opDECSI,            X86.opDECDI,        // 0x4C-0x4F
    X86.opPUSHAX,           X86.opPUSHCX,           X86.opPUSHDX,           X86.opPUSHBX,       // 0x50-0x53
    X86.opPUSHSP_8086,      X86.opPUSHBP,           X86.opPUSHSI,           X86.opPUSHDI,       // 0x54-0x57
    X86.opPOPAX,            X86.opPOPCX,            X86.opPOPDX,            X86.opPOPBX,        // 0x58-0x5B
    X86.opPOPSP,            X86.opPOPBP,            X86.opPOPSI,            X86.opPOPDI,        // 0x5C-0x5F
    /*
     * On an 8086/8088, opcodes 0x60-0x6F are aliases for the conditional jumps 0x70-0x7F.  Sometimes you'll see
     * references to these opcodes (like 0x60) being a "two-byte NOP" and using them differentiate an 8088 from newer
     * CPUs, but they're only a "two-byte NOP" if the second byte is zero, resulting in zero displacement.
     */
    X86.opJO,               X86.opJNO,              X86.opJC,               X86.opJNC,          // 0x60-0x63
    X86.opJZ,               X86.opJNZ,              X86.opJBE,              X86.opJNBE,         // 0x64-0x67
    X86.opJS,               X86.opJNS,              X86.opJP,               X86.opJNP,          // 0x68-0x6B
    X86.opJL,               X86.opJNL,              X86.opJLE,              X86.opJNLE,         // 0x6C-0x6F
    X86.opJO,               X86.opJNO,              X86.opJC,               X86.opJNC,          // 0x70-0x73
    X86.opJZ,               X86.opJNZ,              X86.opJBE,              X86.opJNBE,         // 0x74-0x77
    X86.opJS,               X86.opJNS,              X86.opJP,               X86.opJNP,          // 0x78-0x7B
    X86.opJL,               X86.opJNL,              X86.opJLE,              X86.opJNLE,         // 0x7C-0x7F
    /*
     * On all processors, opcode groups 0x80 and 0x82 perform identically (0x82 opcodes sign-extend their
     * immediate data, but since both 0x80 and 0x82 are byte operations, the sign extension has no effect).
     *
     * WARNING: Intel's "Pentium Processor User's Manual (Volume 3: Architecture and Programming Manual)" refers
     * to opcode 0x82 as a "reserved" instruction, but also cryptically refers to it as "MOVB AL,imm".  This is
     * assumed to be an error in the manual, because as far as I know, 0x82 has always mirrored 0x80.
     */
    X86.opGRP1b,            X86.opGRP1w,            X86.opGRP1b,            X86.opGRP1sw,       // 0x80-0x83
    X86.opTESTrb,           X86.opTESTrw,           X86.opXCHGrb,           X86.opXCHGrw,       // 0x84-0x87
    X86.opMOVmb,            X86.opMOVmw,            X86.opMOVrb,            X86.opMOVrw,        // 0x88-0x8B
    X86.opMOVwsr,           X86.opLEA,              X86.opMOVsrw,           X86.opPOPmw,        // 0x8C-0x8F
    X86.opNOP,              X86.opXCHGCX,           X86.opXCHGDX,           X86.opXCHGBX,       // 0x90-0x93
    X86.opXCHGSP,           X86.opXCHGBP,           X86.opXCHGSI,           X86.opXCHGDI,       // 0x94-0x97
    X86.opCBW,              X86.opCWD,              X86.opCALLF,            X86.opWAIT,         // 0x98-0x9B
    X86.opPUSHF,            X86.opPOPF,             X86.opSAHF,             X86.opLAHF,         // 0x9C-0x9F
    X86.opMOVALm,           X86.opMOVAXm,           X86.opMOVmAL,           X86.opMOVmAX,       // 0xA0-0xA3
    X86.opMOVSb,            X86.opMOVSw,            X86.opCMPSb,            X86.opCMPSw,        // 0xA4-0xA7
    X86.opTESTALb,          X86.opTESTAX,           X86.opSTOSb,            X86.opSTOSw,        // 0xA8-0xAB
    X86.opLODSb,            X86.opLODSw,            X86.opSCASb,            X86.opSCASw,        // 0xAC-0xAF
    X86.opMOVALb,           X86.opMOVCLb,           X86.opMOVDLb,           X86.opMOVBLb,       // 0xB0-0xB3
    X86.opMOVAHb,           X86.opMOVCHb,           X86.opMOVDHb,           X86.opMOVBHb,       // 0xB4-0xB7
    X86.opMOVAX,            X86.opMOVCX,            X86.opMOVDX,            X86.opMOVBX,        // 0xB8-0xBB
    X86.opMOVSP,            X86.opMOVBP,            X86.opMOVSI,            X86.opMOVDI,        // 0xBC-0xBF
    /*
     * On an 8086/8088, opcodes 0xC0 -> 0xC2, 0xC1 -> 0xC3, 0xC8 -> 0xCA and 0xC9 -> 0xCB.
     */
    X86.opRETn,             X86.opRET,              X86.opRETn,             X86.opRET,          // 0xC0-0xC3
    X86.opLES,              X86.opLDS,              X86.opMOVb,             X86.opMOVw,         // 0xC4-0xC7
    X86.opRETFn,            X86.opRETF,             X86.opRETFn,            X86.opRETF,         // 0xC8-0xCB
    X86.opINT3,             X86.opINTn,             X86.opINTO,             X86.opIRET,         // 0xCC-0xCF
    X86.opGRP2b1,           X86.opGRP2w1,           X86.opGRP2bCL,          X86.opGRP2wCL,      // 0xD0-0xD3
    /*
     * Even as of the Pentium, opcode 0xD6 is still marked as "reserved", but it's always been SALC (aka SETALC).
     */
    X86.opAAM,              X86.opAAD,              X86.opSALC,             X86.opXLAT,         // 0xD4-0xD7
    X86.opESC0,             X86.opESC1,             X86.opESC2,             X86.opESC3,         // 0xD8-0xDB
    X86.opESC4,             X86.opESC5,             X86.opESC6,             X86.opESC7,         // 0xDC-0xDF
    X86.opLOOPNZ,           X86.opLOOPZ,            X86.opLOOP,             X86.opJCXZ,         // 0xE0-0xE3
    X86.opINb,              X86.opINw,              X86.opOUTb,             X86.opOUTw,         // 0xE4-0xE7
    X86.opCALL,             X86.opJMP,              X86.opJMPF,             X86.opJMPs,         // 0xE8-0xEB
    X86.opINDXb,            X86.opINDXw,            X86.opOUTDXb,           X86.opOUTDXw,       // 0xEC-0xEF
    /*
     * On an 8086/8088, opcode 0xF1 is believed to be an alias for 0xF0; in any case, it definitely behaves like
     * a prefix on those processors, so we treat it as such.  On the 80186 and 80286, we treat it as opUndefined(),
     * and on the 80386, it becomes opINT1().
     *
     * As of the Pentium, opcode 0xF1 is still marked "reserved".
     */
    X86.opLOCK,             X86.opLOCK,             X86.opREPNZ,            X86.opREPZ,         // 0xF0-0xF3
    X86.opHLT,              X86.opCMC,              X86.opGRP3b,            X86.opGRP3w,        // 0xF4-0xF7
    X86.opCLC,              X86.opSTC,              X86.opCLI,              X86.opSTI,          // 0xF8-0xFB
    X86.opCLD,              X86.opSTD,              X86.opGRP4b,            X86.opGRP4w         // 0xFC-0xFF
];

/*
 * A word (or two) on instruction groups (eg, Grp1, Grp2), which are groups of instructions that
 * use a mod/reg/rm byte, where the reg field of that byte selects a function rather than a register.
 *
 * I start with the groupings used by Intel's "Pentium Processor User's Manual (Volume 3: Architecture
 * and Programming Manual)", but I deviate slightly, mostly by subdividing their groups with letter suffixes:
 *
 *      Opcodes     Intel       PCx86                                               PC Mag TechRef
 *      -------     -----       ----                                                --------------
 *      0x80-0x83   Grp1        Grp1b and Grp1w                                     Group A
 *      0xC0-0xC1   Grp2        Grp2b and Grp2w (opGRP2bn/wn)                       Group B
 *      0xD0-0xD3   Grp2        Grp2b and Grp2w (opGRP2b1/w1 and opGRP2bCL/wCL)     Group B
 *      0xF6-0xF7   Grp3        Grp3b and Grp3w                                     Group C
 *      0xFE        Grp4        Grp4b                                               Group D
 *      0xFF        Grp5        Grp4w                                               Group E
 *      0x0F,0x00   Grp6        Grp6 (SLDT, STR, LLDT, LTR, VERR, VERW)             Group F
 *      0x0F,0x01   Grp7        Grp7 (SGDT, SIDT, LGDT, LIDT, SMSW, LMSW, INVLPG)   Group G
 *      0x0F,0xBA   Grp8        Grp8 (BT, BTS, BTR, BTC)                            Group H
 *      0x0F,0xC7   Grp9        Grp9 (CMPXCH)                                       (N/A, 80486 and up)
 *
 * My only serious deviation is Grp5, which I refer to as Grp4w, because it contains word forms of
 * the INC and DEC instructions found in Grp4b.  Granted, Grp4w also contains versions of the CALL,
 * JMP and PUSH instructions, which are not in Grp4b, but there's nothing in Grp4b that conflicts with
 * Grp4w, so I think my nomenclature makes more sense.  To compensate, I don't use Grp5, so that the
 * remaining group numbers remain in sync with Intel's.
 *
 * To the above list, I've added a few "single-serving" groups: opcode 0x8F uses GrpPOPw, and opcodes 0xC6/0xC7
 * use GrpMOVn.  In both of these groups, the only valid (documented) instruction is where reg=0x0.
 *
 * TODO: Test what happens on real hardware when the reg field is non-zero for opcodes 0x8F and 0xC6/0xC7.
 */
X86.aOpGrp1b = [
    X86.fnADDb,             X86.fnORb,              X86.fnADCb,             X86.fnSBBb,             // 0x80/0x82(reg=0x0-0x3)
    X86.fnANDb,             X86.fnSUBb,             X86.fnXORb,             X86.fnCMPb              // 0x80/0x82(reg=0x4-0x7)
];

X86.aOpGrp1w = [
    X86.fnADDw,             X86.fnORw,              X86.fnADCw,             X86.fnSBBw,             // 0x81/0x83(reg=0x0-0x3)
    X86.fnANDw,             X86.fnSUBw,             X86.fnXORw,             X86.fnCMPw              // 0x81/0x83(reg=0x4-0x7)
];

X86.aOpGrpPOPw = [
    X86.fnPOPw,             X86.fnGRPFault,         X86.fnGRPFault,         X86.fnGRPFault,         // 0x8F(reg=0x0-0x3)
    X86.fnGRPFault,         X86.fnGRPFault,         X86.fnGRPFault,         X86.fnGRPFault          // 0x8F(reg=0x4-0x7)
];

X86.aOpGrpMOVn = [
    X86.fnMOVn,             X86.fnGRPUndefined,     X86.fnGRPUndefined,     X86.fnGRPUndefined,     // 0xC6/0xC7(reg=0x0-0x3)
    X86.fnGRPUndefined,     X86.fnGRPUndefined,     X86.fnGRPUndefined,     X86.fnGRPUndefined      // 0xC6/0xC7(reg=0x4-0x7)
];

X86.aOpGrp2b = [
    X86.fnROLb,             X86.fnRORb,             X86.fnRCLb,             X86.fnRCRb,             // 0xC0/0xD0/0xD2(reg=0x0-0x3)
    X86.fnSHLb,             X86.fnSHRb,             X86.fnGRPUndefined,     X86.fnSARb              // 0xC0/0xD0/0xD2(reg=0x4-0x7)
];

X86.aOpGrp2w = [
    X86.fnROLw,             X86.fnRORw,             X86.fnRCLw,             X86.fnRCRw,             // 0xC1/0xD1/0xD3(reg=0x0-0x3)
    X86.fnSHLw,             X86.fnSHRw,             X86.fnGRPUndefined,     X86.fnSARw              // 0xC1/0xD1/0xD3(reg=0x4-0x7)
];

X86.aOpGrp2d = [
    X86.fnROLd,             X86.fnRORd,             X86.fnRCLd,             X86.fnRCRd,             // 0xC1/0xD1/0xD3(reg=0x0-0x3)
    X86.fnSHLd,             X86.fnSHRd,             X86.fnGRPUndefined,     X86.fnSARd              // 0xC1/0xD1/0xD3(reg=0x4-0x7)
];

X86.aOpGrp3b = [
    X86.fnTESTib,           X86.fnGRPUndefined,     X86.fnNOTb,             X86.fnNEGb,             // 0xF6(reg=0x0-0x3)
    X86.fnMULb,             X86.fnIMULb,            X86.fnDIVb,             X86.fnIDIVb             // 0xF6(reg=0x4-0x7)
];

X86.aOpGrp3w = [
    X86.fnTESTiw,           X86.fnGRPUndefined,     X86.fnNOTw,             X86.fnNEGw,             // 0xF7(reg=0x0-0x3)
    X86.fnMULw,             X86.fnIMULw,            X86.fnDIVw,             X86.fnIDIVw             // 0xF7(reg=0x4-0x7)
];

X86.aOpGrp4b = [
    X86.fnINCb,             X86.fnDECb,             X86.fnGRPUndefined,     X86.fnGRPUndefined,     // 0xFE(reg=0x0-0x3)
    X86.fnGRPUndefined,     X86.fnGRPUndefined,     X86.fnGRPUndefined,     X86.fnGRPUndefined      // 0xFE(reg=0x4-0x7)
];

X86.aOpGrp4w = [
    X86.fnINCw,             X86.fnDECw,             X86.fnCALLw,            X86.fnCALLFdw,          // 0xFF(reg=0x0-0x3)
    X86.fnJMPw,             X86.fnJMPFdw,           X86.fnPUSHw,            X86.fnGRPUndefined      // 0xFF(reg=0x4-0x7)
];

/**
 * @copyright https://www.pcjs.org/machines/pcx86/lib/x86op0f.js (C) 2012-2021 Jeff Parsons
 */


/**
 * op=0x0F,0x00 (GRP6 mem/reg)
 *
 * @this {CPUx86}
 */
X86.opGRP6 = function()
{
    let bModRM = this.peekIPByte();
    if ((bModRM & 0x38) < 0x10) {   // possible reg values: 0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38
        this.opFlags |= X86.OPFLAG.NOREAD;
    }
    this.decodeModGrpWord.call(this, this.aOpGrp6, X86.helpSRCNone);
};

/**
 * op=0x0F,0x01 (GRP7 mem/reg)
 *
 * @this {CPUx86}
 */
X86.opGRP7 = function()
{
    let bModRM = this.peekIPByte();
    if (!(bModRM & 0x10)) {
        this.opFlags |= X86.OPFLAG.NOREAD;
    }
    this.decodeModGrpWord.call(this, X86.aOpGrp7, X86.helpSRCNone);
};

/**
 * opLAR()
 *
 * op=0x0F,0x02 (LAR reg,mem/reg)
 *
 * @this {CPUx86}
 */
X86.opLAR = function()
{
    /*
     * TODO: Consider swapping out this function whenever setProtMode() changes the mode to real-mode or V86-mode.
     */
    if (!(this.regCR0 & X86.CR0.MSW.PE) || I386 && (this.regPS & X86.PS.VM)) {
        X86.opInvalid.call(this);
        return;
    }
    this.decodeModRegWord.call(this, X86.fnLAR);
};

/**
 * opLSL()
 *
 * op=0x0F,0x03 (LSL reg,mem/reg)
 *
 * @this {CPUx86}
 */
X86.opLSL = function()
{
    /*
     * TODO: Consider swapping out this function whenever setProtMode() changes the mode to real-mode or V86-mode.
     */
    if (!(this.regCR0 & X86.CR0.MSW.PE) || I386 && (this.regPS & X86.PS.VM)) {
        X86.opInvalid.call(this);
        return;
    }
    this.decodeModRegWord.call(this, X86.fnLSL);
};

/**
 * opLOADALL286()
 *
 * op=0x0F,0x05 (LOADALL)
 *
 * From the "Undocumented iAPX 286 Test Instruction" document at http://www.pcjs.org/pubs/pc/reference/intel/80286/loadall/:
 *
 *  Physical Address (Hex)        Associated CPU Register
 *          800-805                        None
 *          806-807                        MSW
 *          808-815                        None
 *          816-817                        TR
 *          818-819                        Flag word
 *          81A-81B                        IP
 *          81C-81D                        LDT
 *          81E-81F                        DS
 *          820-821                        SS
 *          822-823                        CS
 *          824-825                        ES
 *          826-827                        DI
 *          828-829                        SI
 *          82A-82B                        BP
 *          82C-82D                        SP
 *          82E-82F                        BX
 *          830-831                        DX
 *          832-833                        CX
 *          834-835                        AX
 *          836-83B                        ES descriptor cache
 *          83C-841                        CS descriptor cache
 *          842-847                        SS descriptor cache
 *          848-84D                        DS descriptor cache
 *          84E-853                        GDTR
 *          854-859                        LDT descriptor cache
 *          85A-85F                        IDTR
 *          860-865                        TSS descriptor cache
 *
 * @this {CPUx86}
 */
X86.opLOADALL286 = function()
{
    if (this.nCPL) {
        /*
         * To use LOADALL, CPL must be zero.
         */
        X86.helpFault.call(this, X86.EXCEPTION.GP_FAULT, 0, 0, true);
        return;
    }
    this.setMSW(this.getShort(0x806));
    this.regEDI = this.getShort(0x826);
    this.regESI = this.getShort(0x828);
    this.regEBP = this.getShort(0x82A);
    this.regEBX = this.getShort(0x82E);
    this.regEDX = this.getShort(0x830);
    this.regECX = this.getShort(0x832);
    this.regEAX = this.getShort(0x834);
    this.segES.loadDesc6(0x836, this.getShort(0x824));
    this.segCS.loadDesc6(0x83C, this.getShort(0x822));
    this.segSS.loadDesc6(0x842, this.getShort(0x820));
    this.segDS.loadDesc6(0x848, this.getShort(0x81E));
    /*
     * Unlike LOADALL386, there's no requirement for calling setPS() before loading segment registers;
     * in fact, since we're not passing a CPL to setPS(), it may be preferable to have CS (and perhaps SS)
     * already loaded, so that setPS() can query the CPL.  TODO: Verify that CPL is set correctly.
     */
    this.setPS(this.getShort(0x818));
    /*
     * It's important to call setIP() and setSP() *after* the segCS and segSS loads, so that the CPU's
     * linear IP and SP registers (regLIP and regLSP) will be updated properly.  Ordinarily that would be
     * taken care of by simply using the CPU's setCS() and setSS() functions, but those functions call the
     * default descriptor load() functions, and obviously here we must use loadDesc6() instead.
     */
    this.setIP(this.getShort(0x81A));
    this.setSP(this.getShort(0x82C));
    /*
     * The bytes at 0x851 and 0x85D "should be zeroes", as per the "Undocumented iAPX 286 Test Instruction"
     * document, but the LOADALL issued by RAMDRIVE in PC-DOS 7.0 contains 0xFF in both of those bytes, resulting
     * in very large addrGDT and addrIDT values.  Obviously, we can't have that, so we load only the low byte
     * of the second word for both of those registers.
     */
    this.addrGDT = this.getShort(0x84E) | (this.getByte(0x850) << 16);
    this.addrGDTLimit = this.addrGDT + this.getShort(0x852);
    this.addrIDT = this.getShort(0x85A) | (this.getByte(0x85C) << 16);
    this.addrIDTLimit = this.addrIDT + this.getShort(0x85E);
    this.segLDT.loadDesc6(0x854, this.getShort(0x81C));
    this.segTSS.loadDesc6(0x860, this.getShort(0x816));

    /*
     * Oddly, the above Intel document gives two contradictory cycle counts for LOADALL: 190 and 195.
     * I'm going with 195, since both the PC Magazine Programmer's Technical Reference and Robert Collins
     * (http://www.rcollins.org/articles/loadall/tspec_a3_doc.html) agree.
     */
    this.nStepCycles -= 195;

    /*
     * TODO: LOADALL operation still needs to be verified in protected mode....
     */
    if (DEBUG && DEBUGGER && (this.regCR0 & X86.CR0.MSW.PE)) this.stopCPU();
};

/**
 * opCLTS()
 *
 * op=0x0F,0x06 (CLTS)
 *
 * @this {CPUx86}
 */
X86.opCLTS = function()
{
    /*
     * NOTE: The following code shouldn't need to also test X86.PS.VM, because V86-mode is CPL 3.
     */
    if (this.nCPL) {
        X86.helpFault.call(this, X86.EXCEPTION.GP_FAULT, 0);
        return;
    }
    this.regCR0 &= ~X86.CR0.MSW.TS;
    this.nStepCycles -= 2;
};

/**
 * opLOADALL386()
 *
 * op=0x0F,0x07 (LOADALL ES:[EDI])
 *
 * Excerpt from Intel Internal Correspondence on "386 LOADALL Instruction" (undated), available as part of the
 * PCjs Project at http://www.pcjs.org/pubs/pc/reference/intel/80386/loadall/
 *
 *      1.5. 386 LOADALL Memory Format
 *
 *      The following tables define the LOADALL memory format. The LOADALL instruction uses a 512-byte block of
 *      memory, where the lowest addressed byte is given in ES:[(E)DI]. The area above offset CC hex is used for
 *      processor dependent registers (temporaries, invisible registers). These are loaded into the processor,
 *      but will not affect normal program execution. All values in the memory area are read from a four byte field,
 *      to keep the memory format DWORD aligned, but it is possible to locate memory area at a non-aligned address.
 *      In this case, the execution time of LOADALL will DOUBLE For this reason, the memory dump area should always
 *      be DWORD aligned.
 *
 *         Offset         Register
 *         ------         --------
 *          0x00            CR0
 *          0x04            EFLAGS
 *          0x08            EIP
 *          0x0C            EDI
 *          0x10            ESI
 *          0x14            EBP
 *          0x18            ESP
 *          0x1C            EBX
 *          0x20            EDX
 *          0x24            ECX
 *          0x28            EAX
 *          0x2C            DR6
 *          0x30            DR7
 *          0x34            TSSR(TSSSelector-Word)
 *          0x38            LDTR(LDTSelector-Word)
 *          0x3C            GS
 *          0x40            FS
 *          0x44            DS
 *          0x48            SS
 *          0x4C            CS
 *          0x50            ES
 *          0x54            TSS(AR)
 *          0x58            TSS(BASE)
 *          0x5C            TSS(LIMIT)
 *          0x60            IDT(AR)
 *          0x64            IDT(BASE)
 *          0x68            IDT(LIMIT)
 *          0x6C            GDT(AR)
 *          0x70            GDT(BASE)
 *          0x74            GDT(LIMIT)
 *          0x78            LDT(AR)
 *          0x7C            LDT(BASE)
 *          0x80            LDT(LIMIT)
 *          0x84            GS(AR)
 *          0x88            GS(BASE)
 *          0x8C            GS(LIMIT)
 *          0x90            FS(AR)
 *          0x94            FS(BASE)
 *          0x98            FS(LIMIT)
 *          0x9C            DS(AR)
 *          0xA0            DS(BASE)
 *          0xA4            DS(LIMIT)
 *          0xA8            SS(AR)
 *          0xAC            SS(BASE)
 *          0xB0            SS(LIMIT)
 *          0xB4            CS(AR)
 *          0xB8            CS(BASE)
 *          0xBC            CS(LIMIT)
 *          0xC0            ES(AR)
 *          0xC4            ES(BASE)
 *          0xC8            ES(LIMIT)
 *
 *      Each descriptor entry consists of 3 pieces:
 *
 *          AR
 *          BASE
 *          LIMIT
 *
 *      The AR part has the same format as the second dword of a segment descriptor except that only the AR byte
 *      (bits 8-15) and the G and B/D bits (bits 23 and 22) are used. All other bits in the AR field are ignored.
 *      The BASE and LIMIT parts contain full 32-bit values, fully expanded and unscrambled from the 386 descriptor.
 *      In particular, the LIMIT field loaded for a page granular segment gives a byte granular limit, so should
 *      contain the page limit*4096 plus 4095.
 *
 * @this {CPUx86}
 */
X86.opLOADALL386 = function()
{
    if (this.nCPL) {
        /*
         * To use LOADALL, CPL must be zero.
         */
        X86.helpFault.call(this, X86.EXCEPTION.GP_FAULT, 0, 0, true);
        return;
    }
    let addr = this.segES.checkRead(this.regEDI & this.maskAddr, 0xCC);
    if (addr !== X86.ADDR_INVALID) {
        X86.helpLoadCR0.call(this, this.getLong(addr));
        /*
         * We need to call setPS() before loading any segment registers, because if the Virtual 8086 Mode (VM)
         * bit is set in EFLAGS, the segment registers need to know that.
         */
        let accSS = this.getLong(addr + 0xA8);
        let cpl = (accSS & X86.DESC.ACC.DPL.MASK) >> X86.DESC.ACC.DPL.SHIFT;
        this.setPS(this.getLong(addr + 0x04), cpl);
        /*
         * TODO: We have no use for the GDT(AR) at offset 0x6C or the IDT(AR) at offset 0x60, because
         * we don't manage them as segment registers.  Should we?
         */
        this.addrGDT = this.getLong(addr + 0x70);
        this.addrGDTLimit = this.addrGDT + this.getLong(addr + 0x74);
        this.addrIDT = this.getLong(addr + 0x64);
        this.addrIDTLimit = this.addrIDT + this.getLong(addr + 0x68);
        this.segLDT.loadDesc(this.getLong(addr + 0x38), this.getLong(addr + 0x78), this.getLong(addr + 0x7C), this.getLong(addr + 0x80));
        this.segTSS.loadDesc(this.getLong(addr + 0x34), this.getLong(addr + 0x54), this.getLong(addr + 0x58), this.getLong(addr + 0x5C));
        this.regEDI = this.getLong(addr + 0x0C);
        this.regESI = this.getLong(addr + 0x10);
        this.regEBP = this.getLong(addr + 0x14);
        this.regEBX = this.getLong(addr + 0x1C);
        this.regEDX = this.getLong(addr + 0x20);
        this.regECX = this.getLong(addr + 0x24);
        this.regEAX = this.getLong(addr + 0x28);
        this.segGS.loadDesc(this.getLong(addr + 0x3C), this.getLong(addr + 0x84), this.getLong(addr + 0x88), this.getLong(addr + 0x8C));
        this.segFS.loadDesc(this.getLong(addr + 0x40), this.getLong(addr + 0x90), this.getLong(addr + 0x94), this.getLong(addr + 0x98));
        this.segDS.loadDesc(this.getLong(addr + 0x44), this.getLong(addr + 0x9C), this.getLong(addr + 0xA0), this.getLong(addr + 0xA4));
        this.segSS.loadDesc(this.getLong(addr + 0x48), accSS,                     this.getLong(addr + 0xAC), this.getLong(addr + 0xB0));
        this.segCS.loadDesc(this.getLong(addr + 0x4C), this.getLong(addr + 0xB4), this.getLong(addr + 0xB8), this.getLong(addr + 0xBC));
        this.segES.loadDesc(this.getLong(addr + 0x50), this.getLong(addr + 0xC0), this.getLong(addr + 0xC4), this.getLong(addr + 0xC8));
        /*
         * It's important to call setIP() and setSP() *after* the segCS and segSS loads, so that the CPU's
         * linear IP and SP registers (regLIP and regLSP) will be updated properly.  Ordinarily that would be
         * taken care of by simply using the CPU's setCS() and setSS() functions, but those functions call the
         * default descriptor load() functions, and obviously here we must use loadDesc() instead.
         */
        this.setIP(this.getLong(addr + 0x08));
        this.setSP(this.getLong(addr + 0x18));
        /*
         * TODO: We need to factor out the code that updates DR6 and DR7 from X86.opMOVdr(), so that we can
         * more easily update DR6 and DR7 (which we're simply ignoring for now).
         */
    }

    /*
     * According to Robert Collins (http://www.rcollins.org/articles/loadall/tspec_a3_doc.html), the 80386 LOADALL
     * takes 122 cycles.  Also, according the above-mentioned Intel document, if the memory buffer is not DWORD aligned,
     * execution time will DOUBLE.
     */
    this.nStepCycles -= (122 << ((addr & 0x3)? 1 : 0));
};

/**
 * opMOVrc()
 *
 * op=0x0F,0x20 (MOV reg,ctlreg)
 *
 * NOTE: Since this instruction uses only 32-bit general-purpose registers, our ModRM decoders
 * are going to be more hindrance than help, so we fully decode and execute the instruction ourselves.
 *
 * From PCMag_Prog_TechRef, p.476: "The 80386 executes the MOV to/from control registers (CRn) regardless
 * of the setting of the MOD field.  The MOD field should be set to 11, but an early 80386 documentation
 * error indicated that the MOD field value was a don't care.  Early versions of the 80486 detect
 * a MOD != 11 as an illegal opcode.  This was changed in later versions to ignore the value of MOD.
 * Assemblers that generate MOD != 11 for these instructions will fail on some 80486s."
 *
 * And in fact, the COMPAQ DeskPro 386 ROM BIOS executes this instruction with MOD set to 00, so we have
 * to ignore it.
 *
 * @this {CPUx86}
 */
X86.opMOVrc = function()
{
    /*
     * NOTE: The following code shouldn't need to also test X86.PS.VM, because V86-mode is CPL 3.
     */
    if (this.nCPL) {
        /*
         * You're not allowed to read control registers if the current privilege level is not zero.
         */
        X86.helpFault.call(this, X86.EXCEPTION.GP_FAULT, 0);
        return;
    }

    let reg;
    let bModRM = this.getIPByte();
    switch((bModRM & 0x38) >> 3) {
    case 0x0:
        reg = this.regCR0;
        break;
    case 0x2:
        reg = this.regCR2;
        break;
    case 0x3:
        reg = this.regCR3;
        break;
    default:
        X86.opUndefined.call(this);
        return;
    }

    this.setReg(bModRM & 0x7, reg);

    this.nStepCycles -= 6;

    /*
     * TODO: Implement BACKTRACK for this instruction (although Control registers are not likely to be a conduit for interesting data).
     */
};

/**
 * opMOVrd()
 *
 * op=0x0F,0x21 (MOV reg,dbgreg)
 *
 * NOTE: Since this instruction uses only 32-bit general-purpose registers, our ModRM decoders
 * are going to be more hindrance than help, so we fully decode and execute the instruction ourselves.
 *
 * @this {CPUx86}
 */
X86.opMOVrd = function()
{
    /*
     * NOTE: The following code shouldn't need to also test X86.PS.VM, because V86-mode is CPL 3.
     */
    if (this.nCPL) {
        /*
         * You're not allowed to read control registers if the current privilege level is not zero.
         */
        X86.helpFault.call(this, X86.EXCEPTION.GP_FAULT, 0);
        return;
    }

    let bModRM = this.getIPByte();
    let iSrc = (bModRM & 0x38) >> 3;

    if (iSrc == 4 || iSrc == 5) {
        X86.opUndefined.call(this);
        return;
    }

    this.setReg(bModRM & 0x7, this.regDR[iSrc]);

    this.nStepCycles -= 22;

    /*
     * TODO: Implement BACKTRACK for this instruction (although Debug registers are not likely to be a conduit for interesting data).
     */
};

/**
 * opMOVcr()
 *
 * op=0x0F,0x22 (MOV ctlreg,reg)
 *
 * NOTE: Since this instruction uses only 32-bit general-purpose registers, our ModRM decoders
 * are going to be more hindrance than help, so we fully decode and execute the instruction ourselves.
 *
 * From PCMag_Prog_TechRef, p.476: "The 80386 executes the MOV to/from control registers (CRn) regardless
 * of the setting of the MOD field.  The MOD field should be set to 11, but an early 80386 documentation
 * error indicated that the MOD field value was a don't care.  Early versions of the 80486 detect
 * a MOD != 11 as an illegal opcode.  This was changed in later versions to ignore the value of MOD.
 * Assemblers that generate MOD != 11 for these instructions will fail on some 80486s."
 *
 * And in fact, the COMPAQ DeskPro 386 ROM BIOS executes this instruction with MOD set to 00, so we have
 * to ignore it.
 *
 * @this {CPUx86}
 */
X86.opMOVcr = function()
{
    /*
     * NOTE: The following code shouldn't need to also test X86.PS.VM, because V86-mode is CPL 3.
     */
    if (this.nCPL) {
        /*
         * You're not allowed to write control registers if the current privilege level is not zero.
         */
        X86.helpFault.call(this, X86.EXCEPTION.GP_FAULT, 0);
        return;
    }

    let bModRM = this.getIPByte();
    let reg = this.getReg(bModRM & 0x7);

    switch((bModRM & 0x38) >> 3) {
    case 0x0:
        X86.helpLoadCR0.call(this, reg);
        this.nStepCycles -= 10;
        break;
    case 0x2:
        this.regCR2 = reg;
        this.nStepCycles -= 4;
        break;
    case 0x3:
        X86.helpLoadCR3.call(this, reg);
        this.nStepCycles -= 5;
        break;
    default:
        X86.opUndefined.call(this);
        return;
    }

    /*
     * TODO: Implement BACKTRACK for this instruction (although Control registers are not likely to be a conduit for interesting data).
     */
};

/**
 * opMOVdr()
 *
 * op=0x0F,0x23 (MOV dbgreg,reg)
 *
 * NOTE: Since this instruction uses only 32-bit general-purpose registers, our ModRM decoders
 * are going to be more hindrance than help, so we fully decode and execute the instruction ourselves.
 *
 * @this {CPUx86}
 */
X86.opMOVdr = function()
{
    /*
     * NOTE: The following code shouldn't need to also test X86.PS.VM, because V86-mode is CPL 3.
     */
    if (this.nCPL) {
        /*
         * You're not allowed to write control registers if the current privilege level is not zero.
         */
        X86.helpFault.call(this, X86.EXCEPTION.GP_FAULT, 0);
        return;
    }

    let bModRM = this.getIPByte();
    let iDst = (bModRM & 0x38) >> 3;

    if (iDst == 4 || iDst == 5) {
        X86.opUndefined.call(this);
        return;
    }

    let regDR = this.getReg(bModRM & 0x7);

    if (regDR != this.regDR[iDst]) {
        this.checkDebugRegisters(false);
        this.regDR[iDst] = regDR;
        this.checkDebugRegisters(true);
    }

    this.nStepCycles -= (iDst < 4? 22 : 14);

    /*
     * TODO: Implement BACKTRACK for this instruction (although Debug registers are not likely to be a conduit for interesting data).
     */
};

/**
 * opMOVrt()
 *
 * op=0x0F,0x24 (MOV reg,tstreg)
 *
 * NOTE: Since this instruction uses only 32-bit general-purpose registers, our ModRM decoders
 * are going to be more hindrance than help, so we fully decode and execute the instruction ourselves.
 *
 * @this {CPUx86}
 */
X86.opMOVrt = function()
{
    /*
     * NOTE: The following code shouldn't need to also test X86.PS.VM, because V86-mode is CPL 3.
     */
    if (this.nCPL) {
        /*
         * You're not allowed to read control registers if the current privilege level is not zero.
         */
        X86.helpFault.call(this, X86.EXCEPTION.GP_FAULT, 0);
        return;
    }

    let bModRM = this.getIPByte();
    let iSrc = (bModRM & 0x38) >> 3;

    /*
     * Only TR6 and TR7 are defined, and only for the 80386 and 80486.  From the PC Magazine Prog. TechRef, p.64:
     *
     *  "The 80386 provides two 32-bit test registers, TR6 and TR7, as a mechanism for programmers to verify proper
     *   operation of the Translation Lookaside Buffer (TLB) when power is applied to the chip. The TLB is a cache used
     *   internally by the 80386 to translate linear addresses to physical addresses."
     */
    if (iSrc < 6) {
        X86.opUndefined.call(this);
        return;
    }

    this.setReg(bModRM & 0x7, this.regTR[iSrc]);
    this.nStepCycles -= 12;

    /*
     * TODO: Implement BACKTRACK for this instruction (although Test registers are not likely to be a conduit for interesting data).
     */
};

/**
 * opMOVtr()
 *
 * op=0x0F,0x26 (MOV tstreg,reg)
 *
 * NOTE: Since this instruction uses only 32-bit general-purpose registers, our ModRM decoders
 * are going to be more hindrance than help, so we fully decode and execute the instruction ourselves.
 *
 * @this {CPUx86}
 */
X86.opMOVtr = function()
{
    /*
     * NOTE: The following code shouldn't need to also test X86.PS.VM, because V86-mode is CPL 3.
     */
    if (this.nCPL) {
        /*
         * You're not allowed to write control registers if the current privilege level is not zero.
         */
        X86.helpFault.call(this, X86.EXCEPTION.GP_FAULT, 0);
        return;
    }

    let bModRM = this.getIPByte();
    let iDst = (bModRM & 0x38) >> 3;

    /*
     * Only TR6 and TR7 are defined, and only for the 80386 and 80486.  From the PC Magazine Prog. TechRef, p.64:
     *
     *  "The 80386 provides two 32-bit test registers, TR6 and TR7, as a mechanism for programmers to verify proper
     *   operation of the Translation Lookaside Buffer (TLB) when power is applied to the chip. The TLB is a cache used
     *   internally by the 80386 to translate linear addresses to physical addresses."
     */
    if (iDst < 6) {
        X86.opUndefined.call(this);
        return;
    }

    /*
     * TODO: Do something useful with the Test registers.
     */
    this.regTR[iDst] = this.getReg(bModRM & 0x7);

    this.nStepCycles -= 12;

    /*
     * TODO: Implement BACKTRACK for this instruction (although Test registers are not likely to be a conduit for interesting data).
     */
};

/*
 * NOTE: The following 16 new conditional jumps actually rely on the OPERAND override setting
 * for determining whether a signed 16-bit or 32-bit displacement will be fetched, even though
 * the ADDRESS override might seem more intuitive.  Think of them as instructions that are loading
 * a new operand into IP/EIP.
 *
 * Also, in 16-bit code, even though a signed rel16 value would seem to imply a range of -32768
 * to +32767, any location within a 64Kb code segment outside that range can be reached by choosing
 * a displacement in the opposite direction, causing the 16-bit value in EIP to underflow or overflow;
 * any underflow or overflow doesn't matter, because only the low 16 bits of EIP are updated when a
 * 16-bit OPERAND size is in effect.
 *
 * In fact, for 16-bit jumps, it's simpler to always think of rel16 as an UNSIGNED value added to
 * the current EIP, where the result is then truncated to a 16-bit value.  This is why we don't have
 * to sign-extend rel16 before adding it to the current EIP.
 */

/**
 * opJOw()
 *
 * op=0x0F,0x80 (JO rel16/rel32)
 *
 * @this {CPUx86}
 */
X86.opJOw = function()
{
    let disp = this.getIPWord();
    if (this.getOF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * opJNOw()
 *
 * op=0x0F,0x81 (JNO rel16/rel32)
 *
 * @this {CPUx86}
 */
X86.opJNOw = function()
{
    let disp = this.getIPWord();
    if (!this.getOF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * opJCw()
 *
 * op=0x0F,0x82 (JC rel16/rel32)
 *
 * @this {CPUx86}
 */
X86.opJCw = function()
{
    let disp = this.getIPWord();
    if (this.getCF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * opJNCw()
 *
 * op=0x0F,0x83 (JNC rel16/rel32)
 *
 * @this {CPUx86}
 */
X86.opJNCw = function()
{
    let disp = this.getIPWord();
    if (!this.getCF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * opJZw()
 *
 * op=0x0F,0x84 (JZ rel16/rel32)
 *
 * @this {CPUx86}
 */
X86.opJZw = function()
{
    let disp = this.getIPWord();
    if (this.getZF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * opJNZw()
 *
 * op=0x0F,0x85 (JNZ rel16/rel32)
 *
 * @this {CPUx86}
 */
X86.opJNZw = function()
{
    let disp = this.getIPWord();
    if (!this.getZF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * opJBEw()
 *
 * op=0x0F,0x86 (JBE rel16/rel32)
 *
 * @this {CPUx86}
 */
X86.opJBEw = function()
{
    let disp = this.getIPWord();
    if (this.getCF() || this.getZF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * opJNBEw()
 *
 * op=0x0F,0x87 (JNBE rel16/rel32)
 *
 * @this {CPUx86}
 */
X86.opJNBEw = function()
{
    let disp = this.getIPWord();
    if (!this.getCF() && !this.getZF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * opJSw()
 *
 * op=0x0F,0x88 (JS rel16/rel32)
 *
 * @this {CPUx86}
 */
X86.opJSw = function()
{
    let disp = this.getIPWord();
    if (this.getSF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * opJNSw()
 *
 * op=0x0F,0x89 (JNS rel16/rel32)
 *
 * @this {CPUx86}
 */
X86.opJNSw = function()
{
    let disp = this.getIPWord();
    if (!this.getSF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * opJPw()
 *
 * op=0x0F,0x8A (JP rel16/rel32)
 *
 * @this {CPUx86}
 */
X86.opJPw = function()
{
    let disp = this.getIPWord();
    if (this.getPF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * opJNPw()
 *
 * op=0x0F,0x8B (JNP rel16/rel32)
 *
 * @this {CPUx86}
 */
X86.opJNPw = function()
{
    let disp = this.getIPWord();
    if (!this.getPF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * opJLw()
 *
 * op=0x0F,0x8C (JL rel16/rel32)
 *
 * @this {CPUx86}
 */
X86.opJLw = function()
{
    let disp = this.getIPWord();
    if (!this.getSF() != !this.getOF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * opJNLw()
 *
 * op=0x0F,0x8D (JNL rel16/rel32)
 *
 * @this {CPUx86}
 */
X86.opJNLw = function()
{
    let disp = this.getIPWord();
    if (!this.getSF() == !this.getOF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * opJLEw()
 *
 * op=0x0F,0x8E (JLE rel16/rel32)
 *
 * @this {CPUx86}
 */
X86.opJLEw = function()
{
    let disp = this.getIPWord();
    if (this.getZF() || !this.getSF() != !this.getOF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * opJNLEw()
 *
 * op=0x0F,0x8F (JNLE rel16/rel32)
 *
 * @this {CPUx86}
 */
X86.opJNLEw = function()
{
    let disp = this.getIPWord();
    if (!this.getZF() && !this.getSF() == !this.getOF()) {
        this.setIP(this.getIP() + disp);
        this.nStepCycles -= this.cycleCounts.nOpCyclesJmpC;
        return;
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesJmpCFall;
};

/**
 * opSETO()
 *
 * op=0x0F,0x90 (SETO b)
 *
 * @this {CPUx86}
 */
X86.opSETO = function()
{
    X86.helpSETcc.call(this, X86.fnSETO);
};

/**
 * opSETNO()
 *
 * op=0x0F,0x91 (SETNO b)
 *
 * @this {CPUx86}
 */
X86.opSETNO = function()
{
    X86.helpSETcc.call(this, X86.fnSETO);
};

/**
 * opSETC()
 *
 * op=0x0F,0x92 (SETC b)
 *
 * @this {CPUx86}
 */
X86.opSETC = function()
{
    X86.helpSETcc.call(this, X86.fnSETC);
};

/**
 * opSETNC()
 *
 * op=0x0F,0x93 (SETNC b)
 *
 * @this {CPUx86}
 */
X86.opSETNC = function()
{
    X86.helpSETcc.call(this, X86.fnSETNC);
};

/**
 * opSETZ()
 *
 * op=0x0F,0x94 (SETZ b)
 *
 * @this {CPUx86}
 */
X86.opSETZ = function()
{
    X86.helpSETcc.call(this, X86.fnSETZ);
};

/**
 * opSETNZ()
 *
 * op=0x0F,0x95 (SETNZ b)
 *
 * @this {CPUx86}
 */
X86.opSETNZ = function()
{
    X86.helpSETcc.call(this, X86.fnSETNZ);
};

/**
 * opSETBE()
 *
 * op=0x0F,0x96 (SETBE b)
 *
 * @this {CPUx86}
 */
X86.opSETBE = function()
{
    X86.helpSETcc.call(this, X86.fnSETBE);
};

/**
 * opSETNBE()
 *
 * op=0x0F,0x97 (SETNBE b)
 *
 * @this {CPUx86}
 */
X86.opSETNBE = function()
{
    X86.helpSETcc.call(this, X86.fnSETNBE);
};

/**
 * opSETS()
 *
 * op=0x0F,0x98 (SETS b)
 *
 * @this {CPUx86}
 */
X86.opSETS = function()
{
    X86.helpSETcc.call(this, X86.fnSETS);
};

/**
 * opSETNS()
 *
 * op=0x0F,0x99 (SETNS b)
 *
 * @this {CPUx86}
 */
X86.opSETNS = function()
{
    X86.helpSETcc.call(this, X86.fnSETNS);
};

/**
 * opSETP()
 *
 * op=0x0F,0x9A (SETP b)
 *
 * @this {CPUx86}
 */
X86.opSETP = function()
{
    X86.helpSETcc.call(this, X86.fnSETP);
};

/**
 * opSETNP()
 *
 * op=0x0F,0x9B (SETNP b)
 *
 * @this {CPUx86}
 */
X86.opSETNP = function()
{
    X86.helpSETcc.call(this, X86.fnSETNP);
};

/**
 * opSETL()
 *
 * op=0x0F,0x9C (SETL b)
 *
 * @this {CPUx86}
 */
X86.opSETL = function()
{
    X86.helpSETcc.call(this, X86.fnSETL);
};

/**
 * opSETNL()
 *
 * op=0x0F,0x9D (SETNL b)
 *
 * @this {CPUx86}
 */
X86.opSETNL = function()
{
    X86.helpSETcc.call(this, X86.fnSETNL);
};

/**
 * opSETLE()
 *
 * op=0x0F,0x9E (SETLE b)
 *
 * @this {CPUx86}
 */
X86.opSETLE = function()
{
    X86.helpSETcc.call(this, X86.fnSETLE);
};

/**
 * opSETNLE()
 *
 * op=0x0F,0x9F (SETNLE b)
 *
 * @this {CPUx86}
 */
X86.opSETNLE = function()
{
    X86.helpSETcc.call(this, X86.fnSETNLE);
};

/**
 * opPUSHFS()
 *
 * op=0x0F,0xA0 (PUSH FS)
 *
 * @this {CPUx86}
 */
X86.opPUSHFS = function()
{
    /*
     * When the OPERAND size is 32 bits, the 80386 will decrement the stack pointer by 4, write the selector
     * into the 2 lower bytes, and leave the 2 upper bytes untouched; to properly emulate that, we must use the
     * more generic pushData() instead of pushWord().
     */
    if (!I386) {
        this.pushWord(this.segFS.sel);
    } else {
        this.pushData(this.segFS.sel, this.sizeData, 2);
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesPushSeg;
};

/**
 * opPOPFS()
 *
 * op=0x0F,0xA1 (POP FS)
 *
 * @this {CPUx86}
 */
X86.opPOPFS = function()
{
    /*
     * Any operation that modifies the stack before loading a new segment must snapshot regLSP first.
     */
    this.opLSP = this.regLSP;
    this.setFS(this.popWord());
    this.nStepCycles -= this.cycleCounts.nOpCyclesPopReg;
    this.opLSP = X86.ADDR_INVALID;
};

/**
 * opBT()
 *
 * op=0x0F,0xA3 (BT mem/reg,reg)
 *
 * @this {CPUx86}
 */
X86.opBT = function()
{
    this.decodeModMemWord.call(this, X86.fnBTMem);
    if (this.regEA !== X86.ADDR_INVALID) this.nStepCycles -= 6;
};

/**
 * opSHLDn()
 *
 * op=0x0F,0xA4 (SHLD mem/reg,reg,imm8)
 *
 * @this {CPUx86}
 */
X86.opSHLDn = function()
{
    this.decodeModMemWord.call(this, this.sizeData == 2? X86.fnSHLDwi : X86.fnSHLDdi);
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? 3 : 7);
};

/**
 * opSHLDcl()
 *
 * op=0x0F,0xA5 (SHLD mem/reg,reg,CL)
 *
 * @this {CPUx86}
 */
X86.opSHLDcl = function()
{
    this.decodeModMemWord.call(this, this.sizeData == 2? X86.fnSHLDwCL : X86.fnSHLDdCL);
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? 3 : 7);
};

/**
 * opXBTS()
 *
 * op=0x0F,0xA6 (XBTS reg,mem/reg,[E]AX,CL)
 *
 * @this {CPUx86}
 */
X86.opXBTS = function()
{
    this.decodeModRegWord.call(this, X86.fnXBTS);
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? 6 : 13);
};

/**
 * opIBTS()
 *
 * op=0x0F,0xA7 (IBTS mem/reg,[E]AX,CL,reg)
 *
 * @this {CPUx86}
 */
X86.opIBTS = function()
{
    this.decodeModMemWord.call(this, X86.fnIBTS);
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? 12 : 19);
};

/**
 * opPUSHGS()
 *
 * op=0x0F,0xA8 (PUSH GS)
 *
 * @this {CPUx86}
 */
X86.opPUSHGS = function()
{
    /*
     * When the OPERAND size is 32 bits, the 80386 will decrement the stack pointer by 4, write the selector
     * into the 2 lower bytes, and leave the 2 upper bytes untouched; to properly emulate that, we must use the
     * more generic pushData() instead of pushWord().
     */
    if (!I386) {
        this.pushWord(this.segGS.sel);
    } else {
        this.pushData(this.segGS.sel, this.sizeData, 2);
    }
    this.nStepCycles -= this.cycleCounts.nOpCyclesPushSeg;
};

/**
 * opPOPGS()
 *
 * op=0x0F,0xA9 (POP GS)
 *
 * @this {CPUx86}
 */
X86.opPOPGS = function()
{
    /*
     * Any operation that modifies the stack before loading a new segment must snapshot regLSP first.
     */
    this.opLSP = this.regLSP;
    this.setGS(this.popWord());
    this.nStepCycles -= this.cycleCounts.nOpCyclesPopReg;
    this.opLSP = X86.ADDR_INVALID;
};

/**
 * opBTS()
 *
 * op=0x0F,0xAB (BTC mem/reg,reg)
 *
 * @this {CPUx86}
 */
X86.opBTS = function()
{
    this.decodeModMemWord.call(this, X86.fnBTSMem);
    if (this.regEA !== X86.ADDR_INVALID) this.nStepCycles -= 5;
};

/**
 * opSHRDn()
 *
 * op=0x0F,0xAC (SHRD mem/reg,reg,imm8)
 *
 * @this {CPUx86}
 */
X86.opSHRDn = function()
{
    this.decodeModMemWord.call(this, this.sizeData == 2? X86.fnSHRDwi : X86.fnSHRDdi);
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? 3 : 7);
};

/**
 * opSHRDcl()
 *
 * op=0x0F,0xAD (SHRD mem/reg,reg,CL)
 *
 * @this {CPUx86}
 */
X86.opSHRDcl = function()
{
    this.decodeModMemWord.call(this, this.sizeData == 2? X86.fnSHRDwCL : X86.fnSHRDdCL);
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? 3 : 7);
};

/**
 * opIMUL()
 *
 * op=0x0F,0xAF (IMUL reg,mem/reg) (80386 and up)
 *
 * @this {CPUx86}
 */
X86.opIMUL = function()
{
    this.decodeModRegWord.call(this, this.sizeData == 2? X86.fnIMULrw : X86.fnIMULrd);
};

/**
 * opLSS()
 *
 * op=0x0F,0xB2 (LSS reg,word)
 *
 * This is like a "MOV reg,rm" operation, but it also loads SS from the next word.
 *
 * @this {CPUx86}
 */
X86.opLSS = function()
{
    this.decodeModRegWord.call(this, X86.fnLSS);
};

/**
 * opBTR()
 *
 * op=0x0F,0xB3 (BTC mem/reg,reg) (80386 and up)
 *
 * @this {CPUx86}
 */
X86.opBTR = function()
{
    this.decodeModMemWord.call(this, X86.fnBTRMem);
    if (this.regEA !== X86.ADDR_INVALID) this.nStepCycles -= 5;
};

/**
 * opLFS()
 *
 * op=0x0F,0xB4 (LFS reg,word)
 *
 * This is like a "MOV reg,rm" operation, but it also loads FS from the next word.
 *
 * @this {CPUx86}
 */
X86.opLFS = function()
{
    this.decodeModRegWord.call(this, X86.fnLFS);
};

/**
 * opLGS()
 *
 * op=0x0F,0xB5 (LGS reg,word)
 *
 * This is like a "MOV reg,rm" operation, but it also loads GS from the next word.
 *
 * @this {CPUx86}
 */
X86.opLGS = function()
{
    this.decodeModRegWord.call(this, X86.fnLGS);
};

/**
 * opMOVZXb()
 *
 * op=0x0F,0xB6 (MOVZX reg,byte)
 *
 * @this {CPUx86}
 */
X86.opMOVZXb = function()
{
    this.decodeModRegByte.call(this, X86.fnMOVXb);
    let reg = (this.bModRM >> 3) & 0x7;
    switch(reg) {
    case 0x0:
        this.regEAX = (this.regEAX & ~this.maskData) | (this.regEAX & 0xff);
        break;
    case 0x1:
        this.regECX = (this.regECX & ~this.maskData) | (this.regECX & 0xff);
        break;
    case 0x2:
        this.regEDX = (this.regEDX & ~this.maskData) | (this.regEDX & 0xff);
        break;
    case 0x3:
        this.regEBX = (this.regEBX & ~this.maskData) | (this.regEBX & 0xff);
        break;
    case 0x4:
        this.regESP = (this.regESP & ~this.maskData) | ((this.regEAX >> 8) & 0xff);
        this.regEAX = this.regXX;
        break;
    case 0x5:
        this.regEBP = (this.regEBP & ~this.maskData) | ((this.regECX >> 8) & 0xff);
        this.regECX = this.regXX;
        break;
    case 0x6:
        this.regESI = (this.regESI & ~this.maskData) | ((this.regEDX >> 8) & 0xff);
        this.regEDX = this.regXX;
        break;
    case 0x7:
        this.regEDI = (this.regEDI & ~this.maskData) | ((this.regEBX >> 8) & 0xff);
        this.regEBX = this.regXX;
        break;
    }
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? 3 : 6);
};

/**
 * opMOVZXw()
 *
 * op=0x0F,0xB7 (MOVZX reg,word)
 *
 * @this {CPUx86}
 */
X86.opMOVZXw = function()
{
    this.setDataSize(2);
    this.decodeModRegWord.call(this, X86.fnMOVXw);
    switch((this.bModRM >> 3) & 0x7) {
    case 0x0:
        this.regEAX = (this.regEAX & 0xffff);
        break;
    case 0x1:
        this.regECX = (this.regECX & 0xffff);
        break;
    case 0x2:
        this.regEDX = (this.regEDX & 0xffff);
        break;
    case 0x3:
        this.regEBX = (this.regEBX & 0xffff);
        break;
    case 0x4:
        this.regESP = (this.regESP & 0xffff);
        break;
    case 0x5:
        this.regEBP = (this.regEBP & 0xffff);
        break;
    case 0x6:
        this.regESI = (this.regESI & 0xffff);
        break;
    case 0x7:
        this.regEDI = (this.regEDI & 0xffff);
        break;
    }
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? 3 : 6);
};

/**
 * op=0x0F,0xBA (GRP8 mem/reg) (80386 and up)
 *
 * @this {CPUx86}
 */
X86.opGRP8 = function()
{
    this.decodeModGrpWord.call(this, X86.aOpGrp8, this.getIPByte);
};

/**
 * opBTC()
 *
 * op=0x0F,0xBB (BTC mem/reg,reg)
 *
 * @this {CPUx86}
 */
X86.opBTC = function()
{
    this.decodeModMemWord.call(this, X86.fnBTCMem);
    if (this.regEA !== X86.ADDR_INVALID) this.nStepCycles -= 5;
};

/**
 * opBSF()
 *
 * op=0x0F,0xBC (BSF reg,mem/reg)
 *
 * @this {CPUx86}
 */
X86.opBSF = function()
{
    this.decodeModRegWord.call(this, X86.fnBSF);
};

/**
 * opBSR()
 *
 * op=0x0F,0xBD (BSR reg,mem/reg)
 *
 * @this {CPUx86}
 */
X86.opBSR = function()
{
    this.decodeModRegWord.call(this, X86.fnBSR);
};

/**
 * opMOVSXb()
 *
 * op=0x0F,0xBE (MOVSX reg,byte)
 *
 * @this {CPUx86}
 */
X86.opMOVSXb = function()
{
    this.decodeModRegByte.call(this, X86.fnMOVXb);
    let reg = (this.bModRM >> 3) & 0x7;
    switch(reg) {
    case 0x0:
        this.regEAX = (this.regEAX & ~this.maskData) | ((((this.regEAX & 0xff) << 24) >> 24) & this.maskData);
        break;
    case 0x1:
        this.regECX = (this.regECX & ~this.maskData) | ((((this.regECX & 0xff) << 24) >> 24) & this.maskData);
        break;
    case 0x2:
        this.regEDX = (this.regEDX & ~this.maskData) | ((((this.regEDX & 0xff) << 24) >> 24) & this.maskData);
        break;
    case 0x3:
        this.regEBX = (this.regEBX & ~this.maskData) | ((((this.regEBX & 0xff) << 24) >> 24) & this.maskData);
        break;
    case 0x4:
        this.regESP = (this.regESP & ~this.maskData) | (((this.regEAX << 16) >> 24) & this.maskData);
        this.regEAX = this.regXX;
        break;
    case 0x5:
        this.regEBP = (this.regEBP & ~this.maskData) | (((this.regECX << 16) >> 24) & this.maskData);
        this.regECX = this.regXX;
        break;
    case 0x6:
        this.regESI = (this.regESI & ~this.maskData) | (((this.regEDX << 16) >> 24) & this.maskData);
        this.regEDX = this.regXX;
        break;
    case 0x7:
        this.regEDI = (this.regEDI & ~this.maskData) | (((this.regEBX << 16) >> 24) & this.maskData);
        this.regEBX = this.regXX;
        break;
    }
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? 3 : 6);
};

/**
 * opMOVSXw()
 *
 * op=0x0F,0xBF (MOVSX reg,word)
 *
 * @this {CPUx86}
 */
X86.opMOVSXw = function()
{
    this.setDataSize(2);
    this.decodeModRegWord.call(this, X86.fnMOVXw);
    switch((this.bModRM >> 3) & 0x7) {
    case 0x0:
        this.regEAX = ((this.regEAX << 16) >> 16);
        break;
    case 0x1:
        this.regECX = ((this.regECX << 16) >> 16);
        break;
    case 0x2:
        this.regEDX = ((this.regEDX << 16) >> 16);
        break;
    case 0x3:
        this.regEBX = ((this.regEBX << 16) >> 16);
        break;
    case 0x4:
        this.regESP = ((this.regESP << 16) >> 16);
        break;
    case 0x5:
        this.regEBP = ((this.regEBP << 16) >> 16);
        break;
    case 0x6:
        this.regESI = ((this.regESI << 16) >> 16);
        break;
    case 0x7:
        this.regEDI = ((this.regEDI << 16) >> 16);
        break;
    }
    this.nStepCycles -= (this.regEA === X86.ADDR_INVALID? 3 : 6);
};

X86.aOps0F = new Array(256);

X86.aOps0F[0x00] = X86.opGRP6;
X86.aOps0F[0x01] = X86.opGRP7;
X86.aOps0F[0x02] = X86.opLAR;
X86.aOps0F[0x03] = X86.opLSL;
X86.aOps0F[0x05] = X86.opLOADALL286;
X86.aOps0F[0x06] = X86.opCLTS;

/*
 * On all processors (except the 8086/8088, of course), X86.OPCODE.UD2 (0x0F,0x0B), aka "UD2", is an
 * instruction guaranteed to raise a #UD (Invalid Opcode) exception (INT 0x06) on all post-8086 processors.
 */
X86.aOps0F[0x0B] = X86.opInvalid;

/*
 * The following 0x0F opcodes are of no consequence to us, since they were all introduced post-80386;
 * 0x0F,0xA6 and 0x0F,0xA7 were introduced on some 80486 processors (and then deprecated), while 0x0F,0xB0
 * and 0x0F,0xB1 were introduced on 80586 (aka Pentium) processors.
 *
 *      CMPXCHG r/m8,reg8           ; 0F B0 /r          [PENT]
 *      CMPXCHG r/m16,reg16         ; o16 0F B1 /r      [PENT]
 *      CMPXCHG r/m32,reg32         ; o32 0F B1 /r      [PENT]
 *      CMPXCHG486 r/m8,reg8        ; 0F A6 /r          [486,UNDOC]
 *      CMPXCHG486 r/m16,reg16      ; o16 0F A7 /r      [486,UNDOC]
 *      CMPXCHG486 r/m32,reg32      ; o32 0F A7 /r      [486,UNDOC]
 *
 * So why are we even mentioning them here? Only because some software (eg, Windows 3.00) attempts to execute
 * 0x0F,0xA6, so we need to explicitly mark it as invalid.  TODO: Purely out of curiosity, I would like to
 * eventually learn *why* Windows 3.00 does this; is it hoping to use the CMPXCHG486 opcode, or is it performing
 * a CPU/stepping check to detect/work-around some errata, or....?
 */
X86.aOps0F[0xA6] = X86.opInvalid;

/*
 * When Windows 95 Setup initializes in protected-mode, it sets a DPMI exception handler for UD_FAULT and
 * then attempts to generate that exception with undefined opcode 0x0F,0xFF.  Apparently, whoever wrote that code
 * didn't get the Intel memo regarding the preferred invalid opcode (0x0F,0x0B, aka UD2), or perhaps Intel hadn't
 * written that memo yet -- although if that's the case, then Intel should have followed Microsoft's lead and
 * selected 0x0F,0xFF instead of 0x0F,0x0B.
 *
 * In any case, this means we need to explicitly set the handler for that opcode to opInvalid(), too.
 */
X86.aOps0F[0xFF] = X86.opInvalid;

/*
 * NOTE: Any other opcode slots NOT explicitly initialized above with either a dedicated function OR opInvalid()
 * will be set to opUndefined() when initProcessor() finalizes the opcode tables.  If the processor is an 80386,
 * initProcessor() will also incorporate all the handlers listed below in aOps0F386.
 *
 * A call to opUndefined() implies something serious has occurred that merits our attention (eg, perhaps someone
 * is using an undocumented opcode that we haven't implemented yet), whereas a call to opInvalid() may or may not.
 */

let I386 = 1;

if (I386) {
    X86.aOps0F386 = [];
    X86.aOps0F386[0x05] = X86.opInvalid;        // the 80286 LOADALL opcode (LOADALL286) is invalid on the 80386
    X86.aOps0F386[0x07] = X86.opLOADALL386;
    X86.aOps0F386[0x10] = X86.opMOVmb;          // see the undocumented [UMOV](/docs/x86/ops/UMOV/) instruction
    X86.aOps0F386[0x11] = X86.opMOVmw;          // see the undocumented [UMOV](/docs/x86/ops/UMOV/) instruction
    X86.aOps0F386[0x12] = X86.opMOVrb;          // see the undocumented [UMOV](/docs/x86/ops/UMOV/) instruction
    X86.aOps0F386[0x13] = X86.opMOVrw;          // see the undocumented [UMOV](/docs/x86/ops/UMOV/) instruction
    X86.aOps0F386[0x20] = X86.opMOVrc;
    X86.aOps0F386[0x21] = X86.opMOVrd;
    X86.aOps0F386[0x22] = X86.opMOVcr;
    X86.aOps0F386[0x23] = X86.opMOVdr;
    X86.aOps0F386[0x24] = X86.opMOVrt;
    X86.aOps0F386[0x26] = X86.opMOVtr;
    X86.aOps0F386[0x80] = X86.opJOw;
    X86.aOps0F386[0x81] = X86.opJNOw;
    X86.aOps0F386[0x82] = X86.opJCw;
    X86.aOps0F386[0x83] = X86.opJNCw;
    X86.aOps0F386[0x84] = X86.opJZw;
    X86.aOps0F386[0x85] = X86.opJNZw;
    X86.aOps0F386[0x86] = X86.opJBEw;
    X86.aOps0F386[0x87] = X86.opJNBEw;
    X86.aOps0F386[0x88] = X86.opJSw;
    X86.aOps0F386[0x89] = X86.opJNSw;
    X86.aOps0F386[0x8A] = X86.opJPw;
    X86.aOps0F386[0x8B] = X86.opJNPw;
    X86.aOps0F386[0x8C] = X86.opJLw;
    X86.aOps0F386[0x8D] = X86.opJNLw;
    X86.aOps0F386[0x8E] = X86.opJLEw;
    X86.aOps0F386[0x8F] = X86.opJNLEw;
    X86.aOps0F386[0x90] = X86.opSETO;
    X86.aOps0F386[0x91] = X86.opSETNO;
    X86.aOps0F386[0x92] = X86.opSETC;
    X86.aOps0F386[0x93] = X86.opSETNC;
    X86.aOps0F386[0x94] = X86.opSETZ;
    X86.aOps0F386[0x95] = X86.opSETNZ;
    X86.aOps0F386[0x96] = X86.opSETBE;
    X86.aOps0F386[0x97] = X86.opSETNBE;
    X86.aOps0F386[0x98] = X86.opSETS;
    X86.aOps0F386[0x99] = X86.opSETNS;
    X86.aOps0F386[0x9A] = X86.opSETP;
    X86.aOps0F386[0x9B] = X86.opSETNP;
    X86.aOps0F386[0x9C] = X86.opSETL;
    X86.aOps0F386[0x9D] = X86.opSETNL;
    X86.aOps0F386[0x9E] = X86.opSETLE;
    X86.aOps0F386[0x9F] = X86.opSETNLE;
    X86.aOps0F386[0xA0] = X86.opPUSHFS;
    X86.aOps0F386[0xA1] = X86.opPOPFS;
    X86.aOps0F386[0xA3] = X86.opBT;
    X86.aOps0F386[0xA4] = X86.opSHLDn;
    X86.aOps0F386[0xA5] = X86.opSHLDcl;
    X86.aOps0F386[0xA8] = X86.opPUSHGS;
    X86.aOps0F386[0xA9] = X86.opPOPGS;
    X86.aOps0F386[0xAB] = X86.opBTS;
    X86.aOps0F386[0xAC] = X86.opSHRDn;
    X86.aOps0F386[0xAD] = X86.opSHRDcl;
    X86.aOps0F386[0xAF] = X86.opIMUL;
    X86.aOps0F386[0xB2] = X86.opLSS;
    X86.aOps0F386[0xB3] = X86.opBTR;
    X86.aOps0F386[0xB4] = X86.opLFS;
    X86.aOps0F386[0xB5] = X86.opLGS;
    X86.aOps0F386[0xB6] = X86.opMOVZXb;
    X86.aOps0F386[0xB7] = X86.opMOVZXw;
    X86.aOps0F386[0xBA] = X86.opGRP8;
    X86.aOps0F386[0xBB] = X86.opBTC;
    X86.aOps0F386[0xBC] = X86.opBSF;
    X86.aOps0F386[0xBD] = X86.opBSR;
    X86.aOps0F386[0xBE] = X86.opMOVSXb;
    X86.aOps0F386[0xBF] = X86.opMOVSXw;
}

/*
 * These instruction groups are not as orthogonal as the original 8086/8088 groups (Grp1 through Grp4); some of
 * the instructions in Grp6 and Grp7 only read their dst operand (eg, LLDT), which means the ModRM helper function
 * must insure that setEAWord() is disabled, while others only write their dst operand (eg, SLDT), which means that
 * getEAWord() should be disabled *prior* to calling the ModRM helper function.  This latter case requires that
 * we decode the reg field of the ModRM byte before dispatching.
 */
X86.aOpGrp6Prot = [
    X86.fnSLDT,             X86.fnSTR,              X86.fnLLDT,             X86.fnLTR,              // 0x0F,0x00(reg=0x0-0x3)
    X86.fnVERR,             X86.fnVERW,             X86.fnGRPUndefined,     X86.fnGRPUndefined      // 0x0F,0x00(reg=0x4-0x7)
];

X86.aOpGrp6Real = [
    X86.fnGRPInvalid,       X86.fnGRPInvalid,       X86.fnGRPInvalid,       X86.fnGRPInvalid,       // 0x0F,0x00(reg=0x0-0x3)
    X86.fnGRPInvalid,       X86.fnGRPInvalid,       X86.fnGRPUndefined,     X86.fnGRPUndefined      // 0x0F,0x00(reg=0x4-0x7)
];

/*
 * Unlike Grp6, Grp7 and Grp8 do not require separate real-mode and protected-mode dispatch tables, because
 * all Grp7 and Grp8 instructions are valid in both modes.
 */
X86.aOpGrp7 = [
    X86.fnSGDT,             X86.fnSIDT,             X86.fnLGDT,             X86.fnLIDT,             // 0x0F,0x01(reg=0x0-0x3)
    X86.fnSMSW,             X86.fnGRPUndefined,     X86.fnLMSW,             X86.fnGRPUndefined      // 0x0F,0x01(reg=0x4-0x7)
];

X86.aOpGrp8 = [
    X86.fnGRPUndefined,     X86.fnGRPUndefined,     X86.fnGRPUndefined,     X86.fnGRPUndefined,     // 0x0F,0xBA(reg=0x0-0x3)
    X86.fnBT,               X86.fnBTS,              X86.fnBTR,              X86.fnBTC               // 0x0F,0xBA(reg=0x4-0x7)
];


const chipset = {
    sw1: 0xff,
    sound: 1,
    floppies: [360, 360],
    monitor: vga,//none|tv|color|mono|ega|vga
    init_date: '2000-01-01T00:00:00',
    kbd: 8041

}


//todo what is bios cmos etc time
class BiosTime{
    /*
     * @this {ChipSet}
     * @param {string} [sDate]
     */
    initRTCTime(sDate)
    {
        /*
         * NOTE: I've already been burned once by a JavaScript library function that did NOT treat an undefined
         * parameter (ie, a parameter === undefined) the same as an omitted parameter (eg, the async parameter in
         * xmlHTTP.open() in IE), so I'm taking no chances here: if sDate is undefined, then explicitly call Date()
         * with no parameters.
         */
        let date = sDate? new Date(sDate) : new Date();

        /*
         * Example of a valid Date string:
         *
         *      2014-10-01T08:00:00 (interpreted as GMT, resulting in "Wed Oct 01 2014 01:00:00 GMT-0700 (PDT)")
         *
         * Examples of INVALID Date strings:
         *
         *      2014-10-01T08:00:00PST
         *      2014-10-01T08:00:00-0700 (actually, this DOES work in Chrome, but NOT in Safari)
         *
         * In the case of INVALID Date strings, the Date object is invalid, but there's no obvious test for an "invalid"
         * object, so I've adapted the following test from StackOverflow.
         *
         * See http://stackoverflow.com/questions/1353684/detecting-an-invalid-date-date-instance-in-javascript
         */
        if (Object.prototype.toString.call(date) !== "[object Date]" || isNaN(date.getTime())) {
            date = new Date();
            this.println("CMOS date invalid (" + sDate + "), using " + date);
        } else if (sDate) {
            this.println("CMOS date: " + date);
        }

        this.abCMOSData[ChipSet.CMOS.ADDR.RTC_SEC] = date.getSeconds();
        this.abCMOSData[ChipSet.CMOS.ADDR.RTC_SEC_ALRM] = 0;
        this.abCMOSData[ChipSet.CMOS.ADDR.RTC_MIN] = date.getMinutes();
        this.abCMOSData[ChipSet.CMOS.ADDR.RTC_MIN_ALRM] = 0;
        this.abCMOSData[ChipSet.CMOS.ADDR.RTC_HOUR] = date.getHours();
        this.abCMOSData[ChipSet.CMOS.ADDR.RTC_HOUR_ALRM] = 0;
        this.abCMOSData[ChipSet.CMOS.ADDR.RTC_WEEK_DAY] = date.getDay() + 1;
        this.abCMOSData[ChipSet.CMOS.ADDR.RTC_MONTH_DAY] = date.getDate();
        this.abCMOSData[ChipSet.CMOS.ADDR.RTC_MONTH] = date.getMonth() + 1;
        let nYear = date.getFullYear();
        this.abCMOSData[ChipSet.CMOS.ADDR.RTC_YEAR] = nYear % 100;
        let nCentury = (nYear / 100);
        this.abCMOSData[ChipSet.CMOS.ADDR.CENTURY_DATE] = (nCentury % 10) | ((nCentury / 10) << 4);

        this.abCMOSData[ChipSet.CMOS.ADDR.STATUSA] = 0x26;                          // hard-coded default; refer to ChipSet.CMOS.STATUSA.DV and ChipSet.CMOS.STATUSA.RS
        this.abCMOSData[ChipSet.CMOS.ADDR.STATUSB] = ChipSet.CMOS.STATUSB.HOUR24;   // default to BCD mode (ChipSet.CMOS.STATUSB.BINARY not set)
        this.abCMOSData[ChipSet.CMOS.ADDR.STATUSC] = 0x00;
        this.abCMOSData[ChipSet.CMOS.ADDR.STATUSD] = ChipSet.CMOS.STATUSD.VRB;

        this.nRTCCyclesLastUpdate = this.nRTCCyclesNextUpdate = 0;
        this.nRTCPeriodsPerSecond = this.nRTCCyclesPerPeriod = null;
    }

    /**
     * getRTCByte(iRTC)
     *
     * @param {number} iRTC
     * @return {number} b
     */
    getRTCByte(iRTC)
    {


        let b = this.abCMOSData[iRTC];

        if (iRTC < ChipSet.CMOS.ADDR.STATUSA) {
            let f12HourValue = false;
            if (iRTC == ChipSet.CMOS.ADDR.RTC_HOUR || iRTC == ChipSet.CMOS.ADDR.RTC_HOUR_ALRM) {
                if (!(this.abCMOSData[ChipSet.CMOS.ADDR.STATUSB] & ChipSet.CMOS.STATUSB.HOUR24)) {
                    if (b < 12) {
                        b = (!b? 12 : b);
                    } else {
                        b -= 12;
                        b = (!b? 0x8c : b + 0x80);
                    }
                    f12HourValue = true;
                }
            }
            if (!(this.abCMOSData[ChipSet.CMOS.ADDR.STATUSB] & ChipSet.CMOS.STATUSB.BINARY)) {
                /*
                 * We're in BCD mode, so we must convert b from BINARY to BCD.  But first:
                 *
                 *      If b is a 12-hour value (ie, we're in 12-hour mode) AND the hour is a PM value
                 *      (ie, in the range 0x81-0x8C), then it must be adjusted to yield 81-92 in BCD.
                 *
                 *      AM hour values (0x01-0x0C) need no adjustment; they naturally convert to 01-12 in BCD.
                 */
                if (f12HourValue && b > 0x80) {
                    b -= (0x81 - 81);
                }
                b = (b % 10) | ((b / 10) << 4);
            }
        } else {
            if (iRTC == ChipSet.CMOS.ADDR.STATUSA) {
                /*
                 * Make sure that the "Update-In-Progress" bit we set in updateRTCTime() doesn't stay set for
                 * more than one read.
                 */
                this.abCMOSData[iRTC] &= ~ChipSet.CMOS.STATUSA.UIP;
            }
        }
        return b;
    }

    /**
     * setRTCByte(iRTC, b)
     *
     * @param {number} iRTC
     * @param {number} b proposed byte to write
     * @return {number} actual byte to write
     */
    setRTCByte(iRTC, b)
    {


        if (iRTC < ChipSet.CMOS.ADDR.STATUSA) {
            let fBCD = false;
            if (!(this.abCMOSData[ChipSet.CMOS.ADDR.STATUSB] & ChipSet.CMOS.STATUSB.BINARY)) {
                /*
                 * We're in BCD mode, so we must convert b from BCD to BINARY (we assume it's valid
                 * BCD; ie, that both nibbles contain only 0-9, not A-F).
                 */
                b = (b >> 4) * 10 + (b & 0xf);
                fBCD = true;
            }
            if (iRTC == ChipSet.CMOS.ADDR.RTC_HOUR || iRTC == ChipSet.CMOS.ADDR.RTC_HOUR_ALRM) {
                if (fBCD) {
                    /*
                     * If the original BCD hour was 0x81-0x92, then the previous BINARY-to-BCD conversion
                     * transformed it to 0x51-0x5C, so we must add 0x30.
                     */
                    if (b > 23) {

                        b += 0x30;
                    }
                }
                if (!(this.abCMOSData[ChipSet.CMOS.ADDR.STATUSB] & ChipSet.CMOS.STATUSB.HOUR24)) {
                    if (b <= 12) {
                        b = (b == 12? 0 : b);
                    } else {
                        b -= (0x80 - 12);
                        b = (b == 24? 12 : b);
                    }
                }
            }
        }
        return b;
    }

    /**
     * calcRTCCyclePeriod()
     *
     * This should be called whenever the timings in STATUSA may have changed.
     *
     * TODO: 1024 is a hard-coded number of periods per second based on the default interrupt rate of 976.562us
     * (ie, 1000000 / 976.562).  Calculate the actual number based on the values programmed in the STATUSA register.
     *
     * @this {ChipSet}
     */
    calcRTCCyclePeriod()
    {
        this.nRTCCyclesLastUpdate = this.cpu.getCycles(this.fScaleTimers);
        this.nRTCPeriodsPerSecond = 1024;
        this.nRTCCyclesPerPeriod = Math.floor(this.cpu.getBaseCyclesPerSecond() / this.nRTCPeriodsPerSecond);
        this.setRTCCycleLimit();
    }

    /**
     * getRTCCycleLimit(nCycles)
     *
     * This is called by the CPU to determine the maximum number of cycles it can process for the current burst.
     *
     * @this {ChipSet}
     * @param {number} nCycles desired
     * @return {number} maximum number of cycles (<= nCycles)
     */
    getRTCCycleLimit(nCycles)
    {
        if (this.abCMOSData && this.abCMOSData[ChipSet.CMOS.ADDR.STATUSB] & ChipSet.CMOS.STATUSB.PIE) {
            let nCyclesUpdate = this.nRTCCyclesNextUpdate - this.cpu.getCycles(this.fScaleTimers);
            if (nCyclesUpdate > 0) {
                if (nCycles > nCyclesUpdate) {
                    if (DEBUG) this.printf(Messages.RTC, "getRTCCycleLimit(%d): reduced to %d cycles\n", nCycles, nCyclesUpdate);
                    nCycles = nCyclesUpdate;
                } else {
                    if (DEBUG) this.printf(Messages.RTC, "getRTCCycleLimit(%d): already less than %d cycles\n", nCycles, nCyclesUpdate);
                }
            } else {
                if (DEBUG) this.printf(Messages.RTC, "RTC next update has passed by %d cycles\n", nCyclesUpdate);
            }
        }
        return nCycles;
    }

    /**
     * setRTCCycleLimit()
     *
     * This should be called when PIE becomes set in STATUSB (and whenever PF is cleared in STATUSC while PIE is still set).
     *
     * @this {ChipSet}
     */
    setRTCCycleLimit()
    {
        let nCycles = this.nRTCCyclesPerPeriod;
        this.nRTCCyclesNextUpdate = this.cpu.getCycles(this.fScaleTimers) + nCycles;
        if (this.abCMOSData[ChipSet.CMOS.ADDR.STATUSB] & ChipSet.CMOS.STATUSB.PIE) {
            this.cpu.setBurstCycles(nCycles);
        }
    }

    /**
     * updateRTCTime()
     *
     * @this {ChipSet}
     */
    updateRTCTime()
    {
        let nCyclesPerSecond = this.cpu.getBaseCyclesPerSecond();
        let nCyclesUpdate = this.cpu.getCycles(this.fScaleTimers);

        /*
         * We must arrange for the very first calcRTCCyclePeriod() call to occur here, on the very first
         * updateRTCTime() call, because this is the first point we can be guaranteed that CPU cycle counts
         * are initialized (the CPU is the last component to be powered up/restored).
         *
         * TODO: A side-effect of this is that it undermines the save/restore code's preservation of last
         * and next RTC cycle counts, which may affect when the next RTC event is delivered.
         */
        if (this.nRTCCyclesPerPeriod == null) this.calcRTCCyclePeriod();

        /*
         * Step 1: Deal with Periodic Interrupts
         */
        if (nCyclesUpdate >= this.nRTCCyclesNextUpdate) {
            let bPrev = this.abCMOSData[ChipSet.CMOS.ADDR.STATUSC];
            this.abCMOSData[ChipSet.CMOS.ADDR.STATUSC] |= ChipSet.CMOS.STATUSC.PF;
            if (this.abCMOSData[ChipSet.CMOS.ADDR.STATUSB] & ChipSet.CMOS.STATUSB.PIE) {
                /*
                 * When PIE is set, setBurstCycles() should be getting called as needed to ensure
                 * that updateRTCTime() is called more frequently, so let's assert that we don't have
                 * an excess of cycles and thus possibly some missed Periodic Interrupts.
                 */
                if (DEBUG) {
                    if (nCyclesUpdate - this.nRTCCyclesNextUpdate > this.nRTCCyclesPerPeriod) {
                        if (bPrev & ChipSet.CMOS.STATUSC.PF) {
                            this.printf(Messages.RTC, "RTC interrupt handler failed to clear STATUSC\n");
                        } else {
                            this.printf(Messages.RTC, "CPU took too long trigger new RTC periodic interrupt\n");
                        }
                    }
                }
                this.abCMOSData[ChipSet.CMOS.ADDR.STATUSC] |= ChipSet.CMOS.STATUSC.IRQF;
                this.setIRR(ChipSet.IRQ.RTC);
                /*
                 * We could also call setRTCCycleLimit() at this point, but I don't think there's any
                 * benefit until the interrupt had been acknowledged and STATUSC has been read, thereby
                 * clearing the way for another Periodic Interrupt; it seems to me that when STATUSC
                 * is read, that's the more appropriate time to call setRTCCycleLimit().
                 */
            }
            this.nRTCCyclesNextUpdate = nCyclesUpdate + this.nRTCCyclesPerPeriod;
        }

        /*
         * Step 2: Deal with Alarm Interrupts
         */
        if (this.abCMOSData[ChipSet.CMOS.ADDR.RTC_SEC] == this.abCMOSData[ChipSet.CMOS.ADDR.RTC_SEC_ALRM]) {
            if (this.abCMOSData[ChipSet.CMOS.ADDR.RTC_MIN] == this.abCMOSData[ChipSet.CMOS.ADDR.RTC_MIN_ALRM]) {
                if (this.abCMOSData[ChipSet.CMOS.ADDR.RTC_HOUR] == this.abCMOSData[ChipSet.CMOS.ADDR.RTC_HOUR_ALRM]) {
                    this.abCMOSData[ChipSet.CMOS.ADDR.STATUSC] |= ChipSet.CMOS.STATUSC.AF;
                    if (this.abCMOSData[ChipSet.CMOS.ADDR.STATUSB] & ChipSet.CMOS.STATUSB.AIE) {
                        this.abCMOSData[ChipSet.CMOS.ADDR.STATUSC] |= ChipSet.CMOS.STATUSC.IRQF;
                        this.setIRR(ChipSet.IRQ.RTC);
                    }
                }
            }
        }

        /*
         * Step 3: Update the RTC date/time and deal with Update Interrupts
         */
        let nCyclesDelta = nCyclesUpdate - this.nRTCCyclesLastUpdate;
        // DEBUG:
        let nSecondsDelta = Math.floor(nCyclesDelta / nCyclesPerSecond);

        /*
         * We trust that updateRTCTime() is being called as part of updateAllTimers(), and is therefore
         * being called often enough to ensure that nSecondsDelta will never be greater than one.  In fact,
         * it would always be LESS than one if it weren't also for the fact that we plow any "unused" cycles
         * (nCyclesDelta % nCyclesPerSecond) back into nRTCCyclesLastUpdate, so that we will eventually
         * see a one-second delta.
         */
        // DEBUG:

        /*
         * Make sure that CMOS.STATUSB.SET isn't set; if it is, then the once-per-second RTC updates must be
         * disabled so that software can write new RTC date/time values without interference.
         */
        if (nSecondsDelta && !(this.abCMOSData[ChipSet.CMOS.ADDR.STATUSB] & ChipSet.CMOS.STATUSB.SET)) {
            while (nSecondsDelta--) {
                if (++this.abCMOSData[ChipSet.CMOS.ADDR.RTC_SEC] >= 60) {
                    this.abCMOSData[ChipSet.CMOS.ADDR.RTC_SEC] = 0;
                    if (++this.abCMOSData[ChipSet.CMOS.ADDR.RTC_MIN] >= 60) {
                        this.abCMOSData[ChipSet.CMOS.ADDR.RTC_MIN] = 0;
                        if (++this.abCMOSData[ChipSet.CMOS.ADDR.RTC_HOUR] >= 24) {
                            this.abCMOSData[ChipSet.CMOS.ADDR.RTC_HOUR] = 0;
                            this.abCMOSData[ChipSet.CMOS.ADDR.RTC_WEEK_DAY] = (this.abCMOSData[ChipSet.CMOS.ADDR.RTC_WEEK_DAY] % 7) + 1;
                            let nDayMax = Usr.getMonthDays(this.abCMOSData[ChipSet.CMOS.ADDR.RTC_MONTH], this.abCMOSData[ChipSet.CMOS.ADDR.RTC_YEAR]);
                            if (++this.abCMOSData[ChipSet.CMOS.ADDR.RTC_MONTH_DAY] > nDayMax) {
                                this.abCMOSData[ChipSet.CMOS.ADDR.RTC_MONTH_DAY] = 1;
                                if (++this.abCMOSData[ChipSet.CMOS.ADDR.RTC_MONTH] > 12) {
                                    this.abCMOSData[ChipSet.CMOS.ADDR.RTC_MONTH] = 1;
                                    this.abCMOSData[ChipSet.CMOS.ADDR.RTC_YEAR] = (this.abCMOSData[ChipSet.CMOS.ADDR.RTC_YEAR] + 1) % 100;
                                }
                            }
                        }
                    }
                }
            }

            /*
             * Obviously, setting the "Update-In-Progress" bit now might seem rather pointless, since we just
             * updated the RTC "atomically" as far as the machine is concerned; however, the bit must be set at
             * at some point, in order to make the MODEL_5170 BIOS ("POST2_RTCUP") happy.
             */
            this.abCMOSData[ChipSet.CMOS.ADDR.STATUSA] |= ChipSet.CMOS.STATUSA.UIP;

            this.abCMOSData[ChipSet.CMOS.ADDR.STATUSC] |= ChipSet.CMOS.STATUSC.UF;
            if (this.abCMOSData[ChipSet.CMOS.ADDR.STATUSB] & ChipSet.CMOS.STATUSB.UIE) {
                this.abCMOSData[ChipSet.CMOS.ADDR.STATUSC] |= ChipSet.CMOS.STATUSC.IRQF;
                this.setIRR(ChipSet.IRQ.RTC);
            }
        }

        this.nRTCCyclesLastUpdate = nCyclesUpdate - (nCyclesDelta % nCyclesPerSecond);
    }

    /**
     * initCMOSData()
     *
     * Initialize all the CMOS configuration bytes in the range 0x0E-0x2F (TODO: Decide what to do about 0x30-0x3F)
     *
     * Note that the MODEL_5170 "SETUP" utility is normally what sets all these bytes, including the checksum, and then
     * the BIOS verifies it, but since we want our machines to pass BIOS verification "out of the box", we go the extra
     * mile here, even though it's not really our responsibility.
     *
     * @this {ChipSet}
     */
    initCMOSData()
    {
        /*
         * On all reset() calls, the RAM component(s) will (re)add their totals, so we have to make sure that
         * the addition always starts with 0.  That also means that ChipSet must always be initialized before RAM.
         */
        let iCMOS;
        for (iCMOS = ChipSet.CMOS.ADDR.BASEMEM_LO; iCMOS <= ChipSet.CMOS.ADDR.EXTMEM_HI; iCMOS++) {
            this.abCMOSData[iCMOS] = 0;
        }

        /*
         * Make sure all the "checksummed" CMOS bytes are initialized (not just the handful we set below) to ensure
         * that the checksum will be valid.
         */
        for (iCMOS = ChipSet.CMOS.ADDR.DIAG; iCMOS < ChipSet.CMOS.ADDR.CHKSUM_HI; iCMOS++) {
            if (this.abCMOSData[iCMOS] === undefined) this.abCMOSData[iCMOS] = 0;
        }

        /*
         * We propagate all compatible "legacy" SW1 bits to the CMOS.EQUIP byte using the old SW masks, but any further
         * access to CMOS.ADDR.EQUIP should use the new CMOS_EQUIP flags (eg, CMOS.EQUIP.FPU, CMOS.EQUIP.MONITOR.CGA80, etc).
         */
        this.abCMOSData[ChipSet.CMOS.ADDR.EQUIP] = this.getDIPLegacyBits(0);
        this.abCMOSData[ChipSet.CMOS.ADDR.FDRIVE] = (this.getDIPFloppyDriveType(0) << 4) | this.getDIPFloppyDriveType(1);

        /*
         * The final step is calculating the CMOS checksum, which we then store into the CMOS as a courtesy, so that the
         * user doesn't get unnecessary CMOS errors.
         */
        this.updateCMOSChecksum();
    }

    /**
     * setCMOSByte(iCMOS, b)
     *
     * This is ONLY for use by components that need to update CMOS configuration bytes to match their internal configuration.
     *
     * @this {ChipSet}
     * @param {number} iCMOS
     * @param {number} b
     * @return {boolean} true if successful, false if not (eg, CMOS not initialized yet, or no CMOS on this machine)
     */
    setCMOSByte(iCMOS, b)
    {
        if (this.abCMOSData) {

            this.abCMOSData[iCMOS] = b;
            this.updateCMOSChecksum();
            return true;
        }
        return false;
    }

    /**
     * addCMOSMemory(addr, size)
     *
     * For use by the RAM component, to dynamically update the CMOS memory configuration.
     *
     * @this {ChipSet}
     * @param {number} addr (if 0, BASEMEM_LO/BASEMEM_HI is updated; if >= 0x100000, then EXTMEM_LO/EXTMEM_HI is updated)
     * @param {number} size (in bytes; we convert to Kb)
     * @return {boolean} true if successful, false if not (eg, CMOS not initialized yet, or no CMOS on this machine)
     */
    addCMOSMemory(addr, size)
    {
        if (this.abCMOSData) {
            let iCMOS = (addr < 0x100000? ChipSet.CMOS.ADDR.BASEMEM_LO : ChipSet.CMOS.ADDR.EXTMEM_LO);
            let wKb = this.abCMOSData[iCMOS] | (this.abCMOSData[iCMOS+1] << 8);
            wKb += (size >> 10);
            this.abCMOSData[iCMOS] = wKb & 0xff;
            this.abCMOSData[iCMOS+1] = wKb >> 8;
            this.updateCMOSChecksum();
            return true;
        }
        return false;
    }

    /**
     * setCMOSDriveType(iDrive, bType)
     *
     * For use by the HDC component, to update the CMOS drive configuration to match HDC's internal configuration.
     *
     * TODO: Consider extending this to support FDC drive updates, so that the FDC can specify diskette drive types
     * (ie, FD360 or FD1200) in the same way that HDC does.  However, historically, the ChipSet has been responsible for
     * floppy drive configuration, at least in terms of *number* of drives, through the use of SW1 settings, and we've
     * continued that tradition with the addition of the ChipSet 'floppies' parameter, which allows both the number *and*
     * capacity of drives to be specified with a simple array (eg, [360, 360] for two 360Kb drives).
     *
     * @this {ChipSet}
     * @param {number} iDrive (0 or 1)
     * @param {number} bType (0 for none, 1-14 for original drive type, 16-255 for extended drive type; 15 reserved)
     * @return {boolean} true if successful, false if not (eg, CMOS not initialized yet, or no CMOS on this machine)
     */
    setCMOSDriveType(iDrive, bType)
    {
        if (this.abCMOSData) {
            let bExt = null, iExt;
            let bOrig = this.abCMOSData[ChipSet.CMOS.ADDR.HDRIVE];
            if (bType > 15) {
                bExt = bType;  bType = 15;
            }
            if (iDrive) {
                bOrig = (bOrig & ChipSet.CMOS.HDRIVE.D0_MASK) | bType;
                iExt = ChipSet.CMOS.ADDR.EXTHDRIVE1;
            } else {
                bOrig = (bOrig & ChipSet.CMOS.HDRIVE.D1_MASK) | (bType << 4);
                iExt = ChipSet.CMOS.ADDR.EXTHDRIVE0;
            }
            this.setCMOSByte(ChipSet.CMOS.ADDR.HDRIVE, bOrig);
            if (bExt != null) this.setCMOSByte(iExt, bExt);
            return true;
        }
        return false;
    }

    /**
     * updateCMOSChecksum()
     *
     * This sums all the CMOS bytes from 0x10-0x2D, creating a 16-bit checksum.  That's a total of 30 (unsigned) 8-bit
     * values which could sum to at most 30*255 or 7650 (0x1DE2).  Since there's no way that can overflow 16 bits, we don't
     * worry about masking it with 0xffff.
     *
     * WARNING: The IBM PC AT TechRef, p.1-53 (p.75) claims that the checksum is on bytes 0x10-0x20, but that's simply wrong.
     *
     * @this {ChipSet}
     */
    updateCMOSChecksum()
    {
        let wChecksum = 0;
        for (let iCMOS = ChipSet.CMOS.ADDR.FDRIVE; iCMOS < ChipSet.CMOS.ADDR.CHKSUM_HI; iCMOS++) {
            wChecksum += this.abCMOSData[iCMOS];
        }
        this.abCMOSData[ChipSet.CMOS.ADDR.CHKSUM_LO] = wChecksum & 0xff;
        this.abCMOSData[ChipSet.CMOS.ADDR.CHKSUM_HI] = wChecksum >> 8;
    }

    /**
     * save()
     *
     * This implements save support for the ChipSet component.
     *
     * @this {ChipSet}
     * @return {Object}
     */
    save()
    {
        let state = new State(this);
        state.set(0, [this.aDIPSwitches]);
        state.set(1, [this.saveDMAControllers()]);
        state.set(2, [this.savePICs()]);
        state.set(3, [this.bPIT0Ctrl, this.saveTimers(), this.bPIT1Ctrl]);
        state.set(4, [this.bPPIA, this.bPPIB, this.bPPIC, this.bPPICtrl, this.bNMI]);
        if (this.model >= ChipSet.MODEL_5170) {
            state.set(5, [this.b8042Status, this.b8042InBuff, this.b8042CmdData,
                          this.b8042OutBuff, this.b8042InPort, this.b8042OutPort]);
            state.set(6, [this.abDMAPageSpare[7], this.abDMAPageSpare, this.bCMOSAddr, this.abCMOSData, this.nRTCCyclesLastUpdate, this.nRTCCyclesNextUpdate]);
        }
        return state.data();
    }

    /**
     * restore(data)
     *
     * This implements restore support for the ChipSet component.
     *
     * @this {ChipSet}
     * @param {Object} data
     * @return {boolean} true if successful, false if failure
     */
    restore(data)
    {
        let a, i;
        a = data[0];

        if (Array.isArray(a[0])) {
            this.aDIPSwitches = a[0];
        } else {
            this.aDIPSwitches[0][0] = a[0];
            this.aDIPSwitches[1][0] = a[1] & 0x0F;  // we do honor SW2[5] now, but it was erroneously set on some machines
            this.aDIPSwitches[0][1] = a[2];
            this.aDIPSwitches[1][1] = a[3] & 0x0F;  // we do honor SW2[5] now, but it was erroneously set on some machines
        }
        this.updateDIPSwitches();

        a = data[1];
        for (i = 0; i < this.cDMACs; i++) {
            this.initDMAController(i, a.length == 1? a[0][i] : a);
        }

        a = data[2];
        for (i = 0; i < this.cPICs; i++) {
            this.initPIC(i, i === 0? ChipSet.PIC0.PORT_LO : ChipSet.PIC1.PORT_LO, a[0][i]);
        }

        a = data[3];
        this.bPIT0Ctrl = a[0];
        this.bPIT1Ctrl = a[2];
        for (i = 0; i < this.aTimers.length; i++) {
            this.initTimer(i, a[1][i]);
        }

        a = data[4];
        this.bPPIA = a[0];
        this.bPPIB = a[1];
        this.bPPIC = a[2];
        this.bPPICtrl = a[3];
        this.bNMI  = a[4];

        a = data[5];
        if (a) {

            this.b8042Status = a[0];
            this.b8042InBuff = a[1];
            this.b8042CmdData = a[2];
            this.b8042OutBuff = a[3];
            this.b8042InPort = a[4];
            this.b8042OutPort = a[5];
        }

        a = data[6];
        if (a) {

            this.abDMAPageSpare = a[1];
            this.abDMAPageSpare[7] = a[0];  // formerly bMFGData
            this.bCMOSAddr = a[2];
            this.abCMOSData = a[3];
            this.nRTCCyclesLastUpdate = a[4];
            this.nRTCCyclesNextUpdate = a[5];
            /*
             * TODO: Decide whether restore() should faithfully preserve the RTC date/time that save() saved,
             * or always reinitialize the date/time, or give the user (or the machine configuration) the option.
             *
             * For now, we're always reinitializing the RTC date.  Alternatively, we could selectively update
             * the CMOS bytes above, instead of overwriting them all, in which case this extra call to initRTCTime()
             * could be avoided.
             */
            this.initRTCTime();
        }
        return true;
    }

    /**
     * start()
     *
     * Notification from the Computer that it's starting.
     *
     * @this {ChipSet}
     */
    start()
    {
        /*
         * Currently, all we do with this notification is allow the speaker to make noise.
         */
        this.setSpeaker();
    }

    /**
     * stop()
     *
     * Notification from the Computer that it's stopping.
     *
     * @this {ChipSet}
     */
    stop()
    {
        /*
         * Currently, all we do with this notification is prevent the speaker from making noise.
         */
        this.setSpeaker();
    }

    /**
     * initDMAController(iDMAC, aState)
     *
     * @this {ChipSet}
     * @param {number} iDMAC
     * @param {Array} [aState]
     */
    initDMAController(iDMAC, aState)
    {
        let controller = this.aDMACs[iDMAC];
        if (!controller) {

            controller = {
                aChannels: new Array(4)
            };
        }
        let a = aState && aState.length >= 5? aState : ChipSet.aDMAControllerInit;
        controller.bStatus = a[0];
        controller.bCmd = a[1];
        controller.bReq = a[2];
        controller.bIndex = a[3];
        controller.nChannelBase = iDMAC << 2;
        for (let iChannel = 0; iChannel < controller.aChannels.length; iChannel++) {
            this.initDMAChannel(controller, iChannel, a[4][iChannel]);
        }
        controller.bTemp = a[5] || 0;       // not present in older states
        this.aDMACs[iDMAC] = controller;
    }

    /**
     * initDMAChannel(controller, iChannel, aState)
     *
     * @this {ChipSet}
     * @param {Object} controller
     * @param {number} iChannel
     * @param {Array} [aState]
     */
    initDMAChannel(controller, iChannel, aState)
    {
        let channel = controller.aChannels[iChannel];
        if (!channel) {

            channel = {
                addrInit: [0,0],
                countInit: [0,0],
                addrCurrent: [0,0],
                countCurrent: [0,0]
            };
        }
        let a = aState && aState.length == 8? aState : ChipSet.aDMAChannelInit;
        channel.masked = a[0];
        channel.addrInit[0] = a[1][0]; channel.addrInit[1] = a[1][1];
        channel.countInit[0] = a[2][0];  channel.countInit[1] = a[2][1];
        channel.addrCurrent[0] = a[3][0]; channel.addrCurrent[1] = a[3][1];
        channel.countCurrent[0] = a[4][0]; channel.countCurrent[1] = a[4][1];
        channel.mode = a[5];
        channel.bPage = a[6];
        // a[7] is deprecated
        channel.controller = controller;
        channel.iChannel = iChannel;
        this.initDMAFunction(channel, a[8], a[9]);
        controller.aChannels[iChannel] = channel;
    }

    /**
     * initDMAFunction(channel)
     *
     * @param {Object} channel
     * @param {Component|string} [component]
     * @param {string} [sFunction]
     * @param {Object} [obj]
     * @return {*}
     */
    initDMAFunction(channel, component, sFunction, obj)
    {
        if (typeof component == "string") {
            component = Component.getComponentByID(component);
        }
        if (component) {
            channel.done = null;
            channel.sDevice = component.id;
            channel.sFunction = sFunction;
            channel.component = component;
            channel.fnTransfer = component[sFunction];
            channel.obj = obj;
        }
        return channel.fnTransfer;
    }

    /**
     * saveDMAControllers()
     *
     * @this {ChipSet}
     * @return {Array}
     */
    saveDMAControllers()
    {
        let data = [];
        for (let iDMAC = 0; iDMAC < this.aDMACs; iDMAC++) {
            let controller = this.aDMACs[iDMAC];
            data[iDMAC] = [
                controller.bStatus,
                controller.bCmd,
                controller.bReq,
                controller.bIndex,
                this.saveDMAChannels(controller),
                controller.bTemp
            ];
        }
        return data;
    }

    /**
     * saveDMAChannels(controller)
     *
     * @this {ChipSet}
     * @param {Object} controller
     * @return {Array}
     */
    saveDMAChannels(controller)
    {
        let data = [];
        for (let iChannel = 0; iChannel < controller.aChannels.length; iChannel++) {
            let channel = controller.aChannels[iChannel];
            data[iChannel] = [
                channel.masked,
                channel.addrInit,
                channel.countInit,
                channel.addrCurrent,
                channel.countCurrent,
                channel.mode,
                channel.bPage,
                channel.sDevice,
                channel.sFunction
            ];
        }
        return data;
    }

    /**
     * initPIC(iPIC, port, aState)
     *
     * @this {ChipSet}
     * @param {number} iPIC
     * @param {number} port
     * @param {Array} [aState]
     */
    initPIC(iPIC, port, aState)
    {
        let pic = this.aPICs[iPIC];
        if (!pic) {
            pic = {
                aICW:   [null,null,null,null]
            };
        }
        let a = aState && aState.length == 8? aState : ChipSet.aPICInit;
        pic.port = port;
        pic.nIRQBase = iPIC << 3;
        pic.nDelay = a[0];
        pic.aICW[0] = a[1][0]; pic.aICW[1] = a[1][1]; pic.aICW[2] = a[1][2]; pic.aICW[3] = a[1][3];
        pic.nICW = a[2];
        pic.bIMR = a[3];
        pic.bIRR = a[4];
        pic.bISR = a[5];
        pic.bIRLow = a[6];
        pic.bOCW3 = a[7];
        this.aPICs[iPIC] = pic;
    }

    /**
     * savePICs()
     *
     * @this {ChipSet}
     * @return {Array}
     */
    savePICs()
    {
        let data = [];
        for (let iPIC = 0; iPIC < this.aPICs.length; iPIC++) {
            let pic = this.aPICs[iPIC];
            data[iPIC] = [
                pic.nDelay,
                pic.aICW,
                pic.nICW,
                pic.bIMR,
                pic.bIRR,
                pic.bISR,
                pic.bIRLow,
                pic.bOCW3
            ];
        }
        return data;
    }

    /**
     * initTimer(iTimer, aState)
     *
     * @this {ChipSet}
     * @param {number} iTimer
     * @param {Array} [aState]
     */
    initTimer(iTimer, aState)
    {
        let timer = this.aTimers[iTimer];
        if (!timer) {
            timer = {
                countInit: [0,0],
                countStart: [0,0],
                countCurrent: [0,0],
                countLatched: [0,0]
            };
        }
        let a = aState && aState.length >= 13? aState : ChipSet.aTimerInit;
        timer.countInit[0] = a[0][0]; timer.countInit[1] = a[0][1];
        timer.countStart[0] = a[1][0]; timer.countStart[1] = a[1][1];
        timer.countCurrent[0] = a[2][0]; timer.countCurrent[1] = a[2][1];
        timer.countLatched[0] = a[3][0]; timer.countLatched[1] = a[3][1];
        timer.bcd = a[4];
        timer.mode = a[5];
        timer.rw = a[6];
        timer.countIndex = a[7];
        timer.countBytes = a[8];
        timer.fOUT = a[9];
        timer.fCountLatched = a[10];
        timer.fCounting = a[11];
        timer.nCyclesStart = a[12];
        timer.bStatus = a[13] || 0;
        timer.fStatusLatched = a[14] || false;
        this.aTimers[iTimer] = timer;
    }

    /**
     * saveTimers()
     *
     * @this {ChipSet}
     * @return {Array}
     */
    saveTimers()
    {
        let data = [];
        for (let iTimer = 0; iTimer < this.aTimers.length; iTimer++) {
            let timer = this.aTimers[iTimer];
            data[iTimer] = [
                timer.countInit,
                timer.countStart,
                timer.countCurrent,
                timer.countLatched,
                timer.bcd,
                timer.mode,
                timer.rw,
                timer.countIndex,
                timer.countBytes,
                timer.fOUT,
                timer.fCountLatched,
                timer.fCounting,
                timer.nCyclesStart,
                timer.bStatus,
                timer.fStatusLatched
            ];
        }
        return data;
    }

    /**
     * addDIPSwitches(iDIP, sBinding)
     *
     * @this {ChipSet}
     * @param {number} iDIP (0 or 1)
     * @param {string} sBinding is the name of the control
     */
    addDIPSwitches(iDIP, sBinding)
    {
        let sHTML = "";
        let control = this.bindings[sBinding];
        for (let i = 1; i <= 8; i++) {
            let sCellClasses = this.sCellClass;
            if (!i) sCellClasses += " " + this.sCellClass + "Left";
            let sCellID = sBinding + "-" + i;
            sHTML += "<div id=\"" + sCellID + "\" class=\"" + sCellClasses + "\" data-value=\"0\">" + i + "</div>\n";
        }
        control.innerHTML = sHTML;
        this.updateDIPSwitchControls(iDIP, sBinding, true);
    }

    /**
     * findDIPSwitch(iDIP, iSwitch)
     *
     * @this {ChipSet}
     * @param {number} iDIP
     * @param {number} iSwitch
     * @return {Object|null} DIPSW switchGroup containing the DIP switch's MASK, VALUES, and LABEL, or null if none
     */
    findDIPSwitch(iDIP, iSwitch)
    {
        let switchDIPs = ChipSet.DIPSW[this.model|0];
        let switchTypes = switchDIPs && switchDIPs[iDIP];
        if (switchTypes) {
            for (let iType in switchTypes) {
                let switchGroup = switchTypes[iType];
                if (switchGroup.MASK & (1 << iSwitch)) {
                    return switchGroup;
                }
            }
        }
        return null;
    }

    /**
     * getDIPLegacyBits(iDIP)
     *
     * @this {ChipSet}
     * @param {number} iDIP
     * @return {number|undefined}
     */
    getDIPLegacyBits(iDIP)
    {
        let b;
        if (!iDIP) {
            b = 0;
            b |= (this.getDIPVideoMonitor() << ChipSet.PPI_SW.MONITOR.SHIFT) & ChipSet.PPI_SW.MONITOR.MASK;
            b |= (this.getDIPCoprocessor()? ChipSet.PPI_SW.FPU : 0);
            let nDrives = this.getDIPFloppyDrives();
            b |= (nDrives? ((((nDrives - 1) << ChipSet.PPI_SW.FDRIVE.SHIFT) & ChipSet.PPI_SW.FDRIVE.MASK) | ChipSet.PPI_SW.FDRIVE.IPL) : 0);
        }
        return b;
    }

    /**
     * getDIPSwitches(iType, fInit)
     *
     * @this {ChipSet}
     * @param {number} iType
     * @param {boolean} [fInit] is true for initial switch value, current value otherwise
     * @return {string|null}
     */
    getDIPSwitches(iType, fInit)
    {
        let value = null;
        let switchDIPs = ChipSet.DIPSW[this.model] || ChipSet.DIPSW[this.model|0] || ChipSet.DIPSW[ChipSet.MODEL_5150];
        for (let iDIP = 0; iDIP < switchDIPs.length; iDIP++) {
            let switchTypes = switchDIPs[iDIP];
            if (switchTypes) {
                let switchGroup = switchTypes[iType];
                if (switchGroup) {
                    let bits = this.aDIPSwitches[iDIP][fInit?0:1] & switchGroup.MASK;
                    for (let v in switchGroup.VALUES) {
                        if (switchGroup.VALUES[v] == bits) {
                            value = v;
                            /*
                             * We prefer numeric properties, and all switch definitions must provide them
                             * if their helper functions (eg, getDIPVideoMonitor()) expect numeric properties.
                             */
                            if (typeof +value == 'number') break;
                        }
                    }
                    break;
                }
            }
        }
        return value;
    }

    /**
     * getDIPSwitchRange(iType)
     *
     * @this {ChipSet}
     * @param {number} iType
     * @return {Array.<number>} [minimum value, maximum value]
     */
    getDIPSwitchRange(iType)
    {
        let values = [-1, -1];          // none of our switches should have negative values
        let switchDIPs = ChipSet.DIPSW[this.model] || ChipSet.DIPSW[this.model|0] || ChipSet.DIPSW[ChipSet.MODEL_5150];
        for (let iDIP = 0; iDIP < switchDIPs.length; iDIP++) {
            let switchTypes = switchDIPs[iDIP];
            if (switchTypes) {
                let switchGroup = switchTypes[iType];
                if (switchGroup) {
                    for (let v in switchGroup.VALUES) {
                        if (values[0] < 0 || values[0] > +v) values[0] = +v;
                        if (values[1] < 0 || values[1] < +v) values[1] = +v;
                    }
                }
            }
        }
        return values;
    }

    /**
     * getDIPCoprocessor(fInit)
     *
     * @this {ChipSet}
     * @param {boolean} [fInit] is true for init switch value(s) only, current value(s) otherwise
     * @return {number} 1 if installed, 0 if not
     */
    getDIPCoprocessor(fInit)
    {
        return +this.getDIPSwitches(ChipSet.SWITCH_TYPE.FPU, fInit);
    }

    /**
     * getDIPFloppyDrives(fInit)
     *
     * @this {ChipSet}
     * @param {boolean} [fInit] is true for init switch value(s) only, current value(s) otherwise
     * @return {number} number of floppy drives specified by SW1 (range is 0 to 4)
     */
    getDIPFloppyDrives(fInit)
    {
        return +this.getDIPSwitches(ChipSet.SWITCH_TYPE.FLOPNUM, fInit);
    }

    /**
     * getDIPFloppyDriveType(iDrive)
     *
     * @this {ChipSet}
     * @param {number} iDrive (0-based)
     * @return {number} one of the ChipSet.CMOS.FDRIVE.FD* values (FD360, FD1200, etc)
     */
    getDIPFloppyDriveType(iDrive)
    {
        if (iDrive < this.getDIPFloppyDrives()) {
            if (!this.aFloppyDrives) {
                return ChipSet.CMOS.FDRIVE.FD360;
            }
            if (iDrive < this.aFloppyDrives.length) {
                switch(this.aFloppyDrives[iDrive]) {
                case 160:
                case 180:
                case 320:
                case 360:
                    return ChipSet.CMOS.FDRIVE.FD360;
                case 720:
                    return ChipSet.CMOS.FDRIVE.FD720;
                case 1200:
                    return ChipSet.CMOS.FDRIVE.FD1200;
                case 1440:
                    return ChipSet.CMOS.FDRIVE.FD1440;
                }
            }

        }
        return ChipSet.CMOS.FDRIVE.NONE;
    }

    /**
     * getDIPFloppyDriveSize(iDrive)
     *
     * @this {ChipSet}
     * @param {number} iDrive (0-based)
     * @return {number} capacity of drive in Kb (eg, 360, 1200, 1440, etc), or 0 if none
     */
    getDIPFloppyDriveSize(iDrive)
    {
        if (iDrive < this.getDIPFloppyDrives()) {
            if (!this.aFloppyDrives) {
                return 360;
            }
            if (iDrive < this.aFloppyDrives.length) {
                return this.aFloppyDrives[iDrive];
            }

        }
        return 0;
    }

    /**
     * getDIPMemorySize(fInit)
     *
     * @this {ChipSet}
     * @param {boolean} [fInit] is true for init switch value(s) only, current value(s) otherwise
     * @return {number} number of Kb of specified memory (NOT necessarily the same as installed memory; see RAM component)
     */
    getDIPMemorySize(fInit)
    {
        let nKBLow = this.getDIPSwitches(ChipSet.SWITCH_TYPE.LOWMEM, fInit);
        let nKBExp = this.getDIPSwitches(ChipSet.SWITCH_TYPE.EXPMEM, fInit);
        return +nKBLow + +nKBExp;
    }

    /**
     * setDIPMemorySize(nKB)
     *
     * @this {ChipSet}
     * @param {number} nKB
     * @return {boolean} true if successful, false if out of range
     */
    setDIPMemorySize(nKB)
    {
        let rangeKBLow = this.getDIPSwitchRange(ChipSet.SWITCH_TYPE.LOWMEM);
        if (nKB <= rangeKBLow[1]) {
            if (this.setDIPSwitches(ChipSet.SWITCH_TYPE.LOWMEM, nKB) && this.setDIPSwitches(ChipSet.SWITCH_TYPE.EXPMEM, 0)) {
                return true;
            }
        }
        let rangeKBExp = this.getDIPSwitchRange(ChipSet.SWITCH_TYPE.EXPMEM);
        if (nKB <= rangeKBLow[1] + rangeKBExp[1]) {
            nKB -= rangeKBLow[1];
            if (this.setDIPSwitches(ChipSet.SWITCH_TYPE.LOWMEM, rangeKBLow[1]) && this.setDIPSwitches(ChipSet.SWITCH_TYPE.EXPMEM, nKB)) {
                return true;
            }
        }
        return false;
    }

    /**
     * getDIPVideoMonitor(fInit)
     *
     * @this {ChipSet}
     * @param {boolean} [fInit] is true for init switch value(s) only, current value(s) otherwise
     * @return {number} one of ChipSet.MONITOR.*
     */
    getDIPVideoMonitor(fInit)
    {
        return +this.getDIPSwitches(ChipSet.SWITCH_TYPE.MONITOR, fInit);
    }

    /**
     * parseDIPSwitches(sBits, bDefault)
     *
     * @this {ChipSet}
     * @param {string} sBits describing switch settings
     * @param {number} [bDefault]
     * @return {number|undefined}
     */
    parseDIPSwitches(sBits, bDefault)
    {
        let b = bDefault;
        if (sBits) {
            /*
             * NOTE: We can't use parseInt() with a base of 2, because both bit order and bit sense are reversed.
             */
            b = 0;
            let bit = 0x1;
            for (let i = 0; i < sBits.length; i++) {
                if (sBits.charAt(i) == "0") b |= bit;
                bit <<= 1;
            }
        }
        return b;
    }

    /**
     * setDIPSwitches(iType, value, fInit)
     *
     * @this {ChipSet}
     * @param {number} iType
     * @param {*} value
     * @param {boolean} [fInit]
     * @return {boolean} true if successful, false if unrecognized type and/or value
     */
    setDIPSwitches(iType, value, fInit)
    {
        let switchDIPs = ChipSet.DIPSW[this.model] || ChipSet.DIPSW[this.model|0] || ChipSet.DIPSW[ChipSet.MODEL_5150];
        for (let iDIP = 0; iDIP < switchDIPs.length; iDIP++) {
            let switchTypes = switchDIPs[iDIP];
            if (switchTypes) {
                let switchGroup = switchTypes[iType];
                if (switchGroup) {
                    for (let v in switchGroup.VALUES) {
                        if (v == value) {
                            this.aDIPSwitches[iDIP][fInit?0:1] &= ~switchGroup.MASK;
                            this.aDIPSwitches[iDIP][fInit?0:1] |= switchGroup.VALUES[v];
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    /**
     * getDIPSwitchControl(control)
     *
     * @this {ChipSet}
     * @param {HTMLElement} control is an HTML control DOM object
     * @return {boolean} true if the switch represented by e is "on", false if "off"
     */
    getDIPSwitchControl(control)
    {
        return control.getAttribute("data-value") == "1";
    }

    /**
     * setDIPSwitchControl(control, f)
     *
     * @this {ChipSet}
     * @param {HTMLElement} control is an HTML control DOM object
     * @param {boolean} f is true if the switch represented by control should be "on", false if "off"
     */
    setDIPSwitchControl(control, f)
    {
        control.setAttribute("data-value", f? "1" : "0");
        control.style.color = (f? "#ffffff" : "#000000");
        control.style.backgroundColor = (f? "#000000" : "#ffffff");
    }

    /**
     * toggleDIPSwitchControl(control)
     *
     * @this {ChipSet}
     * @param {HTMLElement} control is an HTML control DOM object
     */
    toggleDIPSwitchControl(control)
    {
        let f = !this.getDIPSwitchControl(control);
        this.setDIPSwitchControl(control, f);
        let sID = control.getAttribute("id");
        let asParts = sID.split("-");
        let b = (0x1 << (+asParts[1] - 1));
        switch (asParts[0]) {
        case ChipSet.CONTROLS.SW1:
            this.aDIPSwitches[0][0] = (this.aDIPSwitches[0][0] & ~b) | (f? 0 : b);
            break;
        case ChipSet.CONTROLS.SW2:
            this.aDIPSwitches[1][0] = (this.aDIPSwitches[1][0] & ~b) | (f? 0 : b);
            break;
        default:
            break;
        }
        this.updateDIPSwitchDescriptions();
    }

    /**
     * updateDIPSwitches()
     *
     * @this {ChipSet}
     */
    updateDIPSwitches()
    {
        this.updateDIPSwitchControls(0, ChipSet.CONTROLS.SW1);
        this.updateDIPSwitchControls(1, ChipSet.CONTROLS.SW2);
        this.updateDIPSwitchDescriptions();
    }

    /**
     * updateDIPSwitchControls(iDIP, sBinding, fInit)
     *
     * @this {ChipSet}
     * @param {number} iDIP (0 or 1)
     * @param {string} sBinding is the name of the control
     * @param {boolean} [fInit]
     */
    updateDIPSwitchControls(iDIP, sBinding, fInit)
    {
        let control = this.bindings[sBinding];
        if (control) {
            let v;
            if (fInit) {
                v = this.aDIPSwitches[iDIP][0];
            } else {
                v = this.aDIPSwitches[iDIP][1] = this.aDIPSwitches[iDIP][0];
            }
            let aeCells = Component.getElementsByClass(control, this.sCellClass);
            for (let i = 0; i < aeCells.length; i++) {
                let switchGroup = this.findDIPSwitch(iDIP, i);
                let sLabel = switchGroup && switchGroup.LABEL || "Reserved";
                aeCells[i].setAttribute("title", sLabel);
                this.setDIPSwitchControl(aeCells[i], !(v & (0x1 << i)));
                aeCells[i].onclick = function(chipset, eSwitch) {
                    /*
                     * If we define the onclick handler below as "function(e)" instead of simply "function()", then we will
                     * also receive an Event object; however, IE reportedly requires that we examine a global (window.event)
                     * instead.  If that's true, and if we ever care to get more details about the click event, then define
                     * a local var; eg:
                     *
                     *      let event = window.event || e;
                     */
                    return function onClickSwitch() {
                        chipset.toggleDIPSwitchControl(eSwitch);
                    };
                }(this, aeCells[i]);
            }
        }
    }

    /**
     * updateDIPSwitchDescriptions()
     *
     * @this {ChipSet}
     */
    updateDIPSwitchDescriptions()
    {
        let controlDesc = this.bindings[ChipSet.CONTROLS.SWDESC];
        if (controlDesc != null) {
            let sText = "";
            /*
             * TODO: Monitor type 0 used to be "None" (ie, "No Monitor"), which was correct in a pre-EGA world,
             * but in the post-EGA world, it depends.  We should ask the Video component for a definitive answer.
             */
            let asMonitorTypes = {
                0: "Enhanced Color",
                1: "TV",
                2: "Color",
                3: "Monochrome"
            };
            sText += this.getDIPMemorySize(true) + "K";
            sText += ", " + (+this.getDIPCoprocessor(true)? "" : "No ") + "FPU";
            sText += ", " + asMonitorTypes[this.getDIPVideoMonitor(true)] + " Monitor";
            sText += ", " + this.getDIPFloppyDrives(true) + " Floppy Drives";
            if (this.aDIPSwitches[0][1] != null && this.aDIPSwitches[0][1] != this.aDIPSwitches[0][0] ||
                this.aDIPSwitches[1][1] != null && this.aDIPSwitches[1][1] != this.aDIPSwitches[1][0]) {
                sText += " (Reset required)";
            }
            controlDesc.textContent = sText;
        }
    }

    /**
     * dumpPIC()
     *
     * @this {ChipSet}
     */
    dumpPIC()
    {
        if (DEBUGGER) {
            for (let iPIC = 0; iPIC < this.aPICs.length; iPIC++) {
                let pic = this.aPICs[iPIC];
                let sDump = "PIC" + iPIC + ":";
                for (let i = 0; i < pic.aICW.length; i++) {
                    let b = pic.aICW[i];
                    sDump += " IC" + (i + 1) + '=' + Str.toHexByte(b);
                }
                sDump += " IMR=" + Str.toHexByte(pic.bIMR) + " IRR=" + Str.toHexByte(pic.bIRR) + " ISR=" + Str.toHexByte(pic.bISR) + " DELAY=" + pic.nDelay;
                this.dbg.println(sDump);
            }
        }
    }

    /**
     * dumpTimer(asArgs)
     *
     * Use "d timer" to dump all timers, or "d timer n" to dump only timer n.
     *
     * @this {ChipSet}
     * @param {Array.<string>} asArgs
     */
    dumpTimer(asArgs)
    {
        if (DEBUGGER) {
            let sParm = asArgs[0];
            let nTimer = (sParm? +sParm : null);
            for (let iTimer = 0; iTimer < this.aTimers.length; iTimer++) {
                if (nTimer != null && iTimer != nTimer) continue;
                this.updateTimer(iTimer);
                let timer = this.aTimers[iTimer];
                let sDump = "TIMER" + iTimer + ":";
                let count = 0;
                if (timer.countBytes != null) {
                    for (let i = 0; i <= timer.countBytes; i++) {
                        count |= (timer.countCurrent[i] << (i * 8));
                    }
                }
                sDump += " mode=" + (timer.mode >> 1) + " bytes=" + timer.countBytes + " count=" + Str.toHexWord(count);
                this.dbg.println(sDump);
            }
        }
    }

    /**
     * dumpCMOS()
     *
     * @this {ChipSet}
     */
    dumpCMOS()
    {
        if (DEBUGGER) {
            let sDump = "";
            for (let iCMOS = 0; iCMOS < ChipSet.CMOS.ADDR.TOTAL; iCMOS++) {
                let b = (iCMOS <= ChipSet.CMOS.ADDR.STATUSD? this.getRTCByte(iCMOS) : this.abCMOSData[iCMOS]);
                if (sDump) sDump += '\n';
                sDump += "CMOS[" + Str.toHexByte(iCMOS) + "]: " + Str.toHexByte(b);
            }
            this.dbg.println(sDump);
        }
    }

    /**
     * inDMAChannelAddr(iDMAC, iChannel, port, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} iDMAC
     * @param {number} iChannel
     * @param {number} port (0x00, 0x02, 0x04, 0x06 for DMAC 0, 0xC0, 0xC4, 0xC8, 0xCC for DMAC 1)
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     * @return {number} simulated port value
     */
    inDMAChannelAddr(iDMAC, iChannel, port, addrFrom)
    {
        let controller = this.aDMACs[iDMAC];
        let channel = controller.aChannels[iChannel];
        let b = channel.addrCurrent[controller.bIndex];
        if (this.messageEnabled(Messages.DMA + Messages.PORT)) {
            this.printMessageIO(port, undefined, addrFrom, "DMA" + iDMAC + ".CHANNEL" + iChannel + ".ADDR[" + controller.bIndex + "]", b, true);
        }
        controller.bIndex ^= 0x1;
        /*
         * Technically, aTimers[1].fOut is what drives DMA requests for DMA channel 0 (ChipSet.DMA_REFRESH),
         * every 15us, once the BIOS has initialized the channel's "mode" with MODE_SINGLE, INCREMENT, AUTOINIT,
         * and TYPE_READ (0x58) and initialized TIMER1 appropriately.
         *
         * However, we don't need to be that particular.  Simply simulate an ever-increasing address after every
         * read of the full DMA channel 0 address.
         */
        if (!iDMAC && iChannel == ChipSet.DMA_REFRESH && !controller.bIndex) {
            channel.addrCurrent[0]++;
            if (channel.addrCurrent[0] > 0xff) {
                channel.addrCurrent[0] = 0;
                channel.addrCurrent[1]++;
                if (channel.addrCurrent[1] > 0xff) {
                    channel.addrCurrent[1] = 0;
                }
            }
        }
        return b;
    }

    /**
     * outDMAChannelAddr(iDMAC, iChannel, port, bOut, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} iDMAC
     * @param {number} iChannel
     * @param {number} port (0x00, 0x02, 0x04, 0x06 for DMAC 0, 0xC0, 0xC4, 0xC8, 0xCC for DMAC 1)
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     */
    outDMAChannelAddr(iDMAC, iChannel, port, bOut, addrFrom)
    {
        let controller = this.aDMACs[iDMAC];
        if (this.messageEnabled(Messages.DMA + Messages.PORT)) {
            this.printMessageIO(port, bOut, addrFrom, "DMA" + iDMAC + ".CHANNEL" + iChannel + ".ADDR[" + controller.bIndex + "]", undefined, true);
        }
        let channel = controller.aChannels[iChannel];
        channel.addrCurrent[controller.bIndex] = channel.addrInit[controller.bIndex] = bOut;
        controller.bIndex ^= 0x1;
    }

    /**
     * inDMAChannelCount(iDMAC, iChannel, port, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} iDMAC
     * @param {number} iChannel
     * @param {number} port (0x01, 0x03, 0x05, 0x07 for DMAC 0, 0xC2, 0xC6, 0xCA, 0xCE for DMAC 1)
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     * @return {number} simulated port value
     */
    inDMAChannelCount(iDMAC, iChannel, port, addrFrom)
    {
        let controller = this.aDMACs[iDMAC];
        let channel = controller.aChannels[iChannel];
        let b = channel.countCurrent[controller.bIndex];
        if (this.messageEnabled(Messages.DMA + Messages.PORT)) {
            this.printMessageIO(port, undefined, addrFrom, "DMA" + iDMAC + ".CHANNEL" + iChannel + ".COUNT[" + controller.bIndex + "]", b, true);
        }
        controller.bIndex ^= 0x1;
        /*
         * Technically, aTimers[1].fOut is what drives DMA requests for DMA channel 0 (ChipSet.DMA_REFRESH),
         * every 15us, once the BIOS has initialized the channel's "mode" with MODE_SINGLE, INCREMENT, AUTOINIT,
         * and TYPE_READ (0x58) and initialized TIMER1 appropriately.
         *
         * However, we don't need to be that particular.  Simply simulate an ever-decreasing count after every
         * read of the full DMA channel 0 count.
         */
        if (!iDMAC && iChannel == ChipSet.DMA_REFRESH && !controller.bIndex) {
            channel.countCurrent[0]--;
            if (channel.countCurrent[0] < 0) {
                channel.countCurrent[0] = 0xff;
                channel.countCurrent[1]--;
                if (channel.countCurrent[1] < 0) {
                    channel.countCurrent[1] = 0xff;
                    /*
                     * This is the logical point to indicate Terminal Count (TC), but again, there's no need to be
                     * so particular; inDMAStatus() has its own logic for periodically signalling TC.
                     */
                }
            }
        }
        return b;
    }

    /**
     * outDMAChannelCount(iDMAC, iChannel, port, bOut, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} iDMAC
     * @param {number} iChannel (ports 0x01, 0x03, 0x05, 0x07)
     * @param {number} port (0x01, 0x03, 0x05, 0x07 for DMAC 0, 0xC2, 0xC6, 0xCA, 0xCE for DMAC 1)
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     */
    outDMAChannelCount(iDMAC, iChannel, port, bOut, addrFrom)
    {
        let controller = this.aDMACs[iDMAC];
        if (this.messageEnabled(Messages.DMA + Messages.PORT)) {
            this.printMessageIO(port, bOut, addrFrom, "DMA" + iDMAC + ".CHANNEL" + iChannel + ".COUNT[" + controller.bIndex + "]", undefined, true);
        }
        let channel = controller.aChannels[iChannel];
        channel.countCurrent[controller.bIndex] = channel.countInit[controller.bIndex] = bOut;
        controller.bIndex ^= 0x1;
    }

    /**
     * inDMAStatus(iDMAC, port, addrFrom)
     *
     * From the 8237A spec:
     *
     * "The Status register is available to be read out of the 8237A by the microprocessor.
     * It contains information about the status of the devices at this point. This information includes
     * which channels have reached Terminal Count (TC) and which channels have pending DMA requests.
     *
     * Bits 0–3 are set every time a TC is reached by that channel or an external EOP is applied.
     * These bits are cleared upon Reset and on each Status Read.
     *
     * Bits 4–7 are set whenever their corresponding channel is requesting service."
     *
     * TRIVIA: This hook wasn't installed when I was testing with the MODEL_5150 ROM BIOS, and it
     * didn't matter, but the MODEL_5160 ROM BIOS checks it several times, including @F000:E156, where
     * it verifies that TIMER1 didn't request service on channel 0.
     *
     * @this {ChipSet}
     * @param {number} iDMAC
     * @param {number} port (0x08 for DMAC 0, 0xD0 for DMAC 1)
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     * @return {number} simulated port value
     */
    inDMAStatus(iDMAC, port, addrFrom)
    {
        /*
         * HACK: Unlike the MODEL_5150, the MODEL_5160 ROM BIOS checks DMA channel 0 for TC (@F000:E4DF)
         * after running a number of unrelated tests, since enough time would have passed for channel 0 to
         * have reached TC at least once.  So I simply OR in a hard-coded TC bit for channel 0 every time
         * status is read.
         */
        let controller = this.aDMACs[iDMAC];
        let b = controller.bStatus | ChipSet.DMA_STATUS.CH0_TC;
        controller.bStatus &= ~ChipSet.DMA_STATUS.ALL_TC;
        if (this.messageEnabled(Messages.DMA + Messages.PORT)) {
            this.printMessageIO(port, undefined, addrFrom, "DMA" + iDMAC + ".STATUS", b, true);
        }
        return b;
    }

    /**
     * outDMACmd(iDMAC, port, bOut, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} iDMAC
     * @param {number} port (0x08 for DMAC 0, 0xD0 for DMAC 1)
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     */
    outDMACmd(iDMAC, port, bOut, addrFrom)
    {
        if (this.messageEnabled(Messages.DMA + Messages.PORT)) {
            this.printMessageIO(port, bOut, addrFrom, "DMA" + iDMAC + ".CMD", undefined, true);
        }
        this.aDMACs[iDMAC].bCmd = bOut;
    }

    /**
     * outDMAReq(iDMAC, port, bOut, addrFrom)
     *
     * From the 8237A spec:
     *
     * "The 8237A can respond to requests for DMA service which are initiated by software as well as by a DREQ.
     * Each channel has a request bit associated with it in the 4-bit Request register. These are non-maskable and subject
     * to prioritization by the Priority Encoder network. Each register bit is set or reset separately under software
     * control or is cleared upon generation of a TC or external EOP. The entire register is cleared by a Reset.
     *
     * To set or reset a bit the software loads the proper form of the data word.... In order to make a software request,
     * the channel must be in Block Mode."
     *
     * @this {ChipSet}
     * @param {number} iDMAC
     * @param {number} port (0x09 for DMAC 0, 0xD2 for DMAC 1)
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     */
    outDMAReq(iDMAC, port, bOut, addrFrom)
    {
        let controller = this.aDMACs[iDMAC];
        if (this.messageEnabled(Messages.DMA + Messages.PORT)) {
            this.printMessageIO(port, bOut, addrFrom, "DMA" + iDMAC + ".REQ", undefined, true);
        }
        /*
         * Bits 0-1 contain the channel number
         */
        let iChannel = (bOut & 0x3);
        /*
         * Bit 2 is the request bit (0 to reset, 1 to set), which must be propagated to the corresponding bit (4-7) in the status register
         */
        let iChannelBit = ((bOut & 0x4) << (iChannel + 2));
        controller.bStatus = (controller.bStatus & ~(0x10 << iChannel)) | iChannelBit;
        controller.bReq = bOut;
    }

    /**
     * outDMAMask(iDMAC, port, bOut, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} iDMAC
     * @param {number} port (0x0A for DMAC 0, 0xD4 for DMAC 1)
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     */
    outDMAMask(iDMAC, port, bOut, addrFrom)
    {
        let controller = this.aDMACs[iDMAC];
        if (this.messageEnabled(Messages.DMA + Messages.PORT)) {
            this.printMessageIO(port, bOut, addrFrom, "DMA" + iDMAC + ".MASK", undefined, true);
        }
        let iChannel = bOut & ChipSet.DMA_MASK.CHANNEL;
        let channel = controller.aChannels[iChannel];
        channel.masked = !!(bOut & ChipSet.DMA_MASK.CHANNEL_SET);
        if (!channel.masked) this.requestDMA(controller.nChannelBase + iChannel);
    }

    /**
     * outDMAMode(iDMAC, port, bOut, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} iDMAC
     * @param {number} port (0x0B for DMAC 0, 0xD6 for DMAC 1)
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     */
    outDMAMode(iDMAC, port, bOut, addrFrom)
    {
        if (this.messageEnabled(Messages.DMA + Messages.PORT)) {
            this.printMessageIO(port, bOut, addrFrom, "DMA" + iDMAC + ".MODE", undefined, true);
        }
        let iChannel = bOut & ChipSet.DMA_MODE.CHANNEL;
        this.aDMACs[iDMAC].aChannels[iChannel].mode = bOut;
    }

    /**
     * outDMAResetFF(iDMAC, port, bOut, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} iDMAC
     * @param {number} port (0x0C for DMAC 0, 0xD8 for DMAC 1)
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     *
     * Any write to this port simply resets the controller's "first/last flip-flop", which determines whether
     * the even or odd byte of a DMA address or count register will be accessed next.
     */
    outDMAResetFF(iDMAC, port, bOut, addrFrom)
    {
        if (this.messageEnabled(Messages.DMA + Messages.PORT)) {
            this.printMessageIO(port, bOut, addrFrom, "DMA" + iDMAC + ".RESET_FF", undefined, true);
        }
        this.aDMACs[iDMAC].bIndex = 0;
    }

    /**
     * inDMATemp(iDMAC, port, addrFrom)
     *
     * From the 8237A spec:
     *
     * "The Temporary register is used to hold data during memory-to-memory transfers  Following the
     * completion of the transfers, the last word moved can be read by the microprocessor in the Program Condition.
     * The Temporary register always contains the last byte transferred in the previous memory-to-memory operation,
     * unless cleared by a Reset."
     *
     * TRIVIA: This hook wasn't installed when I was testing with ANY of the IBM ROMs, but it's required
     * by the AT&T 6300 (aka Olivetti M24) ROM.
     *
     * TODO: When support is added for memory-to-memory transfers, bTemp needs to be updated according to spec.
     *
     * @this {ChipSet}
     * @param {number} iDMAC
     * @param {number} port (0x0D for DMAC 0, 0xDA for DMAC 1)
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     * @return {number} simulated port value
     */
    inDMATemp(iDMAC, port, addrFrom)
    {
        let controller = this.aDMACs[iDMAC];
        let b = controller.bTemp;
        if (this.messageEnabled(Messages.DMA + Messages.PORT)) {
            this.printMessageIO(port, undefined, addrFrom, "DMA" + iDMAC + ".TEMP", b, true);
        }
        return b;
    }

    /**
     * outDMAMasterClear(iDMAC, port, bOut, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} iDMAC
     * @param {number} port (0x0D for DMAC 0, 0xDA for DMAC 1)
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     */
    outDMAMasterClear(iDMAC, port, bOut, addrFrom)
    {
        if (this.messageEnabled(Messages.DMA + Messages.PORT)) {
            this.printMessageIO(port, bOut, addrFrom, "DMA" + iDMAC + ".MASTER_CLEAR", undefined, true);
        }
        /*
         * The value written to this port doesn't matter; any write triggers a "master clear" operation
         *
         * TODO: Can't we just call initDMAController(), which would also take care of clearing controller.bStatus?
         */
        let controller = this.aDMACs[iDMAC];
        for (let i = 0; i < controller.aChannels.length; i++) {
            this.initDMAChannel(controller, i);
        }
    }

    /**
     * inDMAPageReg(iDMAC, iChannel, port, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} iDMAC
     * @param {number} iChannel
     * @param {number} port
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     * @return {number} simulated port value
     */
    inDMAPageReg(iDMAC, iChannel, port, addrFrom)
    {
        let bIn = this.aDMACs[iDMAC].aChannels[iChannel].bPage;
        if (this.messageEnabled(Messages.DMA + Messages.PORT)) {
            this.printMessageIO(port, undefined, addrFrom, "DMA" + iDMAC + ".CHANNEL" + iChannel + ".PAGE", bIn, true);
        }
        return bIn;
    }

    /**
     * outDMAPageReg(iDMAC, iChannel, port, bOut, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} iDMAC
     * @param {number} iChannel
     * @param {number} port
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     */
    outDMAPageReg(iDMAC, iChannel, port, bOut, addrFrom)
    {
        if (this.messageEnabled(Messages.DMA + Messages.PORT)) {
            this.printMessageIO(port, bOut, addrFrom, "DMA" + iDMAC + ".CHANNEL" + iChannel + ".PAGE", undefined, true);
        }
        this.aDMACs[iDMAC].aChannels[iChannel].bPage = bOut;
    }

    /**
     * inDMAPageSpare(iSpare, port, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} iSpare
     * @param {number} port
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     * @return {number} simulated port value
     */
    inDMAPageSpare(iSpare, port, addrFrom)
    {
        let bIn = this.abDMAPageSpare[iSpare];
        if (this.messageEnabled(Messages.DMA + Messages.PORT)) {
            this.printMessageIO(port, undefined, addrFrom, "DMA.SPARE" + iSpare + ".PAGE", bIn, true);
        }
        return bIn;
    }

    /**
     * outDMAPageSpare(iSpare, port, bOut, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} iSpare
     * @param {number} port
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     */
    outDMAPageSpare(iSpare, port, bOut, addrFrom)
    {
        /*
         * TODO: Remove this DEBUG-only DESKPRO386 code once we're done debugging DeskPro 386 ROMs;
         * it enables logging of all DeskPro 386 ROM checkpoint I/O to port 0x84.
         */
        if (this.messageEnabled(Messages.DMA + Messages.PORT) || DEBUG && (this.model|0) == ChipSet.MODEL_COMPAQ_DESKPRO386) {
            this.printMessageIO(port, bOut, addrFrom, "DMA.SPARE" + iSpare + ".PAGE", undefined, true);
        }
        this.abDMAPageSpare[iSpare] = bOut;
    }

    /**
     * checkDMA(iDMAChannel)
     *
     * @param {number} iDMAChannel
     * @return {number} (current transfer address; may be used by the FDC for bootstrapping tests)
     */
    checkDMA(iDMAChannel)
    {
        let iDMAC = iDMAChannel >> 2;
        let controller = this.aDMACs[iDMAC];

        let iChannel = iDMAChannel & 0x3;
        let channel = controller.aChannels[iChannel];

        return (channel.bPage << 16) | (channel.addrCurrent[1] << 8) | channel.addrCurrent[0];
    }

    /**
     * connectDMA(iDMAChannel, component, sFunction, obj)
     *
     * @param {number} iDMAChannel
     * @param {Component|string} component
     * @param {string} sFunction
     * @param {Object} obj (eg, when the HDC connects, it passes a drive object)
     */
    connectDMA(iDMAChannel, component, sFunction, obj)
    {
        let iDMAC = iDMAChannel >> 2;
        let controller = this.aDMACs[iDMAC];

        let iChannel = iDMAChannel & 0x3;
        let channel = controller.aChannels[iChannel];

        this.initDMAFunction(channel, component, sFunction, obj);
    }

    /**
     * requestDMA(iDMAChannel, done)
     *
     * @this {ChipSet}
     * @param {number} iDMAChannel
     * @param {function(boolean)} [done]
     *
     * For DMA_MODE.TYPE_WRITE transfers, fnTransfer(-1) must return bytes as long as we request them (although it may
     * return -1 if it runs out of bytes prematurely).
     *
     * Similarly, for DMA_MODE.TYPE_READ transfers, fnTransfer(b) must accept bytes as long as we deliver them (although
     * it is certainly free to ignore bytes it no longer wants).
     */
    requestDMA(iDMAChannel, done)
    {
        let iDMAC = iDMAChannel >> 2;
        let controller = this.aDMACs[iDMAC];

        let iChannel = iDMAChannel & 0x3;
        let channel = controller.aChannels[iChannel];

        if (!channel.component || !channel.fnTransfer || !channel.obj) {
            if (DEBUG) this.printf(Messages.DMA + Messages.DATA, "requestDMA(%d): not connected to a component\n", iDMAChannel);
            if (done) done(true);
            return;
        }

        /*
         * We can't simply slam done into channel.done; that would be fine if requestDMA() was called only by functions
         * like HDC.doRead() and HDC.doWrite(), but we're also called whenever a DMA channel is unmasked, and in those cases,
         * we need to preserve whatever handler may have been previously set.
         *
         * However, in an effort to ensure we don't end up with stale done handlers, connectDMA() will reset channel.done.
         */
        if (done) channel.done = done;

        if (channel.masked) {
            if (DEBUG) this.printf(Messages.DMA + Messages.DATA, "requestDMA(%d): channel masked, request queued\n", iDMAChannel);
            return;
        }

        /*
         * Let's try to do async DMA without asking the CPU for help...
         *
         *      this.cpu.setDMA(true);
         */
        this.advanceDMA(channel, true);
    }

    /**
     * advanceDMA(channel, fInit)
     *
     * @this {ChipSet}
     * @param {Object} channel
     * @param {boolean} [fInit]
     */
    advanceDMA(channel, fInit)
    {
        if (fInit) {
            channel.count = (channel.countCurrent[1] << 8) | channel.countCurrent[0];
            channel.type = (channel.mode & ChipSet.DMA_MODE.TYPE);
            channel.fWarning = channel.fError = false;
            if (DEBUG && DEBUGGER) {
                channel.cbDebug = channel.count + 1;
                channel.sAddrDebug = (DEBUG && DEBUGGER? null : undefined);
            }
        }
        /*
         * To support async DMA without requiring help from the CPU (ie, without relying upon cpu.setDMA()), we require that
         * the data transfer functions provide an fAsync parameter to their callbacks; fAsync must be true if the callback was
         * truly asynchronous (ie, it had to wait for a remote I/O request to finish), or false if the data was already available
         * and the callback was performed synchronously.
         *
         * Whenever a callback is issued asynchronously, we will immediately daisy-chain another pair of updateDMA()/advanceDMA()
         * calls, which will either finish the DMA operation if no more remote I/O requests are required, or will queue up another
         * I/O request, which will in turn trigger another async callback.  Thus, the DMA request keeps itself going without
         * requiring any special assistance from the CPU via setDMA().
         */
        let bto = null;
        let chipset = this;
        let fAsyncRequest = false;
        let controller = channel.controller;
        let iDMAChannel = controller.nChannelBase + channel.iChannel;

        while (true) {
            if (channel.count >= 0) {
                let b;
                let addr = (channel.bPage << 16) | (channel.addrCurrent[1] << 8) | channel.addrCurrent[0];
                if (DEBUG && DEBUGGER && channel.sAddrDebug === null) {
                    channel.sAddrDebug = Str.toHex(addr >> 4, 4) + ":" + Str.toHex(addr & 0xf, 4);
                    if (channel.type != ChipSet.DMA_MODE.TYPE_WRITE && this.messageEnabled(this.messageBitsDMA(iDMAChannel))) {
                        this.printf(Messages.ALL, "advanceDMA(%d) transferring %d bytes from %s\n", iDMAChannel, channel.cbDebug, channel.sAddrDebug);
                        this.dbg.doDump(["db", channel.sAddrDebug, "l" + channel.cbDebug]);
                    }
                }
                if (channel.type == ChipSet.DMA_MODE.TYPE_WRITE) {
                    fAsyncRequest = true;
                    (function advanceDMAWrite(addrCur) {
                        channel.fnTransfer.call(channel.component, channel.obj, -1, function onTransferDMA(b, fAsync, obj, off) {
                            if (b < 0) {
                                if (!channel.fWarning) {
                                    if (DEBUG) chipset.printf(Messages.DMA, "advanceDMA(%d) ran out of data, assuming 0xff\n", iDMAChannel);
                                    channel.fWarning = true;
                                }
                                /*
                                 * TODO: Determine whether to abort, as we do for DMA_MODE.TYPE_READ.
                                 */
                                b = 0xff;
                            }
                            if (!channel.masked && !channel.fError) {
                                chipset.bus.setByte(addrCur, b);
                                /*
                                 * WARNING: Do NOT assume that obj is valid; if the sector data was not found, there will be no obj.
                                 */
                                if (BACKTRACK && obj) {
                                    if (!off && obj.file) {
                                        chipset.printf(Messages.DISK, "loading %s[%#0X] at %%%0X\n", obj.file.path, obj.offFile, addrCur);
                                        /*
                                        if (obj.file.path == "\\SYSBAS.EXE" && obj.offFile == 512) {
                                            chipset.cpu.stopCPU();
                                        }
                                        */
                                    }
                                    bto = chipset.bus.addBackTrackObject(obj, bto, off);
                                    chipset.bus.writeBackTrackObject(addrCur, bto, off);
                                }
                            }
                            fAsyncRequest = fAsync;
                            if (fAsync) {
                                setTimeout(function() {
                                    if (!chipset.updateDMA(channel)) chipset.advanceDMA(channel);
                                }, 0);
                            }
                        });
                    }(addr));
                }
                else if (channel.type == ChipSet.DMA_MODE.TYPE_READ) {
                    /*
                     * TODO: Determine whether we should support async dmaWrite() functions (currently not required)
                     */
                    b = chipset.bus.getByte(addr);
                    if (channel.fnTransfer.call(channel.component, channel.obj, b) < 0) {
                        /*
                         * In this case, I think I have no choice but to terminate the DMA operation in response to a failure,
                         * because the ROM BIOS FDC.REG_DATA.CMD.FORMAT_TRACK command specifies a count that is MUCH too large
                         * (a side-effect of the ROM BIOS using the same "DMA_SETUP" code for reads, writes AND formats).
                         */
                        channel.fError = true;
                    }
                }
                else if (channel.type == ChipSet.DMA_MODE.TYPE_VERIFY) {
                    /*
                     * Nothing to read or write; just call updateDMA()
                     */
                }
                else {
                    if (DEBUG) this.printf(Messages.DMA + Messages.WARN, "advanceDMA(%d) unsupported transfer type %#06X\n", iDMAChannel, channel.type);
                    channel.fError = true;
                }
            }
            if (fAsyncRequest || this.updateDMA(channel)) break;
        }
    }

    /**
     * updateDMA(channel)
     *
     * @this {ChipSet}
     * @param {Object} channel
     * @return {boolean} true if DMA operation complete, false if not
     */
    updateDMA(channel)
    {
        if (!channel.fError && --channel.count >= 0) {
            if (channel.mode & ChipSet.DMA_MODE.DECREMENT) {
                channel.addrCurrent[0]--;
                if (channel.addrCurrent[0] < 0) {
                    channel.addrCurrent[0] = 0xff;
                    channel.addrCurrent[1]--;
                    if (channel.addrCurrent[1] < 0) channel.addrCurrent[1] = 0xff;
                }
            } else {
                channel.addrCurrent[0]++;
                if (channel.addrCurrent[0] > 0xff) {
                    channel.addrCurrent[0] = 0x00;
                    channel.addrCurrent[1]++;
                    if (channel.addrCurrent[1] > 0xff) channel.addrCurrent[1] = 0x00;
                }
            }
            /*
             * In situations where an HDC DMA operation took too long, the Fixed Disk BIOS would give up, but the DMA operation would continue.
             *
             * TODO: Verify that the Fixed Disk BIOS shuts down (ie, re-masks) a DMA channel for failed requests, and that this handles those failures.
             */
            if (!channel.masked) return false;
        }

        let controller = channel.controller;
        let iDMAChannel = controller.nChannelBase + channel.iChannel;
        controller.bStatus = (controller.bStatus & ~(0x10 << channel.iChannel)) | (0x1 << channel.iChannel);

        /*
         * EOP is supposed to automatically (re)mask the channel, unless it's set for auto-initialize.
         */
        if (!(channel.mode & ChipSet.DMA_MODE.AUTOINIT)) {
            channel.masked = true;
            channel.component = channel.obj = null;
        }

        if (DEBUG && channel.type == ChipSet.DMA_MODE.TYPE_WRITE && channel.sAddrDebug && this.messageEnabled(this.messageBitsDMA(iDMAChannel))) {
            this.printf(Messages.ALL, "updateDMA(%d) transferred %d bytes to %s\n", iDMAChannel, channel.cbDebug, channel.sAddrDebug);
            this.dbg.doDump(["db", channel.sAddrDebug, "l" + channel.cbDebug]);
        }

        if (channel.done) {
            channel.done(!channel.fError);
            channel.done = null;
        }

        /*
         * While it might make sense to call cpu.setDMA() here, it's simpler to let the CPU issue one more call
         * to chipset.checkDMA() and let the CPU update INTR.DMA on its own, based on the return value from checkDMA().
         */
        return true;
    }

    /**
     * inPICLo(iPIC, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} iPIC
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     * @return {number} simulated port value
     */
    inPICLo(iPIC, addrFrom)
    {
        let b = 0;
        let pic = this.aPICs[iPIC];
        if (pic.bOCW3 != null) {
            let bReadReg = pic.bOCW3 & ChipSet.PIC_LO.OCW3_READ_CMD;
            switch (bReadReg) {
                case ChipSet.PIC_LO.OCW3_READ_IRR:
                    b = pic.bIRR;
                    break;
                case ChipSet.PIC_LO.OCW3_READ_ISR:
                    b = pic.bISR;
                    break;
                default:
                    break;
            }
        }
        if (this.messageEnabled(Messages.PIC + Messages.PORT)) {
            this.printMessageIO(pic.port, undefined, addrFrom, "PIC" + iPIC, b, true);
        }
        return b;
    }

    /**
     * outPICLo(iPIC, bOut, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} iPIC
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     */
    outPICLo(iPIC, bOut, addrFrom)
    {
        let pic = this.aPICs[iPIC];
        if (this.messageEnabled(Messages.PIC + Messages.PORT)) {
            this.printMessageIO(pic.port, bOut, addrFrom, "PIC" + iPIC, undefined, true);
        }
        if (bOut & ChipSet.PIC_LO.ICW1) {
            /*
             * This must be an ICW1...
             */
            pic.nICW = 0;
            pic.aICW[pic.nICW++] = bOut;
            /*
             * I used to do the rest of this initialization in outPICHi(), once all the ICW commands had been received,
             * but a closer reading of the 8259A spec indicates that that should happen now, on receipt on ICW1.
             *
             * Also, on p.10 of that spec, it says "The Interrupt Mask Register is cleared".  I originally took that to
             * mean that all interrupts were masked, but based on what MS-DOS 4.0M expects to happen after this code runs:
             *
             *      0070:44C6 B013          MOV      AL,13
             *      0070:44C8 E620          OUT      20,AL
             *      0070:44CA B050          MOV      AL,50
             *      0070:44CC E621          OUT      21,AL
             *      0070:44CE B009          MOV      AL,09
             *      0070:44D0 E621          OUT      21,AL
             *
             * (ie, it expects its next call to INT 0x13 will still generate an interrupt), I've decided the spec
             * must be read literally, meaning that all IMR bits must be zeroed.  Unmasking all possible interrupts by
             * default seems unwise to me, but who am I to judge....
             */
            pic.bIMR = 0x00;
            pic.bIRLow = 7;
            /*
             * TODO: I'm also zeroing both IRR and ISR, even though that's not actually mentioned as part of the ICW
             * sequence, because they need to be (re)initialized at some point.  However, if some component is currently
             * requesting an interrupt, what should I do about that?  Originally, I had decided to clear them ONLY if they
             * were still undefined, but that change appeared to break the ROM BIOS handling of CTRL-ALT-DEL, so I'm back
             * to unconditionally zeroing them.
             */
            pic.bIRR = pic.bISR = 0;
            /*
             * The spec also says that "Special Mask Mode is cleared and Status Read is set to IRR".  I attempt to insure
             * the latter, but as for special mask mode... well, that mode isn't supported yet.
             */
            pic.bOCW3 = ChipSet.PIC_LO.OCW3 | ChipSet.PIC_LO.OCW3_READ_IRR;
        }
        else if (!(bOut & ChipSet.PIC_LO.OCW3)) {
            /*
             * This must be an OCW2...
             */
            let bOCW2 = bOut & ChipSet.PIC_LO.OCW2_OP_MASK;
            if (bOCW2 & ChipSet.PIC_LO.OCW2_EOI) {
                /*
                 * This OCW2 must be an EOI command...
                 */
                let nIRL, bIREnd = 0;
                if ((bOCW2 & ChipSet.PIC_LO.OCW2_EOI_SPEC) == ChipSet.PIC_LO.OCW2_EOI_SPEC) {
                    /*
                     * More "specifically", a specific EOI command...
                     */
                    nIRL = bOut & ChipSet.PIC_LO.OCW2_IR_LVL;
                    bIREnd = 1 << nIRL;
                } else {
                    /*
                     * Less "specifically", a non-specific EOI command.  The search for the highest priority in-service
                     * interrupt must start with whichever interrupt is opposite the lowest priority interrupt (normally 7,
                     * but technically whatever bIRLow is currently set to).  For example:
                     *
                     *      If bIRLow is 7, then the priority order is: 0, 1, 2, 3, 4, 5, 6, 7.
                     *      If bIRLow is 6, then the priority order is: 7, 0, 1, 2, 3, 4, 5, 6.
                     *      If bIRLow is 5, then the priority order is: 6, 7, 0, 1, 2, 3, 4, 5.
                     *      etc.
                     */
                    nIRL = pic.bIRLow + 1;
                    while (true) {
                        nIRL &= 0x7;
                        let bIR = 1 << nIRL;
                        if (pic.bISR & bIR) {
                            bIREnd = bIR;
                            break;
                        }
                        if (nIRL++ == pic.bIRLow) break;
                    }
                    if (DEBUG && !bIREnd) nIRL = null;      // for unexpected non-specific EOI commands, there's no IRQ to report
                }
                let nIRQ = (nIRL == null? undefined : pic.nIRQBase + nIRL);
                if (pic.bISR & bIREnd) {
                    if (DEBUG && this.dbg) this.printf(this.messageBitsIRQ(nIRQ), "outPIC%d(%#04X): IRQ %d ending @%s stack=%s\n",  iPIC, pic.port, nIRQ, this.dbg.toHexOffset(this.cpu.getIP(), this.cpu.getCS()), this.dbg.toHexOffset(this.cpu.getSP(), this.cpu.getSS()));
                    pic.bISR &= ~bIREnd;
                    this.checkIRR();
                } else {
                    if (DEBUG) {
                        this.printf(Messages.PIC + Messages.WARN + Messages.ADDRESS, "outPIC%d(%#04X): unexpected EOI for IRQ %d\n", iPIC, pic.port, nIRQ);
                        if (MAXDEBUG && this.dbg) this.dbg.stopCPU();
                    }
                }
                /*
                 * TODO: Support EOI commands with automatic rotation (eg, ChipSet.PIC_LO.OCW2_EOI_ROT and ChipSet.PIC_LO.OCW2_EOI_ROTSPEC)
                 */
                if (bOCW2 & ChipSet.PIC_LO.OCW2_SET_ROTAUTO) {
                    this.printf(Messages.PIC + Messages.WARN + Messages.ADDRESS, "outPIC%d(%#04X): unsupported OCW2 rotate %#04X\n", iPIC, pic.port, bOut);
                }
            }
            else  if (bOCW2 == ChipSet.PIC_LO.OCW2_SET_PRI) {
                /*
                 * This OCW2 changes the lowest priority interrupt to the specified level (the default is 7)
                 */
                pic.bIRLow = bOut & ChipSet.PIC_LO.OCW2_IR_LVL;
            }
            else {
                /*
                 * TODO: Remaining commands to support: ChipSet.PIC_LO.OCW2_SET_ROTAUTO and ChipSet.PIC_LO.OCW2_CLR_ROTAUTO
                 */
                this.printf(Messages.PIC + Messages.WARN + Messages.ADDRESS, "outPIC%d(%#04X): unsupported OCW2 automatic rotate %#04X\n", iPIC, pic.port, bOut);
            }
        } else {
            /*
             * This must be an OCW3 request. If it's a "Read Register" command (PIC_LO.OCW3_READ_CMD), inPICLo() will take care it.
             *
             * TODO: If OCW3 specified a "Poll" command (PIC_LO.OCW3_POLL_CMD) or a "Special Mask Mode" command (PIC_LO.OCW3_SMM_CMD),
             * that's unfortunate, because I don't support them yet.
             */
            if (bOut & (ChipSet.PIC_LO.OCW3_POLL_CMD | ChipSet.PIC_LO.OCW3_SMM_CMD)) {
                this.printf(Messages.PIC + Messages.WARN + Messages.ADDRESS, "outPIC%d(%#04X): unsupported OCW3 %#04X\n", iPIC, pic.port, bOut);
            }
            pic.bOCW3 = bOut;
        }
    }

    /**
     * inPICHi(iPIC, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} iPIC
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     * @return {number} simulated port value
     */
    inPICHi(iPIC, addrFrom)
    {
        let pic = this.aPICs[iPIC];
        let b = pic.bIMR;
        if (this.messageEnabled(Messages.PIC + Messages.PORT)) {
            this.printMessageIO(pic.port+1, undefined, addrFrom, "PIC" + iPIC, b, true);
        }
        return b;
    }

    /**
     * outPICHi(iPIC, bOut, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} iPIC
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     */
    outPICHi(iPIC, bOut, addrFrom)
    {
        let pic = this.aPICs[iPIC];
        if (this.messageEnabled(Messages.PIC + Messages.PORT)) {
            this.printMessageIO(pic.port+1, bOut, addrFrom, "PIC" + iPIC, undefined, true);
        }
        if (pic.nICW < pic.aICW.length) {
            pic.aICW[pic.nICW++] = bOut;
            if (pic.nICW == 2 && (pic.aICW[0] & ChipSet.PIC_LO.ICW1_SNGL))
                pic.nICW++;
            if (pic.nICW == 3 && !(pic.aICW[0] & ChipSet.PIC_LO.ICW1_ICW4))
                pic.nICW++;
        }
        else {
            /*
             * We have all our ICW "words" (ie, bytes), so this must be an OCW1 write (which is simply an IMR write)
             */
            pic.bIMR = bOut;
            /*
             * See the CPU's delayINTR() function for an explanation of why this explicit delay is necessary.
             */
            this.cpu.delayINTR();
            /*
             * Alas, we need a longer delay for the MODEL_5170's "KBD_RESET" function (F000:17D2), which must drop
             * into a loop and decrement CX at least once after unmasking the KBD IRQ.  The "KBD_RESET" function on
             * previous models could be handled with a 4-instruction delay provided by the Keyboard.resetDevice() call
             * to setIRR(), but the MODEL_5170 needs a roughly 6-instruction delay after it unmasks the KBD IRQ.
             */
            this.checkIRR(!iPIC && bOut == 0xFD? 6 : 0);
        }
    }

    /**
     * checkIMR(nIRQ)
     *
     * @this {ChipSet}
     * @param {number} nIRQ
     * @return {boolean} true if the specified IRQ is masked, false if not
     */
    checkIMR(nIRQ)
    {
        let iPIC = nIRQ >> 3;
        let nIRL = nIRQ & 0x7;
        let pic = this.aPICs[iPIC];
        return !!(pic.bIMR & (0x1 << nIRL));
    }

    /**
     * setIRR(nIRQ, nDelay)
     *
     * @this {ChipSet}
     * @param {number} nIRQ (IRQ 0-7 implies iPIC 0, and IRQ 8-15 implies iPIC 1)
     * @param {number} [nDelay] is an optional number of instructions to delay acknowledgment of the IRQ (see getIRRVector)
     */
    setIRR(nIRQ, nDelay)
    {
        let iPIC = nIRQ >> 3;
        let nIRL = nIRQ & 0x7;
        let pic = this.aPICs[iPIC];
        let bIRR = (1 << nIRL);
        if (!(pic.bIRR & bIRR)) {
            pic.bIRR |= bIRR;
            this.printf(this.messageBitsIRQ(nIRQ), "set IRQ %d\n", nIRQ);
            pic.nDelay = nDelay || 0;
            this.checkIRR();
        }
    }

    /**
     * clearIRR(nIRQ)
     *
     * @this {ChipSet}
     * @param {number} nIRQ (IRQ 0-7 implies iPIC 0, and IRQ 8-15 implies iPIC 1)
     */
    clearIRR(nIRQ)
    {
        let iPIC = nIRQ >> 3;
        let nIRL = nIRQ & 0x7;
        let pic = this.aPICs[iPIC];
        let bIRR = (1 << nIRL);
        if (pic.bIRR & bIRR) {
            pic.bIRR &= ~bIRR;
            this.printf(this.messageBitsIRQ(nIRQ), "clear IRQ %d\n", nIRQ);
            this.checkIRR();
        }
    }

    /**
     * checkIRR(nDelay)
     *
     * @this {ChipSet}
     * @param {number} [nDelay] is an optional number of instructions to delay acknowledgment of a pending interrupt
     */
    checkIRR(nDelay)
    {
        /*
         * Look for any IRR bits that aren't masked and aren't already in service; in theory, all we'd have to
         * check is the master PIC (which is the *only* PIC on pre-5170 models), because when any IRQs are set or
         * cleared on the slave, that would automatically be reflected in IRQ.SLAVE on the master; that's what
         * setIRR() and clearIRR() used to do.
         *
         * Unfortunately, despite setIRR() and clearIRR()'s efforts, whenever a slave interrupt is acknowledged,
         * getIRRVector() ends up clearing the IRR bits for BOTH the slave's IRQ and the master's IRQ.SLAVE.
         * So if another lower-priority slave IRQ is waiting to be dispatched, that fact is no longer reflected
         * in IRQ.SLAVE.
         *
         * Since checkIRR() is called on every EOI, we can resolve that problem here, by first checking the slave
         * PIC for any unmasked, unserviced interrupts and updating the master's IRQ.SLAVE.
         *
         * And since this is ALSO called by both setIRR() and clearIRR(), those functions no longer need to perform
         * their own IRQ.SLAVE updates.  This function consolidates the propagation of slave interrupts to the master.
         */
        let pic;
        let bIR = -1;

        if (this.cPICs > 1) {
            pic = this.aPICs[1];
            bIR = ~(pic.bISR | pic.bIMR) & pic.bIRR;
        }

        pic = this.aPICs[0];

        if (bIR >= 0) {
            if (bIR) {
                pic.bIRR |= (1 << ChipSet.IRQ.SLAVE);
            } else {
                pic.bIRR &= ~(1 << ChipSet.IRQ.SLAVE);
            }
        }

        bIR = ~(pic.bISR | pic.bIMR) & pic.bIRR;

        this.cpu.updateINTR(!!bIR);

        if (bIR && nDelay) pic.nDelay = nDelay;
    }

    /**
     * getIRRVector()
     *
     * getIRRVector() is called by the CPU whenever PS_IF is set and OP_NOINTR is clear.  Ordinarily, an immediate
     * response would seem perfectly reasonable, but unfortunately, there are places in the original ROM BIOS like
     * "KBD_RESET" (F000:E688) that enable interrupts but still expect nothing to happen for several more instructions.
     *
     * So, in addition to the two normal responses (an IDT vector #, or -1 indicating no pending interrupts), we must
     * support a third response (-2) that basically means: don't change the CPU interrupt state, just keep calling until
     * we return one of the first two responses.  The number of times we delay our normal response is determined by the
     * component that originally called setIRR with an optional delay parameter.
     *
     * @this {ChipSet}
     * @param {number} [iPIC]
     * @return {number} IDT vector # of the next highest-priority interrupt, -1 if none, or -2 for "please try your call again later"
     */
    getIRRVector(iPIC)
    {
        if (iPIC === undefined) iPIC = 0;

        /*
         * Look for any IRR bits that aren't masked and aren't already in service...
         */
        let nIDT = -1;
        let pic = this.aPICs[iPIC];
        if (!pic.nDelay) {
            let bIR = pic.bIRR & ((pic.bISR | pic.bIMR) ^ 0xff);
            /*
             * The search for the next highest priority requested interrupt (that's also not in-service and not masked)
             * must start with whichever interrupt is opposite the lowest priority interrupt (normally 7, but technically
             * whatever bIRLow is currently set to).  For example:
             *
             *      If bIRLow is 7, then the priority order is: 0, 1, 2, 3, 4, 5, 6, 7.
             *      If bIRLow is 6, then the priority order is: 7, 0, 1, 2, 3, 4, 5, 6.
             *      If bIRLow is 5, then the priority order is: 6, 7, 0, 1, 2, 3, 4, 5.
             *      etc.
             *
             * This process is similar to the search performed by non-specific EOIs, except those apply only to a single
             * PIC (which is why a slave interrupt must be EOI'ed twice: once for the slave PIC and again for the master),
             * whereas here we must search across all PICs.
             */
            let nIRL = pic.bIRLow + 1;
            while (true) {

                nIRL &= 0x7;
                let bIRNext = 1 << nIRL;

                /*
                 * If we encounter an interrupt that's still in-service BEFORE we encounter a requested interrupt,
                 * then we're done; we must allow a higher priority in-service interrupt to finish before acknowledging
                 * any lower priority interrupts.
                 */
                if (pic.bISR & bIRNext) break;

                if (bIR & bIRNext) {

                    if (!iPIC && nIRL == ChipSet.IRQ.SLAVE && this.aPICs.length > 1) {
                        /*
                         * Slave interrupts are tied to the master PIC on IRQ2; query the slave PIC for the vector #
                         */
                        nIDT = this.getIRRVector(1);
                    } else {
                        /*
                         * Get the starting IDT vector # from ICW2 and add the IR level to obtain the target IDT vector #
                         */
                        nIDT = pic.aICW[1] + nIRL;
                    }

                    if (nIDT >= 0) {
                        pic.bISR |= bIRNext;

                        /*
                         * Setting the ISR implies clearing the IRR, but clearIRR() has side-effects we don't want
                         * (eg, clearing the slave IRQ, notifying the CPU, etc), so we clear the IRR ourselves.
                         */
                        pic.bIRR &= ~bIRNext;

                        let nIRQ = pic.nIRQBase + nIRL;
                        if (DEBUG && this.dbg) this.printf(this.messageBitsIRQ(nIRQ) + Messages.ADDRESS, "getIRRVector(): IRQ %d interrupting stack %s\n", nIRQ, this.dbg.toHexOffset(this.cpu.getSP(), this.cpu.getSS()));
                        if (MAXDEBUG && DEBUGGER) this.acInterrupts[nIRQ]++;
                    }
                    break;
                }

                if (nIRL++ == pic.bIRLow) break;
            }
        } else {
            nIDT = -2;
            pic.nDelay--;
        }
        return nIDT;
    }

    /**
     * setFPUInterrupt()
     *
     * @this {ChipSet}
     */
    setFPUInterrupt()
    {
        if (this.model >= ChipSet.MODEL_5170) {
            this.setIRR(ChipSet.IRQ.FPU);
        } else {
            /*
             * TODO: Determine whether we need to maintain an "Active NMI" state; ie, if NMI.DISABLE is cleared
             * later, and the FPU coprocessor is still indicating an error condition, should we then generate an NMI?
             */
            if (this.bNMI & ChipSet.NMI.ENABLE) {
                X86.helpInterrupt.call(this.cpu, X86.EXCEPTION.NMI);
            }
        }
    }

    /**
     * clearFPUInterrupt(fSet)
     *
     * @this {ChipSet}
     */
    clearFPUInterrupt()
    {
        if (this.model >= ChipSet.MODEL_5170) {
            this.clearIRR(ChipSet.IRQ.FPU);
        } else {
            /*
             * TODO: If we maintain an "Active NMI" state, then we will need code here to clear that state, as well
             * as code in outNMI() to clear that state and generate an NMI as needed.
             */
        }
    }

    /**
     * inTimer(iPIT, iPITTimer, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} iPIT (0 or 1)
     * @param {number} iPITTimer (0, 1, or 2)
     * @param {number} port (0x40, 0x41, 0x42, etc)
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     * @return {number} simulated port value
     */
    inTimer(iPIT, iPITTimer, port, addrFrom)
    {
        let b;
        let iBaseTimer = (iPIT? 3 : 0);
        let timer = this.aTimers[iBaseTimer + iPITTimer];

        if (timer.fStatusLatched) {
            b = timer.bStatus;
            timer.fStatusLatched = false;
        }
        else {
            if (timer.countIndex == timer.countBytes) {
                this.resetTimerIndex(iBaseTimer + iPITTimer);
            }
            if (timer.fCountLatched) {
                b = timer.countLatched[timer.countIndex++];
                if (timer.countIndex == timer.countBytes) {
                    timer.fCountLatched = false
                }
            }
            else {
                this.updateTimer(iBaseTimer + iPITTimer);
                b = timer.countCurrent[timer.countIndex++];
            }
        }
        if (this.messageEnabled(Messages.TIMER + Messages.PORT)) {
            this.printMessageIO(port, undefined, addrFrom, "PIT" + iPIT + ".TIMER" + iPITTimer, b, true);
        }
        return b;
    }

    /**
     * outTimer(iPIT, iPITTimer, port, bOut, addrFrom)
     *
     * We now rely EXCLUSIVELY on setBurstCycles() to address situations where quick timer interrupt turn-around
     * is expected; eg, by the ROM BIOS POST when it sets TIMER0 to a low test count (0x16); since we typically
     * don't update any of the timers until after we've finished a burst of CPU cycles, we must reduce the current
     * burst cycle count, so that the current instruction burst will end at the same time a timer interrupt is expected.
     *
     * @this {ChipSet}
     * @param {number} iPIT (0 or 1)
     * @param {number} iPITTimer (0, 1, or 2)
     * @param {number} port (0x40, 0x41, 0x42, etc)
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     */
    outTimer(iPIT, iPITTimer, port, bOut, addrFrom)
    {
        if (this.messageEnabled(Messages.TIMER + Messages.PORT)) {
            this.printMessageIO(port, bOut, addrFrom, "PIT" + iPIT + ".TIMER" + iPITTimer, undefined, true);
        }

        let iBaseTimer = (iPIT? 3 : 0);
        let timer = this.aTimers[iBaseTimer + iPITTimer];

        if (timer.countIndex == timer.countBytes) {
            this.resetTimerIndex(iBaseTimer + iPITTimer);
        }

        timer.countInit[timer.countIndex++] = bOut;

        if (timer.countIndex == timer.countBytes) {
            /*
             * In general, writing a new count to a timer that's already counting isn't supposed to affect the current
             * count, with the notable exceptions of MODE0 and MODE4.
             */
            if (!timer.fCounting || timer.mode == ChipSet.PIT_CTRL.MODE0 || timer.mode == ChipSet.PIT_CTRL.MODE4) {
                timer.fCountLatched = false;
                timer.countCurrent[0] = timer.countStart[0] = timer.countInit[0];
                timer.countCurrent[1] = timer.countStart[1] = timer.countInit[1];
                timer.nCyclesStart = this.cpu.getCycles(this.fScaleTimers);
                timer.fCounting = true;

                /*
                 * I believe MODE0 is the only mode where OUT (fOUT) starts out low (false); for the rest of the modes,
                 * OUT (fOUT) starts high (true).  It's also my understanding that the way edge-triggered interrupts work
                 * on the original PC is that an interrupt is requested only when the corresponding OUT transitions from
                 * low to high.
                 */
                timer.fOUT = (timer.mode != ChipSet.PIT_CTRL.MODE0);

                if (iPIT == ChipSet.PIT0.INDEX && iPITTimer == ChipSet.PIT0.TIMER0) {
                    /*
                     * TODO: Determine if there are situations/modes where I should NOT automatically clear IRQ0 on behalf of TIMER0.
                     */
                    this.clearIRR(ChipSet.IRQ.TIMER0);
                    let countInit = this.getTimerInit(ChipSet.PIT0.TIMER0);
                    let nCyclesRemain = (countInit * this.nTicksDivisor) | 0;
                    if (timer.mode == ChipSet.PIT_CTRL.MODE3) nCyclesRemain >>= 1;
                    this.cpu.setBurstCycles(nCyclesRemain);
                }
            }

            if (iPIT == ChipSet.PIT0.INDEX && iPITTimer == ChipSet.PIT0.TIMER2) this.setSpeaker();
        }
    }

    /**
     * inTimerCtrl(iPIT, port, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} iPIT (0 or 1)
     * @param {number} port (0x43 or 0x4B)
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     * @return {number|null} simulated port value
     */
    inTimerCtrl(iPIT, port, addrFrom)
    {
        this.printMessageIO(port, undefined, addrFrom, "PIT" + iPIT + ".CTRL", undefined, Messages.TIMER);
        /*
         * NOTE: Even though reads to port 0x43 are undefined (I think), I'm going to "define" it
         * as returning the last value written, purely for the Debugger's benefit.
         */
        return iPIT? this.bPIT1Ctrl : this.bPIT0Ctrl;
    }

    /**
     * outTimerCtrl(iPIT, port, bOut, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} iPIT (0 or 1)
     * @param {number} port (0x43)
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     */
    outTimerCtrl(iPIT, port, bOut, addrFrom)
    {
        this.printMessageIO(port, bOut, addrFrom, "PIT" + iPIT + ".CTRL", undefined, Messages.TIMER);

        /*
         * Extract the SC (Select Counter) bits.
         */
        let iBaseTimer = 0;
        let iPITTimer = (bOut & ChipSet.PIT_CTRL.SC);
        if (!iPIT) {
            this.bPIT0Ctrl = bOut;
        } else {
            iBaseTimer = 3;
            this.bPIT1Ctrl = bOut;
        }

        /*
         * Check for the Read-Back command and process as needed.
         */
        if (iPITTimer == ChipSet.PIT_CTRL.SC_BACK) {
            if (!(bOut & ChipSet.PIT_CTRL.RB_STATUS)) {
                for (iPITTimer = 0; iPITTimer <= 2; iPITTimer++) {
                    if (bOut & (ChipSet.PIT_CTRL.RB_CTR0 << iPITTimer)) {
                        this.latchTimerStatus(iBaseTimer + iPITTimer);
                    }
                }
            }
            if (!(bOut & ChipSet.PIT_CTRL.RB_COUNTS)) {
                for (iPITTimer = 0; iPITTimer <= 2; iPITTimer++) {
                    if (bOut & (ChipSet.PIT_CTRL.RB_CTR0 << iPITTimer)) {
                        this.latchTimerCount(iBaseTimer + iPITTimer);
                    }
                }
            }
            return;
        }

        /*
         * Convert the SC (Select Counter) bits into an iPITTimer index (0-2).
         */
        iPITTimer >>= ChipSet.PIT_CTRL.SC_SHIFT;

        /*
         * Extract BCD (bit 0), MODE (bits 1-3), and RW (bits 4-5), which we simply store as-is (see setTimerMode).
         */
        let bcd = (bOut & ChipSet.PIT_CTRL.BCD);
        let mode = (bOut & ChipSet.PIT_CTRL.MODE);
        let rw = (bOut & ChipSet.PIT_CTRL.RW);

        if (rw == ChipSet.PIT_CTRL.RW_LATCH) {
            /*
             * Of all the RW bit combinations, this is the only one that "countermands" normal control register
             * processing (the BCD and MODE bits are "don't care").
             */
            this.latchTimerCount(iBaseTimer + iPITTimer);
        }
        else {
            this.setTimerMode(iBaseTimer + iPITTimer, bcd, mode, rw);

            /*
             * The 5150 ROM BIOS code @F000:E285 ("TEST.7") would fail after a warm boot (eg, after a CTRL-ALT-DEL) because
             * it assumed that no TIMER0 interrupt would occur between the point it unmasked the TIMER0 interrupt and the
             * point it started reprogramming TIMER0.
             *
             * Similarly, the 5160 ROM BIOS @F000:E35D ("8253 TIMER CHECKOUT") would fail after initializing the EGA BIOS,
             * because the EGA BIOS uses TIMER0 during its diagnostics; as in the previous example, by the time the 8253
             * test code runs later, there's now a pending TIMER0 interrupt, which triggers an interrupt as soon as IRQ0 is
             * unmasked @F000:E364.
             *
             * After looking at this problem at bit more closely the second time around (while debugging the EGA BIOS),
             * it turns out I missed an important 8253 feature: whenever a new MODE0 control word OR a new MODE0 count
             * is written, fOUT (which is what drives IRQ0) goes low.  So, by simply adding an appropriate clearIRR() call
             * both here and in outTimer(), this annoying problem seems to be gone.
             *
             * TODO: Determine if there are situations/modes where I should NOT automatically clear IRQ0 on behalf of TIMER0.
             */
            if (iPIT == ChipSet.PIT0.INDEX && iPITTimer == ChipSet.PIT0.TIMER0) this.clearIRR(ChipSet.IRQ.TIMER0);

            /*
             * Another TIMER0 HACK: The "CASSETTE DATA WRAP TEST" @F000:E51E occasionally reports an error when the second of
             * two TIMER0 counts it latches is greater than the first.  You would think the ROM BIOS would expect this, since
             * TIMER0 can reload its count at any time.  Is the ROM BIOS assuming that TIMER0 was initialized sufficiently
             * recently that this should never happen?  I'm not sure, but for now, let's try resetting TIMER0's count immediately
             * after TIMER2 has been reprogrammed for the test in question (ie, when interrupts are masked and PPIB is set as
             * shown below).
             *
             * FWIW, I believe the cassette hardware was discontinued after MODEL_5150, and even if the test fails, it's non-fatal;
             * the ROM BIOS displays an error (131) and moves on.
             */
            if (iPIT == ChipSet.PIT0.INDEX && iPITTimer == ChipSet.PIT0.TIMER2) {
                let pic = this.aPICs[0];
                if (pic.bIMR == 0xff && this.bPPIB == (ChipSet.PPI_B.CLK_TIMER2 | ChipSet.PPI_B.ENABLE_SW2 | ChipSet.PPI_B.CASS_MOTOR_OFF | ChipSet.PPI_B.CLK_KBD)) {
                    let timer = this.aTimers[0];
                    timer.countStart[0] = timer.countInit[0];
                    timer.countStart[1] = timer.countInit[1];
                    timer.nCyclesStart = this.cpu.getCycles(this.fScaleTimers);
                    if (DEBUG) this.printf(Messages.TIMER, "PIT0.TIMER0 count reset @%d cycles\n", timer.nCyclesStart);
                }
            }
        }
    }

    /**
     * getTimerInit(iTimer)
     *
     * @this {ChipSet}
     * @param {number} iTimer
     * @return {number} initial timer count
     */
    getTimerInit(iTimer)
    {
        let timer = this.aTimers[iTimer];
        let countInit = (timer.countInit[1] << 8) | timer.countInit[0];
        if (!countInit) countInit = (timer.countBytes == 1? 0x100 : 0x10000);
        return countInit;
    }

    /**
     * getTimerStart(iTimer)
     *
     * @this {ChipSet}
     * @param {number} iTimer
     * @return {number} starting timer count (from the initial timer count for the current countdown)
     */
    getTimerStart(iTimer)
    {
        let timer = this.aTimers[iTimer];
        let countStart = (timer.countStart[1] << 8) | timer.countStart[0];
        if (!countStart) countStart = (timer.countBytes == 1? 0x100 : 0x10000);
        return countStart;
    }

    /**
     * getTimerCycleLimit(iTimer, nCycles)
     *
     * This is called by the CPU to determine the maximum number of cycles it can process for the current burst.
     * It's presumed that no instructions have been executed since the last updateTimer(iTimer) call.
     *
     * @this {ChipSet}
     * @param {number} iTimer
     * @param {number} nCycles desired
     * @return {number} maximum number of cycles remaining for the specified timer (<= nCycles)
     */
    getTimerCycleLimit(iTimer, nCycles)
    {
        let timer = this.aTimers[iTimer];
        if (timer.fCounting) {
            let nCyclesUpdate = this.cpu.getCycles(this.fScaleTimers);
            let ticksElapsed = ((nCyclesUpdate - timer.nCyclesStart) / this.nTicksDivisor) | 0;
            // DEBUG:
            let countStart = this.getTimerStart(iTimer);
            let count = countStart - ticksElapsed;
            if (timer.mode == ChipSet.PIT_CTRL.MODE3) count -= ticksElapsed;
            // DEBUG:
            let nCyclesRemain = (count * this.nTicksDivisor) | 0;
            if (timer.mode == ChipSet.PIT_CTRL.MODE3) nCyclesRemain >>= 1;
            if (nCycles > nCyclesRemain) nCycles = nCyclesRemain;
        }
        return nCycles;
    }

    /**
     * latchTimerCount(iTimer)
     *
     * @this {ChipSet}
     * @param {number} iTimer
     */
    latchTimerCount(iTimer)
    {
        /*
         * Update the timer's current count.
         */
        this.updateTimer(iTimer);

        /*
         * Now we can latch it.
         */
        let timer = this.aTimers[iTimer];
        timer.countLatched[0] = timer.countCurrent[0];
        timer.countLatched[1] = timer.countCurrent[1];
        timer.fCountLatched = true;

        /*
         * VERIFY: That a latch request resets the timer index.
         */
        this.resetTimerIndex(iTimer);
    }

    /**
     * latchTimerStatus(iTimer)
     *
     * @this {ChipSet}
     * @param {number} iTimer
     */
    latchTimerStatus(iTimer)
    {
        let timer = this.aTimers[iTimer];
        if (!timer.fStatusLatched) {
            this.updateTimer(iTimer);
            timer.bStatus = timer.bcd | timer.mode | timer.rw | (timer.countIndex < timer.countBytes? ChipSet.PIT_CTRL.RB_NULL : 0) | (timer.fOUT? ChipSet.PIT_CTRL.RB_OUT : 0);
            timer.fStatusLatched = true;
        }
    }

    /**
     * setTimerMode(iTimer, bcd, mode, rw)
     *
     * FYI: After setting a timer's mode, the CPU must set the timer's count before it becomes operational;
     * ie, before fCounting becomes true.
     *
     * @this {ChipSet}
     * @param {number} iTimer
     * @param {number} bcd
     * @param {number} mode
     * @param {number} rw
     */
    setTimerMode(iTimer, bcd, mode, rw)
    {
        let timer = this.aTimers[iTimer];
        timer.rw = rw;
        timer.mode = mode;
        timer.bcd = bcd;
        timer.countInit = [0, 0];
        timer.countCurrent = [0, 0];
        timer.countLatched = [0, 0];
        timer.fOUT = false;
        timer.fCountLatched = false;
        timer.fCounting = false;
        timer.fStatusLatched = false;
        this.resetTimerIndex(iTimer);
    }

    /**
     * resetTimerIndex(iTimer)
     *
     * @this {ChipSet}
     * @param {number} iTimer
     */
    resetTimerIndex(iTimer)
    {
        let timer = this.aTimers[iTimer];
        timer.countIndex = (timer.rw == ChipSet.PIT_CTRL.RW_MSB? 1 : 0);
        timer.countBytes = (timer.rw == ChipSet.PIT_CTRL.RW_BOTH? 2 : 1);
    }

    /**
     * updateTimer(iTimer, fCycleReset)
     *
     * updateTimer() calculates and updates a timer's current count purely on an "on-demand" basis; we don't
     * actually adjust timer counters every 4 CPU cycles on a 4.77Mhz PC, since updating timers that frequently
     * would be prohibitively slow.  If you're single-stepping the CPU, then yes, updateTimer() will be called
     * after every stepCPU(), via updateAllTimers(), but if we're doing our job correctly here, the frequency
     * of calls to updateTimer() should not affect timer counts across otherwise identical runs.
     *
     * TODO: Implement support for all TIMER modes, and verify that all the modes currently implemented are
     * "up to spec"; they're close enough to make the ROM BIOS happy, but beyond that, I've done very little.
     *
     * @this {ChipSet}
     * @param {number} iTimer
     *      0: Time-of-Day interrupt (~18.2 interrupts/second)
     *      1: DMA refresh
     *      2: Sound/Cassette
     * @param {boolean} [fCycleReset] is true if a cycle-count reset is about to occur
     * @return {Timer}
     */
    updateTimer(iTimer, fCycleReset)
    {
        let timer = this.aTimers[iTimer];

        /*
         * Every timer's counting state is gated by its own fCounting flag; TIMER2 is further gated by PPI_B's
         * CLK_TIMER2 bit.
         */
        if (timer.fCounting && (iTimer != ChipSet.PIT0.TIMER2 || (this.bPPIB & ChipSet.PPI_B.CLK_TIMER2))) {
            /*
             * We determine the current timer count based on how many instruction cycles have elapsed since we started
             * the timer.  Timers are supposed to be "ticking" at a rate of 1193181.8181 times per second, which is
             * the system clock of 14.31818Mhz, divided by 12.
             *
             * Similarly, for an 8088, there are supposed to be 4.77Mhz instruction cycles per second, which comes from
             * the system clock of 14.31818Mhz, divided by 3.
             *
             * If we divide 4,772,727 CPU cycles per second by 1,193,181 ticks per second, we get 4 cycles per tick,
             * which agrees with the ratio of the clock divisors: 12 / 3 == 4.
             *
             * However, if getCycles() is being called with fScaleTimers == true AND the CPU is running faster than its
             * base cycles-per-second setting, then getCycles() will divide the cycle count by the CPU's cycle multiplier,
             * so that the timers fire with the same real-world frequency that the user expects.  However, that will
             * break any code (eg, the ROM BIOS diagnostics) that assumes that the timers are ticking once every 4 cycles
             * (or more like every 5 cycles on a 6Mhz 80286).
             *
             * So, when using a machine with the ChipSet "scaleTimers" property set, make sure you reset the machine's
             * speed prior to rebooting, otherwise you're likely to see ROM BIOS errors.  Ditto for any application code
             * that makes similar assumptions about the relationship between CPU and timer speeds.
             *
             * In general, you're probably better off NOT using the "scaleTimers" property, and simply allowing the timers
             * to tick faster as you increase CPU speed (which is why fScaleTimers defaults to false).
             */
            let nCycles = this.cpu.getCycles(this.fScaleTimers);

            /*
             * Instead of maintaining partial tick counts, we calculate a fresh countCurrent from countStart every
             * time we're called, using the cycle count recorded when the timer was initialized.  countStart is set
             * to countInit when fCounting is first set, and then it is refreshed from countInit at the expiration of
             * every count, so that if someone loaded a new countInit in the meantime (eg, BASICA), we'll pick it up.
             *
             * For the original MODEL_5170, the number of cycles per tick is approximately 6,000,000 / 1,193,181,
             * or 5.028575, so we can no longer always divide cycles by 4 with a simple right-shift by 2.  The proper
             * divisor (eg, 4 for MODEL_5150 and MODEL_5160, 5 for MODEL_5170, etc) is nTicksDivisor, which initBus()
             * calculates using the base CPU speed returned by cpu.getBaseCyclesPerSecond().
             */
            let ticksElapsed = ((nCycles - timer.nCyclesStart) / this.nTicksDivisor) | 0;

            if (ticksElapsed < 0) {
                if (DEBUG) this.printf(Messages.TIMER, "updateTimer(%d): negative tick count (%d)\n", iTimer, ticksElapsed);
                timer.nCyclesStart = nCycles;
                ticksElapsed = 0;
            }

            let countInit = this.getTimerInit(iTimer);
            let countStart = this.getTimerStart(iTimer);

            let fFired = false;
            let count = countStart - ticksElapsed;

            /*
             * NOTE: This mode is used by ROM BIOS test code that wants to verify timer interrupts are arriving
             * neither too slowly nor too quickly.  As a result, I've had to add some corresponding trickery
             * in outTimer() to force interrupt simulation immediately after a low initial count (0x16) has been set.
             */
            if (timer.mode == ChipSet.PIT_CTRL.MODE0) {
                if (count <= 0) count = 0;
                if (DEBUG) this.printf(Messages.TIMER, "updateTimer(%d): MODE0 timer count=%d\n" + iTimer, count);
                if (!count) {
                    timer.fOUT = true;
                    timer.fCounting = false;
                    if (!iTimer) {
                        fFired = true;
                        this.setIRR(ChipSet.IRQ.TIMER0);
                        if (MAXDEBUG && DEBUGGER) this.acTimersFired[iTimer]++;
                    }
                }
            }
            /*
             * Early implementation of this mode was minimal because when using this mode, the ROM BIOS simply wanted
             * to see the count changing; it wasn't looking for interrupts.  See ROM BIOS "TEST.03" code @F000:E0DE,
             * where TIMER1 is programmed for MODE2, LSB (the same settings, incidentally, used immediately afterward
             * for TIMER1 in conjunction with DMA channel 0 memory refreshes).
             *
             * Now this mode generates interrupts.  Note that OUT goes low when the count reaches 1, then high
             * one tick later, at which point the count is reloaded and counting continues.
             *
             * Chances are, we will often miss the exact point at which the count becomes 1 (or more importantly,
             * one tick later, when the count *would* become 0, since that's when OUT transitions from low to high),
             * but as with MODE3, hopefully no one will mind.
             *
             * FYI, technically, it appears that the count is never supposed to reach 0, and that an initial count of 1
             * is "illegal", whatever that means.
             */
            else if (timer.mode == ChipSet.PIT_CTRL.MODE2) {
                timer.fOUT = (count != 1);          // yes, this line does seem rather pointless....
                if (count <= 0) {
                    count = countInit + count;
                    if (count <= 0) {
                        /*
                         * TODO: Consider whether we ever care about TIMER1 or TIMER2 underflow
                         */
                        if (DEBUG && !iTimer) this.printf(Messages.TIMER, "updateTimer(%d): mode=2, underflow=%d\n", iTimer, count);
                        count = countInit;
                    }
                    timer.countStart[0] = count & 0xff;
                    timer.countStart[1] = (count >> 8) & 0xff;
                    timer.nCyclesStart = nCycles;
                    if (!iTimer && timer.fOUT) {
                        fFired = true;
                        this.setIRR(ChipSet.IRQ.TIMER0);
                        if (MAXDEBUG && DEBUGGER) this.acTimersFired[iTimer]++;
                    }
                }
            }
            /*
             * NOTE: This is the normal mode for TIMER0, which the ROM BIOS uses to generate h/w interrupts roughly
             * 18.2 times per second.  In this mode, the count must be decremented twice as fast (hence the extra ticks
             * subtraction below, in addition to the subtraction above), but IRQ_TIMER0 is raised only on alternate
             * iterations; ie, only when fOUT transitions to true ("high").  The equal alternating fOUT states is why
             * this mode is referred to as "square wave" mode.
             *
             * TODO: Implement the correct behavior for this mode when the count is ODD.  In that case, fOUT is supposed
             * to be "high" for (N + 1) / 2 ticks and "low" for (N - 1) / 2 ticks.
             */
            else if (timer.mode == ChipSet.PIT_CTRL.MODE3) {
                count -= ticksElapsed;
                if (count <= 0) {
                    timer.fOUT = !timer.fOUT;
                    count = countInit + count;
                    if (count <= 0) {
                        /*
                         * TODO: Consider whether we ever care about TIMER1 or TIMER2 underflow
                         */
                        if (DEBUG && !iTimer) this.printf(Messages.TIMER, "updateTimer(%d): mode=3, underflow=%d\n", iTimer, count);
                        count = countInit;
                    }
                    if (MAXDEBUG && DEBUGGER && !iTimer) {
                        let nCycleDelta = 0;
                        if (this.acTimer0Counts.length > 0) nCycleDelta = nCycles - this.acTimer0Counts[0][1];
                        this.acTimer0Counts.push([count, nCycles, nCycleDelta]);
                    }
                    timer.countStart[0] = count & 0xff;
                    timer.countStart[1] = (count >> 8) & 0xff;
                    timer.nCyclesStart = nCycles;
                    if (!iTimer && timer.fOUT) {
                        fFired = true;
                        this.setIRR(ChipSet.IRQ.TIMER0);
                        if (MAXDEBUG && DEBUGGER) this.acTimersFired[iTimer]++;
                    }
                }
            }

            if (MAXDEBUG && this.messageEnabled(Messages.TIMER + Messages.WARN)) {
                this.log("TIMER" + iTimer + " count: " + count + ", ticks: " + ticksElapsed + ", fired: " + (fFired? "true" : "false"));
            }

            timer.countCurrent[0] = count & 0xff;
            timer.countCurrent[1] = (count >> 8) & 0xff;
            if (fCycleReset) this.nCyclesStart = 0;
        }
        return timer;
    }

    /**
     * updateAllTimers(fCycleReset)
     *
     * @this {ChipSet}
     * @param {boolean} [fCycleReset] is true if a cycle-count reset is about to occur
     */
    updateAllTimers(fCycleReset)
    {
        for (let iTimer = 0; iTimer < this.aTimers.length; iTimer++) {
            this.updateTimer(iTimer, fCycleReset);
        }
        if (this.model >= ChipSet.MODEL_5170) this.updateRTCTime();
    }

    /**
     * outMFGTest(port, bOut, addrFrom)
     *
     * This is test port on the PCjr (MODEL_4860) only.
     *
     * @this {ChipSet}
     * @param {number} port (0x10)
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     */
    outMFGTest(port, bOut, addrFrom)
    {
        this.printMessageIO(port, bOut, addrFrom, "MFG_TEST");
    }

    /**
     * inPPIA(port, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} port (0x60)
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     * @return {number} simulated port value
     */
    inPPIA(port, addrFrom)
    {
        let b = this.bPPIA;
        if (this.bPPICtrl & ChipSet.PPI_CTRL.A_IN) {
            if (this.bPPIB & ChipSet.PPI_B.CLEAR_KBD) {
                b = this.aDIPSwitches[0][1];
            } else {
                b = this.bKbdData;
                this.printMessageIO(port, undefined, addrFrom, "PPI_A", b, Messages.KBD);
                return b;
            }
        }
        this.printMessageIO(port, undefined, addrFrom, "PPI_A", b);
        return b;
    }

    /**
     * outPPIA(port, bOut, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} port (0x60)
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     */
    outPPIA(port, bOut, addrFrom)
    {
        this.printMessageIO(port, bOut, addrFrom, "PPI_A");
        this.bPPIA = bOut;
    }

    /**
     * inPPIB(port, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} port (0x61)
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     * @return {number} simulated port value
     */
    inPPIB(port, addrFrom)
    {
        let b = this.bPPIB;
        this.printMessageIO(port, undefined, addrFrom, "PPI_B", b);
        return b;
    }

    /**
     * outPPIB(port, bOut, addrFrom)
     *
     * This is the original (MODEL_5150 and MODEL_5160) handler for port 0x61.  Functionality common
     * to all models must be placed in updatePPIB().
     *
     * @this {ChipSet}
     * @param {number} port (0x61)
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     */
    outPPIB(port, bOut, addrFrom)
    {
        this.printMessageIO(port, bOut, addrFrom, "PPI_B");
        this.updatePPIB(bOut);
    }

    /**
     * updatePPIB(bOut)
     *
     * On MODEL_5170 and up, this updates the "simulated" PPI_B.  The only common (and well-documented) PPI_B bits
     * across all models are PPI_B.CLK_TIMER2 and PPI_B.SPK_TIMER2, so its possible that this function may need to
     * limit its updates to just those bits, and move any model-specific requirements back into the appropriate I/O
     * handlers (PPIB or 8042RWReg).  We'll see.
     *
     * UPDATE: The WOLF3D keyboard interrupt handler toggles the CLEAR_KBD bit of port 0x61 (ie, it sets and then
     * clears the bit) after reading the scan code from port 0x60; assuming that they use the same interrupt handler
     * for all machine models (which I haven't verified), the clear implication is that updatePPIB() also needs to
     * support CLEAR_KBD and CLK_KBD, so I've moved that code from outPPIB() to updatePPIB().
     *
     * @this {ChipSet}
     * @param {number} bOut
     */
    updatePPIB(bOut)
    {
        let toggled = (bOut ^ this.bPPIB);
        if (toggled & ChipSet.PPI_B.CLK_TIMER2) {
            /*
             * If TIMER2 is about to be "declocked", then we should update the timer NOW, because any attempt to read
             * timer's count AFTER it has been declocked will not trigger an update.  This was a problem for the following
             * code in SUPERPCK.EXE from DR DOS 6.00:
             *
             *      &10AE:C863 E461             IN       AL,61
             *      &10AE:C865 24FC             AND      AL,FC
             *      &10AE:C867 8AE0             MOV      AH,AL
             *      &10AE:C869 E661             OUT      61,AL              ; PPI_B: disable CLK_TIMER2 and SPK_TIMER2
             *      &10AE:C86B B0B4             MOV      AL,B4
             *      &10AE:C86D E643             OUT      43,AL              : PIT_CTRL: MODE2, RW_BOTH, SC_CTR2
             *      &10AE:C86F 32C0             XOR      AL,AL
             *      &10AE:C871 E642             OUT      42,AL
             *      &10AE:C873 EB00             JMP      C875 (SUPERPCK.EXE+0x745B)
             *      &10AE:C875 E642             OUT      42,AL
             *      &10AE:C877 B90010           MOV      CX,1000
             *      &10AE:C87A 8AC4             MOV      AL,AH
             *      &10AE:C87C 0C01             OR       AL,01
             *      &10AE:C87E E661             OUT      61,AL              ; PPI_B: enable CLK_TIMER2
             *      &10AE:C880 E2FE             LOOP     C880 (SUPERPCK.EXE+0x7469)
             *      &10AE:C882 8AC4             MOV      AL,AH
             *      &10AE:C884 E661             OUT      61,AL              ; PPI_B: disable CLK_TIMER2 again
             *      &10AE:C886 E442             IN       AL,42              ; PIT_TIMER2: read count (without, um, latching)
             *      &10AE:C888 8AE0             MOV      AH,AL
             *      &10AE:C88A E442             IN       AL,42
             *      &10AE:C88C 86C4             XCHG     AL,AH
             *      &10AE:C88E F7D8             NEG      AX
             *      &10AE:C890 8BD8             MOV      BX,AX
             *      &10AE:C892 B80010           MOV      AX,1000
             *      &10AE:C895 33D2             XOR      DX,DX
             *      &10AE:C897 F7F3             DIV      BX                 ; potential divide-by-zero if TIMER2 count was zero
             *
             * Another interesting but unrelated problem is that DR DOS's divide-by-zero exception handler was pointing
             * to 0F71:258C at this point, which contained invalid code.  The code was valid when the handler was first set,
             * but it was later discarded or relocated and then overwritten.
             */
            if (!(bOut & ChipSet.PPI_B.CLK_TIMER2)) {
                this.updateTimer(ChipSet.PIT0.TIMER2);
            }
        }
        this.bPPIB = bOut;
        if (toggled & ChipSet.PPI_B.SPK_TIMER2) {
            /*
             * Originally, this code didn't catch the "ERROR_BEEP" case @F000:EC34, which first turns both PPI_B.CLK_TIMER2 (0x01)
             * and PPI_B.SPK_TIMER2 (0x02) off, then turns on only PPI_B.SPK_TIMER2 (0x02), then restores the original port value.
             *
             * So, when the ROM BIOS keyboard buffer got full, we didn't issue a BEEP alert.  I've fixed that by limiting the test
             * to PPI_B.SPK_TIMER2 and ignoring PPI_B.CLK_TIMER2.
             */
            this.setSpeaker(bOut & ChipSet.PPI_B.SPK_TIMER2);
        }
        if (this.kbd) this.kbd.setEnabled(!(bOut & ChipSet.PPI_B.CLEAR_KBD), !!(bOut & ChipSet.PPI_B.CLK_KBD));
    }

    /**
     * inPPIC(port, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} port (0x62)
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     * @return {number} simulated port value
     */
    inPPIC(port, addrFrom)
    {
        let b = 0;

        /*
         * If you ever wanted to simulate I/O channel errors or R/W memory parity errors, you could
         * add either PPI_C.IO_CHANNEL_CHK (0x40) or PPI_C.RW_PARITY_CHK (0x80) to the return value (b).
         */
        if ((this.model|0) == ChipSet.MODEL_4860) {
            b |= this.bNMI & ChipSet.NMI.KBD_LATCH;
            /*
             * We're going to hard-code the rest of the PCjr settings for now, including NOT setting the NO_KBD_CABLE
             * bit, on the theory that if we don't have to deal with IR hardware emulation, so much the better.
             */
            b |= ChipSet.PPI_C.NO_MODEM | ChipSet.PPI_C.NO_DISKETTE | ChipSet.PPI_C.NO_MEMEXP;
            /*
             * I'm just guessing at how keyboard data is "clocked" into the the KBD_DATA bit; this will be revisited.
             */
            b |= (this.bKbdData & 0x1)? ChipSet.PPI_C.KBD_DATA : 0;
            this.bKbdData >>>= 1;
        }
        else if ((this.model|0) == ChipSet.MODEL_5150) {
            if (this.bPPIB & ChipSet.PPI_B.ENABLE_SW2) {
                b |= this.aDIPSwitches[1][1] & ChipSet.PPI_C.SW;
            } else {
                b |= (this.aDIPSwitches[1][1] >> 4) & 0x1;
            }
        } else {
            if (this.bPPIB & ChipSet.PPI_B.ENABLE_SW_HI) {
                b |= this.aDIPSwitches[0][1] >> 4;
            } else {
                b |= this.aDIPSwitches[0][1] & 0xf;
            }
        }

        if (this.bPPIB & ChipSet.PPI_B.CLK_TIMER2) {
            let timer = this.updateTimer(ChipSet.PIT0.TIMER2);
            if (timer.fOUT) {
                if (this.bPPIB & ChipSet.PPI_B.SPK_TIMER2)
                    b |= ChipSet.PPI_C.TIMER2_OUT;
                else
                    b |= ChipSet.PPI_C.CASS_DATA_IN;
            }
        }

        /*
         * The ROM BIOS polls this port incessantly during its memory tests, checking for memory parity errors
         * (which of course we never report), so you must use both Messages.PORT and Messages.CHIPSET.
         */
        this.printMessageIO(port, undefined, addrFrom, "PPI_C", b, Messages.CHIPSET);
        return b;
    }

    /**
     * outPPIC(port, bOut, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} port (0x62)
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     */
    outPPIC(port, bOut, addrFrom)
    {
        this.printMessageIO(port, bOut, addrFrom, "PPI_C");
        this.bPPIC = bOut;
    }

    /**
     * inPPICtrl(port, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} port (0x63)
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     * @return {number} simulated port value
     */
    inPPICtrl(port, addrFrom)
    {
        let b = this.bPPICtrl;
        this.printMessageIO(port, undefined, addrFrom, "PPI_CTRL", b);
        return b;
    }

    /**
     * outPPICtrl(port, bOut, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} port (0x63)
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to write the specified port)
     */
    outPPICtrl(port, bOut, addrFrom)
    {
        this.printMessageIO(port, bOut, addrFrom, "PPI_CTRL");
        this.bPPICtrl = bOut;
    }

    /**
     * in8041Kbd(port, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} port (0x60)
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     * @return {number} simulated port value
     */
    in8041Kbd(port, addrFrom)
    {
        let b = this.bKbdData;
        this.printMessageIO(port, undefined, addrFrom, "8041_KBD", b, Messages.KBD);
        this.b8041Status &= ~ChipSet.C8042.STATUS.OUTBUFF_FULL;
        return b;
    }

    /**
     * out8041Kbd(port, bOut, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} port (0x60)
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     */
    out8041Kbd(port, bOut, addrFrom)
    {
        this.printMessageIO(port, bOut, addrFrom, "8041_KBD");
        // if (this.kbd) this.kbd.receiveCmd(bOut);
    }

    /**
     * in8041Ctrl(port, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} port (0x61)
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     * @return {number} simulated port value
     */
    in8041Ctrl(port, addrFrom)
    {
        let b = this.bPPIB;
        this.printMessageIO(port, undefined, addrFrom, "8041_CTRL", b);
        return b;
    }

    /**
     * out8041Ctrl(port, bOut, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} port (0x61)
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     */
    out8041Ctrl(port, bOut, addrFrom)
    {
        this.printMessageIO(port, bOut, addrFrom, "8041_CTRL");
        this.updatePPIB(bOut);
    }

    /**
     * in8041Status(port, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} port (0x64)
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     * @return {number} simulated port value
     */
    in8041Status(port, addrFrom)
    {
        let b = this.b8041Status;
        this.printMessageIO(port, undefined, addrFrom, "8041_STATUS", b);
        return b;
    }

    /**
     * in8042OutBuff(port, addrFrom)
     *
     * Return the contents of the OUTBUFF register and clear the OUTBUFF_FULL status bit.
     *
     * Moreover, we also call kbd.checkBuffer() to let the Keyboard know that we just pulled
     * data, so that it can reset its internal timer controlling the delivery of additional data.
     *
     * Note that there are applications like BASICA that install a keyboard interrupt handler
     * that reads OUTBUFF, does some scan code preprocessing, and then passes control on to the
     * ROM's interrupt handler.  As a result, OUTBUFF is read multiple times during a single
     * interrupt, so we need to avoid filling it with new data after every read; otherwise,
     * scan codes will get dropped.
     *
     * The safest thing to do is to wait until kbd.setEnabled() is called, and let that call supply
     * more data to receiveKbdData().  That will happen as soon as the ROM re-enables the controller,
     * and is why C8042.CMD.ENABLE_KBD processing ends with a call to kbd.checkBuffer().  However,
     * not all software (eg, Xenix 286, and the Windows 95 VMM) does that, so we have to rely on
     * the Keyboard's internal timer.
     *
     * Also note that, the foregoing notwithstanding, I still clear the OUTBUFF_FULL bit here
     * (as I believe I should); fortunately, none of the interrupt handlers I've seen rely on
     * OUTBUFF_FULL as a prerequisite for reading OUTBUFF (certainly not BASICA or the ROM).
     * The assumption seems to be that if an interrupt occurred, OUTBUFF must contain data,
     * regardless of the state of OUTBUFF_FULL.
     *
     * @this {ChipSet}
     * @param {number} port (0x60)
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     * @return {number} simulated port value
     */
    in8042OutBuff(port, addrFrom)
    {
        let b = this.b8042OutBuff;
        this.printMessageIO(port, undefined, addrFrom, "8042_OUTBUFF", b, Messages.C8042);
        this.b8042Status &= ~(ChipSet.C8042.STATUS.OUTBUFF_FULL | ChipSet.C8042.STATUS.OUTBUFF_DELAY);
        if (this.kbd) this.kbd.checkBuffer(b);
        return b;
    }

    /**
     * out8042InBuffData(port, bOut, addrFrom)
     *
     * This writes to the 8042's input buffer; using this port (ie, 0x60 instead of 0x64) designates the
     * the byte as a C8042.DATA.CMD "data byte".  Before clearing C8042.STATUS.CMD_FLAG, however, we see if it's set,
     * and then based on the previous C8042.CMD "command byte", we do whatever needs to be done with this "data byte".
     *
     * @this {ChipSet}
     * @param {number} port (0x60)
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to write the specified port)
     */
    out8042InBuffData(port, bOut, addrFrom)
    {
        this.printMessageIO(port, bOut, addrFrom, "8042_INBUF.DATA", undefined, Messages.C8042);

        if (this.b8042Status & ChipSet.C8042.STATUS.CMD_FLAG) {

            switch (this.b8042InBuff) {

            case ChipSet.C8042.CMD.WRITE_CMD:
                this.set8042CmdData(bOut);
                break;

            case ChipSet.C8042.CMD.WRITE_OUTPORT:
                this.set8042OutPort(bOut);
                break;

            /*
             * This case is reserved for command bytes that the 8042 is not expecting, which should therefore be passed
             * on to the Keyboard itself.
             *
             * Here's some relevant MODEL_5170 ROM BIOS code, "XMIT_8042" (missing from the original MODEL_5170 ROM BIOS
             * listing), which sends a command code in AL to the Keyboard and waits for a response, returning it in AL.
             * Note that the only "success" exit path from this function involves LOOPing 64K times before finally reading
             * the Keyboard's response; either the hardware and/or this code seems a bit brain-damaged if that's REALLY
             * what you had to do to ensure a valid response....
             *
             *      F000:1B25 86E0          XCHG     AH,AL
             *      F000:1B27 2BC9          SUB      CX,CX
             *      F000:1B29 E464          IN       AL,64
             *      F000:1B2B A802          TEST     AL,02      ; WAIT FOR INBUFF_FULL TO BE CLEAR
             *      F000:1B2D E0FA          LOOPNZ   1B29
             *      F000:1B2F E334          JCXZ     1B65       ; EXIT WITH ERROR (CX == 0)
             *      F000:1B31 86E0          XCHG     AH,AL
             *      F000:1B33 E660          OUT      60,AL      ; SAFE TO WRITE KEYBOARD CMD TO INBUFF NOW
             *      F000:1B35 2BC9          SUB      CX,CX
             *      F000:1B37 E464          IN       AL,64
             *      F000:1B39 8AE0          MOV      AH,AL
             *      F000:1B3B A801          TEST     AL,01
             *      F000:1B3D 7402          JZ       1B41
             *      F000:1B3F E460          IN       AL,60      ; READ PORT 0x60 IF OUTBUFF_FULL SET ("FLUSH"?)
             *      F000:1B41 F6C402        TEST     AH,02
             *      F000:1B44 E0F1          LOOPNZ   1B37
             *      F000:1B46 751D          JNZ      1B65       ; EXIT WITH ERROR (CX == 0)
             *      F000:1B48 B306          MOV      BL,06
             *      F000:1B4A 2BC9          SUB      CX,CX
             *      F000:1B4C E464          IN       AL,64
             *      F000:1B4E A801          TEST     AL,01
             *      F000:1B50 E1FA          LOOPZ    1B4C
             *      F000:1B52 7508          JNZ      1B5C       ; PROCEED TO EXIT NOW THAT OUTBUFF_FULL IS SET
             *      F000:1B54 FECB          DEC      BL
             *      F000:1B56 75F4          JNZ      1B4C
             *      F000:1B58 FEC3          INC      BL
             *      F000:1B5A EB09          JMP      1B65       ; EXIT WITH ERROR (CX == 0)
             *      F000:1B5C 2BC9          SUB      CX,CX
             *      F000:1B5E E2FE          LOOP     1B5E       ; LOOOOOOPING....
             *      F000:1B60 E460          IN       AL,60
             *      F000:1B62 83E901        SUB      CX,0001    ; EXIT WITH SUCCESS (CX != 0)
             *      F000:1B65 C3            RET
             *
             * But WAIT, the FUN doesn't end there.  After this function returns, "KBD_RESET" waits for a Keyboard
             * interrupt to occur, hoping for scan code 0xAA as the Keyboard's final response.  "KBD_RESET" also returns
             * CX to the caller, and the caller ("TEST.21") assumes there was no interrupt if CX is zero.
             *
             *              MOV     AL,0FDH
             *              OUT     INTA01,AL
             *              MOV     INTR_FLAG,0
             *              STI
             *              MOV     BL,10
             *              SUB     CX,CX
             *      G11:    TEST    [1NTR_FLAG],02H
             *              JNZ     G12
             *              LOOP    G11
             *              DEC     BL
             *              JNZ     G11
             *              ...
             *
             * However, if [INTR_FLAG] is set immediately, the above code will exit immediately, without ever decrementing
             * CX.  CX can be zero not only if the loop exhausted it, but also if no looping was required; the latter is not
             * an error, but "TEST.21" assumes that it is.
             */
            default:
                this.set8042CmdData(this.b8042CmdData & ~ChipSet.C8042.DATA.CMD.NO_CLOCK);
                if (this.kbd) this.set8042OutBuff(this.kbd.receiveCmd(bOut));
                break;
            }
        }
        this.b8042InBuff = bOut;
        this.b8042Status &= ~ChipSet.C8042.STATUS.CMD_FLAG;
    }

    /**
     * in8042RWReg(port, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} port (0x61)
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     * @return {number} simulated port value
     */
    in8042RWReg(port, addrFrom)
    {
        /*
         * Normally, we return whatever was last written to this port, but we do need to mask the
         * two upper-most bits (C8042.RWREG.NMI_ERROR), as those are output-only bits used to signal
         * parity errors.
         *
         * Also, "TEST.09" of the MODEL_5170 BIOS expects the REFRESH_BIT to alternate, so we used to
         * do this:
         *
         *      this.bPPIB ^= ChipSet.C8042.RWREG.REFRESH_BIT;
         *
         * However, the MODEL_5170_REV3 BIOS not only checks REFRESH_BIT in "TEST.09", but includes
         * an additional test right before "TEST.11A", which requires the bit change "a bit less"
         * frequently.  This new test sets CX to zero, and at the end of the test (@F000:05B8), CX
         * must be in the narrow range of 0xF600 through 0xF9FD.
         *
         * In fact, the new "WAITF" function @F000:1A3A tells us exactly how frequently REFRESH_BIT
         * is expected to change now.  That function performs a "FIXED TIME WAIT", where CX is a
         * "COUNT OF 15.085737us INTERVALS TO WAIT".
         *
         * So we now tie the state of the REFRESH_BIT to bit 6 of the current CPU cycle count,
         * effectively toggling the bit after every 64 cycles.  On an 8Mhz CPU that can do 8 cycles
         * in 1us, 64 cycles represents 8us, so that might be a bit fast for "WAITF", but bit 6
         * is the only choice that also satisfies the pre-"TEST.11A" test as well.
         */
        let b = this.bPPIB & ~(ChipSet.C8042.RWREG.NMI_ERROR | ChipSet.C8042.RWREG.REFRESH_BIT) | ((this.cpu.getCycles() & 0x40)? ChipSet.C8042.RWREG.REFRESH_BIT : 0);
        /*
         * Thanks to the WAITF function, this has become a very "busy" port, so if this generates too
         * many messages, try adding Messages.WARN to the criteria.
         */
        this.printMessageIO(port, undefined, addrFrom, "8042_RWREG", b, Messages.C8042 + Messages.WARN);
        return b;
    }

    /**
     * out8042RWReg(port, bOut, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} port (0x61)
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     */
    out8042RWReg(port, bOut, addrFrom)
    {
        this.printMessageIO(port, bOut, addrFrom, "8042_RWREG", undefined, Messages.C8042);
        this.updatePPIB(bOut);
    }

    /**
     * in8042Status(port, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} port (0x64)
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     * @return {number} simulated port value
     */
    in8042Status(port, addrFrom)
    {
        this.printMessageIO(port, undefined, addrFrom, "8042_STATUS", this.b8042Status, Messages.C8042);
        let b = this.b8042Status & 0xff;
        /*
         * There's code in the 5170 BIOS (F000:03BF) that writes an 8042 command (0xAA), waits for
         * C8042.STATUS.INBUFF_FULL to go clear (which it always is, because we always accept commands
         * immediately), then checks C8042.STATUS.OUTBUFF_FULL and performs a "flush" on port 0x60 if
         * it's set, then waits for C8042.STATUS.OUTBUFF_FULL *again*.  Unfortunately, the "flush" throws
         * away our response if we respond immediately.
         *
         * So now when out8042InBuffCmd() has a response, it sets C8042.STATUS.OUTBUFF_DELAY instead
         * (which is outside the 0xff range of bits we return); when we see C8042.STATUS.OUTBUFF_DELAY,
         * we clear it and set C8042.STATUS.OUTBUFF_FULL, which will be returned on the next read.
         *
         * This provides a single poll delay, so that the aforementioned "flush" won't toss our response.
         * If longer delays are needed down the road, we may need to set a delay count in the upper (unused)
         * bits of b8042Status, instead of using a single delay bit.
         */
        if (this.b8042Status & ChipSet.C8042.STATUS.OUTBUFF_DELAY) {
            this.b8042Status |= ChipSet.C8042.STATUS.OUTBUFF_FULL;
            this.b8042Status &= ~ChipSet.C8042.STATUS.OUTBUFF_DELAY;
        }
        /*
         * I added this for Windows 95's VMM keyboard driver for DOS sessions, which differs from the keyboard
         * driver for protected-mode applications (see the keyboard's setEnabled() function for more details).
         *
         * The Windows 95 VMM driver doesn't do what EITHER the ROM or the protected-mode driver typically does
         * after receiving a scan code (ie, toggle the keyboard's enable state).  Instead, the VMM simply checks
         * this status port one more time, perhaps to confirm that the OUTBUFF_FULL bit is clear.  It then
         * expects another keyboard interrupt to arrive when the next scan code is available.  Very minimalistic.
         */
        if (!(this.b8042Status & ChipSet.C8042.STATUS.OUTBUFF_FULL) && this.kbd) {
            this.kbd.checkBuffer();
        }
        return b;
    }

    /**
     * out8042InBuffCmd(port, bOut, addrFrom)
     *
     * This writes to the 8042's input buffer; using this port (ie, 0x64 instead of 0x60) designates the
     * the byte as a "command byte".  We immediately set C8042.STATUS.CMD_FLAG, and then see if we can act upon
     * the command immediately (some commands requires us to wait for a "data byte").
     *
     * @this {ChipSet}
     * @param {number} port (0x64)
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to write the specified port)
     */
    out8042InBuffCmd(port, bOut, addrFrom)
    {
        this.printMessageIO(port, bOut, addrFrom, "8042_INBUFF.CMD", undefined, Messages.C8042);

        this.b8042InBuff = bOut;

        this.b8042Status |= ChipSet.C8042.STATUS.CMD_FLAG;

        let bPulseBits = 0;
        if (this.b8042InBuff >= ChipSet.C8042.CMD.PULSE_OUTPORT) {
            bPulseBits = (this.b8042InBuff ^ 0xf);
            /*
             * Now that we have isolated the bit(s) to pulse, map all pulse commands to C8042.CMD.PULSE_OUTPORT
             */
            this.b8042InBuff = ChipSet.C8042.CMD.PULSE_OUTPORT;
        }

        switch (this.b8042InBuff) {
        case ChipSet.C8042.CMD.READ_CMD:        // 0x20
            this.set8042OutBuff(this.b8042CmdData);
            break;

        case ChipSet.C8042.CMD.WRITE_CMD:       // 0x60
            /*
             * No further action required for this command; more data is expected via out8042InBuffData()
             */
            break;

        case ChipSet.C8042.CMD.DISABLE_KBD:     // 0xAD
            this.set8042CmdData(this.b8042CmdData | ChipSet.C8042.DATA.CMD.NO_CLOCK);
            if (!COMPILED) this.printf(Messages.KBD + Messages.PORT, "keyboard disabled\n");
            /*
             * NOTE: The MODEL_5170 BIOS calls "KBD_RESET" (F000:17D2) while the keyboard interface is disabled,
             * yet we must still deliver the Keyboard's CMDRES.BAT_OK response code?  Seems like an odd thing for
             * a "disabled interface" to do.
             */
            break;

        case ChipSet.C8042.CMD.ENABLE_KBD:      // 0xAE
            this.set8042CmdData(this.b8042CmdData & ~ChipSet.C8042.DATA.CMD.NO_CLOCK);
            if (!COMPILED) this.printf(Messages.KBD + Messages.PORT, "keyboard re-enabled\n");
            if (this.kbd) this.kbd.checkBuffer();
            break;

        case ChipSet.C8042.CMD.SELF_TEST:       // 0xAA
            if (this.kbd) this.kbd.flushBuffer();
            this.set8042CmdData(this.b8042CmdData | ChipSet.C8042.DATA.CMD.NO_CLOCK);
            if (!COMPILED) this.printf(Messages.KBD + Messages.PORT, "keyboard disabled on reset\n");
            this.set8042OutBuff(ChipSet.C8042.DATA.SELF_TEST.OK);
            this.set8042OutPort(ChipSet.C8042.OUTPORT.NO_RESET | ChipSet.C8042.OUTPORT.A20_ON);
            break;

        case ChipSet.C8042.CMD.INTF_TEST:       // 0xAB
            /*
             * TODO: Determine all the side-effects of the Interface Test, if any.
             */
            this.set8042OutBuff(ChipSet.C8042.DATA.INTF_TEST.OK);
            break;

        case ChipSet.C8042.CMD.READ_INPORT:     // 0xC0
            this.set8042OutBuff(this.b8042InPort);
            break;

        case ChipSet.C8042.CMD.READ_OUTPORT:    // 0xD0
            this.set8042OutBuff(this.b8042OutPort);
            break;

        case ChipSet.C8042.CMD.WRITE_OUTPORT:   // 0xD1
            /*
             * No further action required for this command; more data is expected via out8042InBuffData()
             */
            break;

        case ChipSet.C8042.CMD.READ_TEST:       // 0xE0
            this.set8042OutBuff((this.b8042CmdData & ChipSet.C8042.DATA.CMD.NO_CLOCK)? 0 : ChipSet.C8042.TESTPORT.KBD_CLOCK);
            break;

        case ChipSet.C8042.CMD.PULSE_OUTPORT:   // 0xF0-0xFF
            if (bPulseBits & 0x1) {
                /*
                 * Bit 0 of the 8042's output port is connected to RESET.  If it's pulsed, the processor resets.
                 * We don't want to clear *all* CPU state (eg, cycle counts), so we call cpu.resetRegs() instead
                 * of cpu.reset().
                 */
                this.cpu.resetRegs();
            }
            break;

        default:
            if (!COMPILED) {
                this.printf(Messages.ALL, "unrecognized 8042 command: %#04X\n", this.b8042InBuff);
                // if (this.dbg) this.dbg.stopCPU();
            }
            break;
        }
    }

    /**
     * set8042CmdData(b)
     *
     * @this {ChipSet}
     * @param {number} b
     */
    set8042CmdData(b)
    {
        this.b8042CmdData = b;

        this.b8042Status = (this.b8042Status & ~ChipSet.C8042.STATUS.SYS_FLAG) | (b & ChipSet.C8042.DATA.CMD.SYS_FLAG);
        if (this.kbd) {
            /*
             * This seems to be what the doctor ordered for the MODEL_5170_REV3 BIOS @F000:0A6D, where it
             * sends ChipSet.C8042.CMD.WRITE_CMD to port 0x64, followed by 0x4D to port 0x60, which clears NO_CLOCK
             * and enables the keyboard.  The BIOS then waits for OUTBUFF_FULL to be set, at which point it seems
             * to be anticipating an 0xAA response in the output buffer.
             *
             * And indeed, if we call the original MODEL_5150/MODEL_5160 setEnabled() Keyboard interface here,
             * and both the data and clock lines have transitioned high (ie, both parameters are true), then it
             * will call resetDevice(), generating a Keyboard.CMDRES.BAT_OK response.
             *
             * This agrees with my understanding of what happens when the 8042 toggles the clock line high
             * (ie, clears NO_CLOCK): the TechRef's "Basic Assurance Test" section says that when the Keyboard is
             * powered on, it performs the BAT, and then when the clock and data lines go high, the keyboard sends
             * a completion code (eg, 0xAA for success, or 0xFC or something else for failure).
             */
            this.kbd.setEnabled(!!(b & ChipSet.C8042.DATA.CMD.NO_INHIBIT), !(b & ChipSet.C8042.DATA.CMD.NO_CLOCK));
        }
    }

    /**
     * set8042OutBuff(b, fNoDelay)
     *
     * The 5170 ROM BIOS assumed there would be a slight delay after certain 8042 commands, like SELF_TEST
     * (0xAA), before there was an OUTBUFF response; in fact, there is BIOS code that will fail without such
     * a delay.  This is discussed in greater detail in in8042Status().
     *
     * So we default to a "single poll" delay, setting OUTBUFF_DELAY instead of OUTBUFF_FULL, unless the caller
     * explicitly asks for no delay.  The fNoDelay parameter was added later, so that receiveKbdData() could
     * request immediate delivery of keyboard scan codes, because some operating systems (eg, Microport's 1986
     * version of Unix for PC AT machines) poll the status port only once, immediately giving up if no data is
     * available.
     *
     * TODO: Determine if we should invert the fNoDelay default (from false to true) and delay only in specific
     * cases; ie, perhaps only the SELF_TEST command required a delay.
     *
     * @this {ChipSet}
     * @param {number} b
     * @param {boolean} [fNoDelay]
     */
    set8042OutBuff(b, fNoDelay)
    {
        if (b >= 0) {
            this.b8042OutBuff = b;
            if (fNoDelay) {
                this.b8042Status |= ChipSet.C8042.STATUS.OUTBUFF_FULL;
            } else {
                this.b8042Status &= ~ChipSet.C8042.STATUS.OUTBUFF_FULL;
                this.b8042Status |= ChipSet.C8042.STATUS.OUTBUFF_DELAY;
            }
            if (!COMPILED) this.printf(Messages.KBD + Messages.PORT, "chipset.set8042OutBuff(%#04X,delay=%b)\n", b, !fNoDelay);
        }
    }

    /**
     * set8042OutPort(b)
     *
     * When ChipSet.C8042.CMD.WRITE_OUTPORT (0xD1) is written to port 0x64, the next byte written to port 0x60 comes here,
     * to the KBC's OUTPORT.  One of the most important bits in the OUTPORT is the A20_ON bit (0x02): set it to turn A20 on,
     * clear it to turn A20 off.
     *
     * @this {ChipSet}
     * @param {number} b
     */
    set8042OutPort(b)
    {
        this.b8042OutPort = b;

        this.bus.setA20(!!(b & ChipSet.C8042.OUTPORT.A20_ON));

        if (!(b & ChipSet.C8042.OUTPORT.NO_RESET)) {
            /*
             * Bit 0 of the 8042's output port is connected to RESET.  Normally, it's "pulsed" with the
             * C8042.CMD.PULSE_OUTPORT command, so if a RESET is detected via this command, we should try to
             * determine if that's what the caller intended.
             */
            if (!COMPILED) {
                this.printf(Messages.ALL, "unexpected 8042 output port reset: %#04X\n", b);
                if (this.dbg) this.dbg.stopCPU();
            }
            this.cpu.resetRegs();
        }
    }

    /**
     * receiveKbdData(b)
     *
     * In the old days of PCx86, the Keyboard component would simply call setIRR() when it had some data for the
     * keyboard controller.  However, the Keyboard's sole responsibility is to emulate an actual keyboard and call
     * receiveKbdData() whenever it has some data; it's not allowed to mess with IRQ lines.
     *
     * If there's an 8042, we check (this.b8042CmdData & ChipSet.C8042.DATA.CMD.NO_CLOCK); if NO_CLOCK is clear,
     * we can raise the IRQ immediately.  Well, not quite immediately....
     *
     * Notes regarding the MODEL_5170 (eg, /devices/pc/machine/5170/ega/1152kb/rev3/machine.xml):
     *
     * The "Rev3" BIOS, dated 11-Nov-1985, contains the following code in the keyboard interrupt handler at K26A:
     *
     *      F000:3704 FA            CLI
     *      F000:3705 B020          MOV      AL,20
     *      F000:3707 E620          OUT      20,AL
     *      F000:3709 B0AE          MOV      AL,AE
     *      F000:370B E88D02        CALL     SHIP_IT
     *      F000:370E FA            CLI                     <-- window of opportunity
     *      F000:370F 07            POP      ES
     *      F000:3710 1F            POP      DS
     *      F000:3711 5F            POP      DI
     *      F000:3712 5E            POP      SI
     *      F000:3713 5A            POP      DX
     *      F000:3714 59            POP      CX
     *      F000:3715 5B            POP      BX
     *      F000:3716 58            POP      AX
     *      F000:3717 5D            POP      BP
     *      F000:3718 CF            IRET
     *
     * and SHIP_IT looks like this:
     *
     *      F000:399B 50            PUSH     AX
     *      F000:399C FA            CLI
     *      F000:399D 2BC9          SUB      CX,CX
     *      F000:399F E464          IN       AL,64
     *      F000:39A1 A802          TEST     AL,02
     *      F000:39A3 E0FA          LOOPNZ   399F
     *      F000:39A5 58            POP      AX
     *      F000:39A6 E664          OUT      64,AL
     *      F000:39A8 FB            STI
     *      F000:39A9 C3            RET
     *
     * This code *appears* to be trying to ensure that another keyboard interrupt won't occur until after the IRET,
     * but sadly, it looks to me like the CLI following the call to SHIP_IT is too late.  SHIP_IT should have been
     * written with PUSHF/CLI and POPF intro/outro sequences, thereby honoring the first CLI at the top of K26A and
     * eliminating the need for the second CLI (@F000:370E).
     *
     * Of course, in "real life", this was probably never a problem, because the 8042 probably wasn't fast enough to
     * generate another interrupt so soon after receiving the ChipSet.C8042.CMD.ENABLE_KBD command.  In my case, I ran
     * into this problem by 1) turning on "kbd" Debugger messages and 2) rapidly typing lots of keys.  The Debugger
     * messages bogged the machine down enough for me to hit the "window of opportunity", generating this message in
     * PC-DOS 3.20:
     *
     *      "FATAL: Internal Stack Failure, System Halted."
     *
     * and halting the system @0070:0923 (JMP 0923).
     *
     * That wasn't the only spot in the BIOS where I hit this problem; here's another "window of opportunity":
     *
     *      F000:3975 FA            CLI
     *      F000:3976 B020          MOV      AL,20
     *      F000:3978 E620          OUT      20,AL
     *      F000:397A B0AE          MOV      AL,AE
     *      F000:397C E81C00        CALL     SHIP_IT
     *      F000:397F B80291        MOV      AX,9102        <-- window of opportunity
     *      F000:3982 CD15          INT      15
     *      F000:3984 80269600FC    AND      [0096],FC
     *      F000:3989 E982FD        JMP      370E
     *
     * In this second, lengthier, example, I counted about 60 instructions being executed from the EOI @F000:3978 to
     * the final IRET @F000:3718, most of them in the INT 0x15 handler.  So, I'm going to double that count to 120
     * instructions, just to be safe, and pass that along to every setIRR() call we make here.
     *
     * @this {ChipSet}
     * @param {number} b
     * @return {boolean} (true if data accepted, false if declined)
     */
    receiveKbdData(b)
    {
        if (!COMPILED) this.printf(Messages.KBD + Messages.PORT, "chipset.receiveKbdData(%#04X)\n", b);
        if (this.model == ChipSet.MODEL_4860) {
            if (!(this.bNMI & ChipSet.NMI.KBD_LATCH)) {
                this.bNMI |= ChipSet.NMI.KBD_LATCH;
                this.bKbdData = b;
                if (b && (this.bNMI & ChipSet.NMI.ENABLE)) {
                    X86.helpInterrupt.call(this.cpu, X86.EXCEPTION.NMI);
                }
                return true;
            }
            return false;
        }
        if (this.model < ChipSet.MODEL_5170) {
            if (this.bPPIB & ChipSet.PPI_B.CLK_KBD) {
                this.bKbdData = b;
                if (b) {
                    this.setIRR(ChipSet.IRQ.KBD, 120);
                    this.b8041Status |= ChipSet.C8042.STATUS.OUTBUFF_FULL;
                }
                return true;
            }
            return false;
        }
        if (b) {
            if (!(this.b8042CmdData & ChipSet.C8042.DATA.CMD.NO_CLOCK)) {
                /*
                 * The next in8042OutBuff() will clear both of these bits and call kbd.checkBuffer(),
                 * which will call receiveKbdData() again if there's still keyboard data to process.
                 */
                if (!(this.b8042Status & (ChipSet.C8042.STATUS.OUTBUFF_FULL | ChipSet.C8042.STATUS.OUTBUFF_DELAY))) {
                    this.set8042OutBuff(b, true);
                    /*
                     * A delay of 4 instructions was originally requested as part of the the Keyboard's resetDevice()
                     * response, but a larger delay (120) is now needed for MODEL_5170 machines, per the discussion above.
                     */
                    this.setIRR(ChipSet.IRQ.KBD, 120);
                    return true;
                }
                if (!COMPILED) this.printf(Messages.KBD + Messages.PORT, "chipset.receiveKbdData(%#04X): output buffer full\n", b);
                return false;
            }
            if (!COMPILED) this.printf(Messages.KBD + Messages.PORT, "chipset.receiveKbdData(%#04X): disabled\n", b);
        }
        return false;
    }

    /**
     * in6300DIPSwitches(iDIP, port, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} iDIP (0 or 1)
     * @param {number} port (0x66 or 0x67)
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     * @return {number} simulated port value
     */
    in6300DIPSwitches(iDIP, port, addrFrom)
    {
        let b = this.aDIPSwitches[iDIP][1];
        this.printMessageIO(port, undefined, addrFrom, "DIPSW-" + iDIP, b, Messages.CHIPSET);
        return b;
    }

    /**
     * inCMOSAddr(port, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} port (0x70)
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     * @return {number} simulated port value
     */
    inCMOSAddr(port, addrFrom)
    {
        this.printMessageIO(port, undefined, addrFrom, "CMOS.ADDR", this.bCMOSAddr, Messages.CMOS);
        return this.bCMOSAddr;
    }

    /**
     * outCMOSAddr(port, bOut, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} port (0x70)
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to write the specified port)
     */
    outCMOSAddr(port, bOut, addrFrom)
    {
        this.printMessageIO(port, bOut, addrFrom, "CMOS.ADDR", undefined, Messages.CMOS);
        this.bCMOSAddr = bOut;
        this.bNMI = (this.bNMI & ~ChipSet.NMI.ENABLE) | ((bOut & ChipSet.CMOS.ADDR.NMI_DISABLE)? 0 : ChipSet.NMI.ENABLE);
    }

    /**
     * inCMOSData(port, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} port (0x71)
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     * @return {number} simulated port value
     */
    inCMOSData(port, addrFrom)
    {
        let bAddr = this.bCMOSAddr & ChipSet.CMOS.ADDR.MASK;
        let bIn = (bAddr <= ChipSet.CMOS.ADDR.STATUSD? this.getRTCByte(bAddr) : this.abCMOSData[bAddr]);
        if (this.messageEnabled(Messages.CMOS + Messages.PORT)) {
            this.printMessageIO(port, undefined, addrFrom, "CMOS.DATA[" + Str.toHexByte(bAddr) + "]", bIn, true);
        }
        if (addrFrom != null) {
            if (bAddr == ChipSet.CMOS.ADDR.STATUSC) {
                /*
                 * When software reads the STATUSC port, all interrupt bits (PF, AF, and UF) are automatically
                 * cleared, which in turn clears the IRQF bit, which in turn clears the IRQ.
                 */
                this.abCMOSData[bAddr] &= ChipSet.CMOS.STATUSC.RESERVED;
                if (bIn & ChipSet.CMOS.STATUSC.IRQF) this.clearIRR(ChipSet.IRQ.RTC);
                /*
                 * If we just cleared PF, and PIE is still set, then we need to make sure the next Periodic Interrupt
                 * occurs in a timely manner, too.
                 */
                if ((bIn & ChipSet.CMOS.STATUSC.PF) && (this.abCMOSData[ChipSet.CMOS.ADDR.STATUSB] & ChipSet.CMOS.STATUSB.PIE)) {
                    if (!COMPILED) this.printf(Messages.RTC, "RTC periodic interrupt cleared\n");
                    this.setRTCCycleLimit();
                }
            }
        }
        return bIn;
    }

    /**
     * outCMOSData(port, bOut, addrFrom)
     *
     * @this {ChipSet}
     * @param {number} port (0x71)
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to write the specified port)
     */
    outCMOSData(port, bOut, addrFrom)
    {
        let bAddr = this.bCMOSAddr & ChipSet.CMOS.ADDR.MASK;
        if (this.messageEnabled(Messages.CMOS + Messages.PORT)) {
            this.printMessageIO(port, bOut, addrFrom, "CMOS.DATA[" + Str.toHexByte(bAddr) + "]", undefined, true);
        }
        let bDelta = bOut ^ this.abCMOSData[bAddr];
        this.abCMOSData[bAddr] = (bAddr <= ChipSet.CMOS.ADDR.STATUSD? this.setRTCByte(bAddr, bOut) : bOut);
        if (bAddr == ChipSet.CMOS.ADDR.STATUSB && (bDelta & ChipSet.CMOS.STATUSB.PIE)) {
            if (bOut & ChipSet.CMOS.STATUSB.PIE) {
                if (!COMPILED) this.printf(Messages.RTC, "RTC periodic interrupts enabled\n");
                this.setRTCCycleLimit();
            } else {
                if (!COMPILED) this.printf(Messages.RTC, "RTC periodic interrupts disabled\n");
            }
        }
    }

    /**
     * inNMI(port, addrFrom)
     *
     * This handler is installed only for models before MODEL_5170; technically, this port is not readable,
     * except on the MODEL_4860, and even there, all a read is required to do is clear KBD_LATCH, but we go ahead
     * and return all the bits.
     *
     * @this {ChipSet}
     * @param {number} port (0xA0)
     * @param {number} [addrFrom] (not defined if the Debugger is trying to read the specified port)
     * @return {number} simulated port value
     */
    inNMI(port, addrFrom)
    {
        let bIn = this.bNMI;
        this.printMessageIO(port, undefined, addrFrom, "NMI", bIn);
        this.bNMI &= ~ChipSet.NMI.KBD_LATCH;
        return bIn;
    }

    /**
     * outNMI(port, bOut, addrFrom)
     *
     * This handler is installed only for models before MODEL_5170.
     *
     * @this {ChipSet}
     * @param {number} port (0xA0)
     * @param {number} bOut
     * @param {number} [addrFrom] (not defined if the Debugger is trying to write the specified port)
     */
    outNMI(port, bOut, addrFrom)
    {
        this.printMessageIO(port, bOut, addrFrom, "NMI");
        this.bNMI = bOut;
    }

    /**
     * outFPUClear(port, bOut, addrFrom)
     *
     * This handler is installed only for MODEL_5170.
     *
     * @this {ChipSet}
     * @param {number} port (0xF0)
     * @param {number} bOut (0x00 is the only expected output)
     * @param {number} [addrFrom] (not defined if the Debugger is trying to write the specified port)
     */
    outFPUClear(port, bOut, addrFrom)
    {
        this.printMessageIO(port, bOut, addrFrom, "FPU.CLEAR");

        if (this.fpuActive) this.fpuActive.clearBusy();
    }

    /**
     * outFPUReset(port, bOut, addrFrom)
     *
     * This handler is installed only for MODEL_5170.
     *
     * @this {ChipSet}
     * @param {number} port (0xF1)
     * @param {number} bOut (0x00 is the only expected output)
     * @param {number} [addrFrom] (not defined if the Debugger is trying to write the specified port)
     */
    outFPUReset(port, bOut, addrFrom)
    {
        this.printMessageIO(port, bOut, addrFrom, "FPU.RESET");

        if (this.fpuActive) this.fpuActive.resetFPU();
    }

    /**
     * intBIOSTimer(addr)
     *
     * INT 0x1A Quick Reference:
     *
     *      AH
     *      ----
     *      0x00    Get current clock count in CX:DX
     *      0x01    Set current clock count from CX:DX
     *      0x02    Get real-time clock using BCD (CH=hours, CL=minutes, DH=seconds)
     *      0x03    Set real-time clock using BCD (CH=hours, CL=minutes, DH=seconds, DL=1 if Daylight Savings Time option)
     *      0x04    Get real-time date using BCD (CH=century, CL=year, DH=month, DL=day)
     *      0x05    Set real-time date using BCD (CH=century, CL=year, DH=month, DL=day)
     *      0x06    Set alarm using BCD (CH=hours, CL=minutes, DH=seconds)
     *      0x07    Reset alarm
     *
     * @this {ChipSet}
     * @param {number} addr
     * @return {boolean} true to proceed with the INT 0x1A software interrupt, false to skip
     */
    intBIOSTimer(addr)
    {
        if (DEBUGGER) {
            if (this.messageEnabled(Messages.INT) && this.dbg.messageInt(Interrupts.TIMER, addr)) {
                /*
                 * By computing AH now, we get the incoming AH value; if we computed it below, along with
                 * the rest of the register values, we'd get the outgoing AH value, which is not what we want.
                 */
                let chipset = this;
                let AH = this.cpu.regEAX >> 8;
                let nCycles = this.cpu.getCycles();
                this.cpu.addIntReturn(addr, function onBIOSRTCReturn(nLevel) {
                    let sResult;
                    let CL = chipset.cpu.regEDX & 0xff;
                    let CH = chipset.cpu.regEDX >> 8;
                    let DL = chipset.cpu.regEDX & 0xff;
                    let DH = chipset.cpu.regEDX >> 8;
                    if (AH == 0x02 || AH == 0x03) {
                        sResult = " CH(hour)=" + Str.toHexWord(CH) + " CL(min)=" + Str.toHexByte(CL) + " DH(sec)=" + Str.toHexByte(DH);
                    } else if (AH == 0x04 || AH == 0x05) {
                        sResult = " CX(year)=" + Str.toHexWord(chipset.cpu.regECX) + " DH(month)=" + Str.toHexByte(DH) + " DL(day)=" + Str.toHexByte(DL);
                    }
                    let nCyclesDelta = -nCycles + (nCycles = chipset.cpu.getCycles());
                    chipset.dbg.messageIntReturn(Interrupts.TIMER, nLevel, nCyclesDelta, sResult);
                });
            }
        }
        return true;
    }

    /**
     * setSpeaker(enable)
     *
     * @this {ChipSet}
     * @param {number} [enable] (non-zero to enable speaker, zero to disable it; otherwise, update as appropriate)
     */
    setSpeaker(enable)
    {
        let fOn;
        if (enable !== undefined) {
            fOn = !!enable;
            if (fOn != this.fSpeakerEnabled) {
                //
                // Yielding doesn't seem to help the simulation of sound via rapid speaker toggling.
                //
                // if (this.cpu) {
                //     this.cpu.yieldCPU();
                // }
                this.fSpeakerEnabled = fOn;
            }
        } else {
            fOn = !!(this.fSpeakerEnabled && this.cpu && this.cpu.isRunning());
        }
        let freq = Math.round(ChipSet.TIMER_TICKS_PER_SEC / this.getTimerInit(ChipSet.PIT0.TIMER2));
        if (freq < 20 || freq > 20000) {
            /*
             * Treat frequencies outside the normal hearing range (below 20hz or above 20Khz) as a clever
             * attempt to turn sound off.
             */
            fOn = false;
        }
        if (this.contextAudio) {
            if (fOn && this.startAudio()) {
                /*
                 * Instead of setting the frequency's 'value' property directly, as we used to do, we use the
                 * setValueAtTime() method, with a time of zero, as a work-around to avoid the "easing" (aka
                 * "de-zippering") of the frequency that browsers like to do.  Supposedly de-zippering is an
                 * attempt to avoid "pops" if the frequency is altered while the wave is still rising or falling.
                 *
                 * Ditto for the gain's 'value'.
                 */
                // this.oscillatorAudio['frequency']['value'] = freq;
                this.oscillatorAudio['frequency']['setValueAtTime'](freq, 0);
                // this.volumeAudio['gain']['value'] = this.volumeInit;
                this.volumeAudio['gain']['setValueAtTime'](this.volumeInit, 0);
                this.printf(Messages.SPEAKER, "speaker on at  %dhz\n", freq);
            } else if (this.volumeAudio) {
                this.volumeAudio['gain']['setValueAtTime'](0, 0);
                this.printf(Messages.SPEAKER, "speaker off at %dhz\n", freq);
            }
        } else if (fOn && this.fSpeakerOn != fOn) {
            this.printf(Messages.SPEAKER, "BEEP\n");
        }
        this.fSpeakerOn = fOn;
    }

    /**
     * startAudio(event)
     *
     * NOTE: We currently use named properties rather than "dot" properties to access all the AudioContext
     * properties and methods, because we don't have any built-in declarations or externs for them, so neither
     * WebStorm nor the Closure Compiler recognize them.  We could live with the WebStorm inspection warnings,
     * but we definitely can't have the Closure Compiler renaming any of the properties -- and since it
     * automatically converts them all to "dot" properties, there's no incentive for us to do anything more.
     *
     * @this {ChipSet}
     * @param {Event} [event] object from a 'touch' event, if any
     * @return {boolean}
     */
    startAudio(event)
    {
        if (this.contextAudio) {
            /*
             * NOTE: If the machine happened to enable its speaker *before* the user generated an event
             * (eg, touchstart) that resulted in a call here, then we're too late -- at least as far as iOS
             * devices are concerned, because those devices require the oscillator's start() method to be
             * called in the context of a user-initiated event.
             *
             * So, for the benefit of iOS devices, when we finally receive a user-generated call, we will
             * simply recreate the oscillator.  This is a one-time work-around for the life of the machine.
             *
             * TODO: Consider adding a "Sound On/Off" button to all machines (probably in the top right corner,
             * where "Full Screen" and "Lock Pointer" buttons typically appear), at least on iOS devices.
             */
            if (event) {
                if (this.fUserSound) return true;
                this.oscillatorAudio = null;
                this.fUserSound = true;
            }
            if (this.oscillatorAudio) return true;
            try {
                this.oscillatorAudio = this.contextAudio['createOscillator']();
                if ('start' in this.oscillatorAudio) {  // early versions of Web Audio used noteOn() instead of start()
                    this.volumeAudio = this.contextAudio['createGain']();
                    this.oscillatorAudio['connect'](this.volumeAudio);
                    this.volumeAudio['connect'](this.contextAudio['destination']);
                    this.volumeAudio['gain']['setValueAtTime'](0, 0);
                    this.oscillatorAudio['type'] = "square";
                    this.oscillatorAudio['start'](0);
                    return true;
                }
            } catch(e) {
                this.notice("AudioContext exception: " + e.message);
                this.contextAudio = null;
            }
        }
        return false;
    }

    /**
     * messageBitsDMA(iChannel)
     *
     * @this {ChipSet}
     * @param {number} [iChannel] if the message is associated with a particular IRQ #
     * @return {number}
     */
    messageBitsDMA(iChannel)
    {
        let bitsMessage = 0;
        if (DEBUG) {
            bitsMessage = Messages.DATA;
            if (iChannel == ChipSet.DMA_FDC) {
                bitsMessage += Messages.FDC;
            } else if (iChannel == ChipSet.DMA_HDC) {
                bitsMessage += Messages.HDC;
            }
        }
        return bitsMessage;
    }

    /**
     * messageBitsIRQ(nIRQ)
     *
     * @this {ChipSet}
     * @param {number|undefined} [nIRQ] if the message is associated with a particular IRQ #
     * @return {number}
     */
    messageBitsIRQ(nIRQ)
    {
        let bitsMessage = Messages.IRQ;
        if (nIRQ == ChipSet.IRQ.TIMER0) {       // IRQ 0
            bitsMessage |= Messages.TIMER;
        } else if (nIRQ == ChipSet.IRQ.KBD) {   // IRQ 1
            bitsMessage |= Messages.KBD;
        } else if (nIRQ == ChipSet.IRQ.SLAVE) { // IRQ 2
            bitsMessage =  Messages.NONE;       // (we're not really interested in IRQ 2 itself, just the slaves)
        } else if (nIRQ == ChipSet.IRQ.COM1 || nIRQ == ChipSet.IRQ.COM2) {
            bitsMessage |= Messages.SERIAL;
        } else if (nIRQ == ChipSet.IRQ.XTC) {   // IRQ 5 (MODEL_5160)
            bitsMessage |= Messages.HDC;
        } else if (nIRQ == ChipSet.IRQ.FDC) {   // IRQ 6
            bitsMessage |= Messages.FDC;
        } else if (nIRQ == ChipSet.IRQ.RTC) {   // IRQ 8 (MODEL_5170 and up)
            bitsMessage |= Messages.RTC;
        } else if (nIRQ == ChipSet.IRQ.ATC1 || nIRQ == ChipSet.IRQ.ATC2) {      // IRQ 14 or 15 (MODEL_5170 and up)
            bitsMessage |= Messages.HDC;
        }
        return bitsMessage;
    }

    /**
     * checkDMA()
     *
     * Called by the CPU whenever INTR.DMA is set.
     *
     * @return {boolean} true if one or more async DMA channels are still active (unmasked), false to reset INTR.DMA
     *
     checkDMA()
     {
         let fActive = false;
         for (let iDMAC = 0; iDMAC < this.aDMACs; iDMAC++) {
             let controller = this.aDMACs[iDMAC];
             for (let iChannel = 0; iChannel < controller.aChannels.length; iChannel++) {
                 let channel = controller.aChannels[iChannel];
                 if (!channel.masked) {
                     this.advanceDMA(channel);
                     if (!channel.masked) fActive = true;
                 }
             }
         }
         return fActive;
     }
     */

    /**
     * ChipSet.init()
     *
     * This function operates on every HTML element of class "chipset", extracting the
     * JSON-encoded parameters for the ChipSet constructor from the element's "data-value"
     * attribute, invoking the constructor to create a ChipSet component, and then binding
     * any associated HTML controls to the new component.
     */
    static init()
    {
        let aeChipSet = Component.getElementsByClass(document, PCx86.APPCLASS, "chipset");
        for (let iChip = 0; iChip < aeChipSet.length; iChip++) {
            let eChipSet = aeChipSet[iChip];
            let parmsChipSet = Component.getComponentParms(eChipSet);
            let chipset = new ChipSet(parmsChipSet);
            Component.bindComponentControls(chipset, eChipSet, PCx86.APPCLASS);
            chipset.updateDIPSwitchDescriptions();
        }
    }
}


/*
 * 8041 Keyboard Controller I/O ports (MODEL_ATT_6300)
 *
 * The AT&T 6300 uses an 8041 for its Keyboard Controller, which has the following ports:
 *
 *      Port    Description
 *      ----    -----------
 *      0x60    Keyboard Scan Code (input)
 *      0x61    Keyboard Control Port (output)
 *      0x64    Keyboard Status Port (input)
 *
 * And the Keyboard Control Port (0x61) has the following bit definitions:
 *
 *      0x01    Speaker gate to 8253 (counter 2)
 *      0x02    Speaker data
 *      0x0C    Not used
 *      0x10    RAM Parity (NMI) Enable
 *      0x20    I/O Channel (NMI) Enable
 *      0x40    Keyboard Clock Reset
 *      0x80    Reset Interrupt Pending
 */

let ROMx86 = {}
/*
 * ROM BIOS Data Area (RBDA) definitions, in physical address form, using the same CAPITALIZED names
 * found in the original IBM PC ROM BIOS listing.
 */
ROMx86.BIOS = {
    RS232_BASE:     0x400,              // ADDRESSES OF RS232 ADAPTERS (4 words)
    PRINTER_BASE:   0x408,              // ADDRESSES OF PRINTERS (4 words)
    EQUIP_FLAG: {                       // INSTALLED HARDWARE (word)
        ADDR:       0x410,
        NUM_PRINT:      0xC000,         // NUMBER OF PRINTERS ATTACHED
        GAME_CTRL:      0x1000,         // GAME I/O ATTACHED
        NUM_RS232:      0x0E00,         // NUMBER OF RS232 CARDS ATTACHED
        NUM_DRIVES:     0x00C0,         // NUMBER OF DISKETTE DRIVES (00=1, 01=2, 10=3, 11=4) ONLY IF IPL_DRIVE SET
        VIDEO_MODE:     0x0030,         // INITIAL VIDEO MODE (00=UNUSED, 01=40X25 COLOR, 10=80X25 COLOR, 11=80X25 MONO)
        RAM_SIZE:       0x000C,         // PLANAR RAM SIZE (00=16K,01=32K,10=48K,11=64K)
        IPL_DRIVE:      0x0001          // IPL (Initial Program Load) FROM DISKETTE (ie, diskette drives exist)
    },
    MFG_TEST:       0x412,              // INITIALIZATION FLAG (byte)
    MEMORY_SIZE:    0x413,              // MEMORY SIZE IN K BYTES (word)
    IO_RAM_SIZE:    0x415,              // PC: MEMORY IN I/O CHANNEL (word)
    MFG_ERR_FLAG:   0x415,              // PC AT: SCRATCHPAD FOR MANUFACTURING ERROR CODES (2 bytes)
    COMPAQ_PREV_SC: 0x415,              // COMPAQ DESKPRO 386: PREVIOUS SCAN CODE (byte)
    COMPAQ_KEYCLICK:0x416,              // COMPAQ DESKPRO 386: KEYCLICK LOUDNESS (byte)
    /*
     * KEYBOARD DATA AREAS
     */
    KB_FLAG: {                          // FIRST BYTE OF KEYBOARD STATUS (byte)
        ADDR:       0x417,              //
        INS_STATE:      0x80,           // INSERT STATE IS ACTIVE
        CAPS_STATE:     0x40,           // CAPS LOCK STATE HAS BEEN TOGGLED
        NUM_STATE:      0x20,           // NUM LOCK STATE HAS BEEN TOGGLED
        SCROLL_STATE:   0x10,           // SCROLL LOCK STATE HAS BEEN TOGGLED
        ALT_SHIFT:      0x08,           // ALTERNATE SHIFT KEY DEPRESSED
        CTL_SHIFT:      0x04,           // CONTROL SHIFT KEY DEPRESSED
        LEFT_SHIFT:     0x02,           // LEFT SHIFT KEY DEPRESSED
        RIGHT_SHIFT:    0x01            // RIGHT SHIFT KEY DEPRESSED
    },
    KB_FLAG_1: {                        // SECOND BYTE OF KEYBOARD STATUS (byte)
        ADDR:       0x418,              //
        INS_SHIFT:      0x80,           // INSERT KEY IS DEPRESSED
        CAPS_SHIFT:     0x40,           // CAPS LOCK KEY IS DEPRESSED
        NUM_SHIFT:      0x20,           // NUM LOCK KEY IS DEPRESSED
        SCROLL_SHIFT:   0x10,           // SCROLL LOCK KEY IS DEPRESSED
        HOLD_STATE:     0x08            // SUSPEND KEY HAS BEEN TOGGLED
    },
    ALT_INPUT:      0x419,              // STORAGE FOR ALTERNATE KEYPAD ENTRY (byte)
    BUFFER_HEAD:    0x41A,              // POINTER TO HEAD OF KEYBOARD BUFFER (word)
    BUFFER_TAIL:    0x41C,              // POINTER TO TAIL OF KEYBOARD BUFFER (word)
    KB_BUFFER:      0x41E,              // ROOM FOR 15 ENTRIES (16 words)
    KB_BUFFER_END:  0x43E,              // HEAD = TAIL INDICATES THAT THE BUFFER IS EMPTY
    /*
     * DISKETTE DATA AREAS
     */
    SEEK_STATUS: {                      // DRIVE RECALIBRATION STATUS (byte)
        ADDR:       0x43E,              //
                                        //      BIT 3-0 = DRIVE 3-0 NEEDS RECAL BEFORE
                                        //      NEXT SEEK IF BIT IS = 0
        INT_FLAG:       0x80,           // INTERRUPT OCCURRENCE FLAG
    },
    MOTOR_STATUS:   0x43F,              // MOTOR STATUS (byte)
                                        //      BIT 3-0 = DRIVE 3-0 IS CURRENTLY RUNNING
                                        //      BIT 7 = CURRENT OPERATION IS A WRITE, REQUIRES DELAY
    MOTOR_COUNT:    0x440,              // TIME OUT COUNTER FOR DRIVE TURN OFF
                                        //      37 == TWO SECONDS OF COUNTS FOR MOTOR TURN OFF
    DISKETTE_STATUS: {                  // SINGLE BYTE OF RETURN CODE INFO FOR STATUS
        ADDR:       0x441,
        TIME_OUT:       0x80,           // ATTACHMENT FAILED TO RESPOND
        BAD_SEEK:       0x40,           // SEEK OPERATION FAILED
        BAD_NEC:        0x20,           // NEC CONTROLLER HAS FAILED
        BAD_CRC:        0x10,           // BAD CRC ON DISKETTE READ
        DMA_BOUNDARY:   0x09,           // ATTEMPT TO DMA ACROSS 64K BOUNDARY
        BAD_DMA:        0x08,           // DMA OVERRUN ON OPERATION
        RECORD_NOT_FND: 0x04,           // REQUESTED SECTOR NOT FOUND
        WRITE_PROTECT:  0x03,           // WRITE ATTEMPTED ON WRITE PROT DISK
        BAD_ADDR_MARK:  0x02,           // ADDRESS MARK NOT FOUND
        BAD_CMD:        0x01            // BAD COMMAND PASSED TO DISKETTE I/O
    },
    NEC_STATUS:     0x442,              // STATUS BYTES FROM NEC (7 bytes)
    /*
     * VIDEO DISPLAY DATA AREA
     */
    CRT_MODE:       0x449,              // CURRENT CRT MODE (byte)
    CRT_COLS:       0x44A,              // NUMBER OF COLUMNS ON SCREEN (word)
    CRT_LEN:        0x44C,              // LENGTH OF REGEN IN BYTES (word)
    CRT_START:      0x44E,              // STARTING ADDRESS IN REGEN BUFFER (word)
    CURSOR_POSN:    0x450,              // CURSOR FOR EACH OF UP TO 8 PAGES (8 words)
    CURSOR_MODE:    0x460,              // CURRENT CURSOR MODE SETTING (word)
    ACTIVE_PAGE:    0x462,              // CURRENT PAGE BEING DISPLAYED (byte)
    ADDR_6845:      0x463,              // BASE ADDRESS FOR ACTIVE DISPLAY CARD (word)
    CRT_MODE_SET:   0x465,              // CURRENT SETTING OF THE 3X8 REGISTER (byte)
    CRT_PALLETTE:   0x466,              // CURRENT PALLETTE SETTING COLOR CARD (byte)
    /*
     * CASSETTE DATA AREA
     */
    EDGE_CNT:       0x467,              // PC: TIME COUNT AT DATA EDGE (word)
    CRC_REG:        0x469,              // PC: CRC REGISTER (word)
    LAST_VAL:       0x46B,              // PC: LAST INPUT VALUE (byte)
    IO_ROM_INIT:    0x467,              // PC AT: POINTER TO ROM INITIALIZATION ROUTINE
    IO_ROM_SEG:     0x469,              // PC AT: POINTER TO I/O ROM SEGMENT
    INTR_FLAG:      0x46B,              // PC AT: FLAG INDICATING AN INTERRUPT HAPPENED
    /*
     * TIMER DATA AREA
     */
    TIMER_LOW:      0x46C,              // LOW WORD OF TIMER COUNT (word)
    TIMER_HIGH:     0x46E,              // HIGH WORD OF TIMER COUNT (word)
    TIMER_OFL:      0x470,              // TIMER HAS ROLLED OVER SINCE LAST READ (byte)
    /*
     * SYSTEM DATA AREA
     */
    BIOS_BREAK:     0x471,              // BIT 7 = 1 IF BREAK KEY HAS BEEN DEPRESSED (byte)
    /*
     * RESET_FLAG is the traditional end of the RBDA, as originally defined by the IBM PC
     */
    RESET_FLAG: {
        ADDR:       0x472,              // SET TO 0x1234 IF KEYBOARD RESET UNDERWAY (word)
        WARMBOOT:       0x1234          // this value indicates a "warm boot", bypassing memory tests
    },
    /*
     * FIXED DISK DATA AREAS
     */
    DISK_STATUS1:   0x474,              // PC AT: FIXED DISK STATUS (byte)
    HF_NUM:         0x475,              // PC AT: COUNT OF FIXED DISK DRIVES (byte)
    CONTROL_BYTE:   0x476,              // PC AT: HEAD CONTROL BYTE (byte)
    PORT_OFF:       0x477,              // PC AT: RESERVED (PORT OFFSET) (byte)
    /*
     * TIME-OUT VARIABLES
     */
    PRINT_TIM_OUT:  0x478,              // PC AT: TIME OUT COUNTERS FOR PRINTER RESPONSE (4 bytes)
    RS232_TIM_OUT:  0x47C,              // PC AT: TIME OUT COUNTERS FOR RS232 RESPONSE (4 bytes)
    /*
     * ADDITIONAL KEYBOARD DATA AREA
     */
    BUFFER_START:   0x480,              // PC AT: OFFSET OF KEYBOARD BUFFER START WITHIN SEGMENT 40H
    BUFFER_END:     0x482,              // PC AT: OFFSET OF END OF BUFFER
    /*
     * EGA/PGA DISPLAY WORK AREA
     */
    ROWS:           0x484,              // PC AT: ROWS ON THE ACTIVE SCREEN (LESS 1) (byte)
    POINTS:         0x485,              // PC AT: BYTES PER CHARACTER (word)
    INFO:           0x487,              // PC AT: MODE OPTIONS (byte)
    /*
     * INFO BITS:
     *
     *      0x80: HIGH BIT OF MODE SET, CLEAR/NOT CLEAR REGEN
     *      0x60: 256K OF VRAM
     *      0x40: 192K OF VRAM
     *      0x20: 128K OF VRAM
     *      0x10: RESERVED
     *      0x08: EGA ACTIVE MONITOR (0), EGA NOT ACTIVE (1)
     *      0x04: WAIT FOR DISPLAY ENABLE (1)
     *      0x02: EGA HAS A MONOCHROME ATTACHED
     *      0x01: SET C_TYPE EMULATE ACTIVE (0)
     */
    INFO_3:         0x488,              // PC AT: FEATURE BIT SWITCHES (1 byte, plus 2 reserved bytes)
    /*
     *     40:88  byte  PCjr: third keyboard status byte
     *                  EGA feature bit switches, emulated on VGA
     *
     *         |7|6|5|4|3|2|1|0| EGA feature bit switches (EGA+)
     *          | | | | | | | `-- EGA SW1 config (1=off)
     *          | | | | | | `--- EGA SW2 config (1=off)
     *          | | | | | `---- EGA SW3 config (1=off)
     *          | | | | `----- EGA SW4 config (1=off)
     *          | | | `------ Input FEAT0 (ISR0 bit 5) after output on FCR0
     *          | | `------- Input FEAT0 (ISR0 bit 6) after output on FCR0
     *          | `-------- Input FEAT1 (ISR0 bit 5) after output on FCR1
     *          `--------- Input FEAT1 (ISR0 bit 6) after output on FCR1
     *
     *     40:89  byte  Video display data area (MCGA and VGA)
     *
     *         |7|6|5|4|3|2|1|0| Video display data area (MCGA and VGA)
     *          | | | | | | | `-- 1=VGA is active
     *          | | | | | | `--- 1=gray scale is enabled
     *          | | | | | `---- 1=using monochrome monitor
     *          | | | | `----- 1=default palette loading is disabled
     *          | | | `------ see table below
     *          | | `------- reserved
     *          | `--------  1=display switching enabled
     *          `--------- alphanumeric scan lines (see table below)
     *
     *           Bit7    Bit4   Scan Lines
     *             0       0    350 line mode
     *             0       1    400 line mode
     *             1       0    200 line mode
     *             1       1    reserved
     */
    /*
     * ADDITIONAL MEDIA DATA
     */
    LASTRATE:       0x48B,              // PC AT: LAST DISKETTE DATA RATE SELECTED (byte)
    HF_STATUS:      0x48C,              // PC AT: STATUS REGISTER (byte)
    HF_ERROR:       0x48D,              // PC AT: ERROR REGISTER (byte)
    HF_INT_FLAG:    0x48E,              // PC AT: FIXED DISK INTERRUPT FLAG (byte)
    HF_CNTRL:       0x48F,              // PC AT: COMBO FIXED DISK/DISKETTE CARD BIT 0=1 (byte)
    DSK_STATE:      0x490,              // PC AT: DRIVE 0/1 MEDIA/OPERATION STATES (4 bytes)
    DSK_TRK:        0x494,              // PC AT: DRIVE 0/1 PRESENT CYLINDER (2 bytes)
    /*
     * ADDITIONAL KEYBOARD FLAGS
     */
    KB_FLAG_3: {
        ADDR:       0x496,              // PC AT: KEYBOARD MODE STATE AND TYPE FLAGS (byte)
        LC_E1:          0b00000001,     // LAST CODE WAS THE E1 HIDDEN CODE
        LC_E0:          0b00000010,     // LAST CODE WAS THE E0 HIDDEN CODE
        R_CTL_SHIFT:    0b00000100,     // RIGHT CTL KEY DOWN
        R_ALT_SHIFT:    0b00001000,     // RIGHT ALT KEY DOWN
        GRAPH_ON:       0b00001000,     // ALT GRAPHICS KEY DOWN (WT ONLY)
        KBX:            0b00010000,     // ENHANCED KEYBOARD INSTALLED
        SET_NUM_LK:     0b00100000,     // FORCE NUM LOCK IF READ ID AND KBX
        LC_AB:          0b01000000,     // LAST CHARACTER WAS FIRST ID CHARACTER
        RD_ID:          0b10000000      // DOING A READ ID (MUST BE BIT0)
    },
    KB_FLAG_2: {
        ADDR:       0x497,              // PC AT: KEYBOARD LED FLAGS (byte)
        KB_LEDS:        0b00000111,     // KEYBOARD LED STATE BITS
        SCROLL_LOCK:    0b00000001,     // SCROLL LOCK INDICATOR
        NUM_LOCK:       0b00000010,     // NUM LOCK INDICATOR
        CAPS_LOCK:      0b00000100,     // CAPS LOCK INDICATOR
        KB_FA:          0b00010000,     // ACKNOWLEDGMENT RECEIVED
        KB_FE:          0b00100000,     // RESEND RECEIVED FLAG
        KB_PR_LED:      0b01000000,     // MODE INDICATOR UPDATE
        KB_ERR:         0b10000000      // KEYBOARD TRANSMIT ERROR FLAG
    },
    /*
     * REAL TIME CLOCK DATA AREA
     */
    USER_FLAG:      0x498,              // PC AT: OFFSET ADDRESS OF USERS WAIT FLAG (word)
    USER_FLAG_SEG:  0x49A,              // PC AT: SEGMENT ADDRESS OF USER WAIT FLAG (word)
    RTC_LOW:        0x49C,              // PC AT: LOW WORD OF USER WAIT FLAG (word)
    RTC_HIGH:       0x49E,              // PC AT: HIGH WORD OF USER WAIT FLAG (word)
    RTC_WAIT_FLAG:  0x4A0,              // PC AT: WAIT ACTIVE FLAG (01=BUSY, 80=POSTED, 00=POST ACKNOWLEDGED) (byte)
    /*
     * AREA FOR NETWORK ADAPTER
     */
    NET:            0x4A1,              // PC AT: RESERVED FOR NETWORK ADAPTERS (7 bytes)
    /*
     * EGA/PGA PALETTE POINTER
     */
    SAVE_PTR:       0x4A8,              // PC AT: POINTER TO EGA PARAMETER CONTROL BLOCK (2 words)
    /*
     * DATA AREA - PRINT SCREEN
     */
    STATUS_BYTE:    0x500               // PRINT SCREEN STATUS BYTE (00=READY/OK, 01=BUSY, FF=ERROR) (byte)
};

//TODO KBD -> sends to chipset

const VideoX86 = {
    model: 'vga',
    mode: null,
    cols: 0,
    rows: 0,
    fontrom: 0,
    MODELS = {
        "mda": [VideoX86.MODES.MDA_80X25],
        "cga": [VideoX86.MODES.CGA_80X25],
        "ega": [VideoX86.MODES.CGA_80X25],
        "vga": [VideoX86.MODES.CGA_80X25]
    },
    MODES = {
        CGA_40X25_BW:       0,
        CGA_40X25:          1,
        CGA_80X25_BW:       2,
        CGA_80X25:          3,
        CGA_320X200:        4,
        CGA_320X200_BW:     5,
        CGA_640X200:        6,
        MDA_80X25:          7,
        EGA_320X200:        0x0D,   // mapped at A000:0000, color, 4bpp, planar
        EGA_640X200:        0x0E,   // mapped at A000:0000, color, 4bpp, planar
        EGA_640X350_MONO:   0x0F,   // mapped at A000:0000, mono,  2bpp, planar
        EGA_640X350:        0x10,   // mapped at A000:0000, color, 4bpp, planar
        VGA_640X480_MONO:   0x11,   // mapped at A000:0000, mono,  2bpp, planar
        VGA_640X480:        0x12,   // mapped at A000:0000, color, 4bpp, planar
        VGA_320X200:        0x13,   // mapped at A000:0000, color, 8bpp, linear
        /*
         * The remaining mode identifiers are for internal use only; there is no correlation with any
         * publicly defined BIOS modes, and overlap with any third-party mode numbers is purely coincidental.
         */
        VGA_320X200P:       0x14,   // mapped at A000:0000, color, 8bpp, planar
        VGA_320X240P:       0x15,   // mapped at A000:0000, color, 8bpp, planar ("Mode X")
        VGA_320X400P:       0x16,   // mapped at A000:0000, color, 8bpp, planar
        /*
         * Here's where we might assign additional identifiers to certain unique combinations, like the
         * fTextGraphicsHybrid 320x400 mode that Windows 95 uses (ie, when the buffer is mapped to B800:0000
         * instead of A000:0000 and is configured for text mode access, but graphics are still being displayed
         * from the second half of video memory).
         */
        UNKNOWN:            0xFF
    },
    
    UPDATES_PER_SECOND: 60
}

/*
 * MDA attribute byte definitions
 *
 * For MDA, only the following group of ATTR definitions are supported; any FGND/BGND value combinations
 * outside this group will be treated as "normal" (ATTR_FGND_WHITE | ATTR_BGND_BLACK).
 *
 * NOTE: Assuming MDA.MODE.BLINK_ENABLE is set (which the ROM BIOS sets by default), ATTR_BGND_BLINK will
 * cause the *foreground* element of the cell to blink, even though it is part of the *background* attribute bits.
 *
 * Regarding blink rate, characters are supposed to blink every 16 vertical frames, which amounts to .26667 blinks
 * per second, assuming a 60Hz vertical refresh rate.  So roughly every 267ms, we need to take care of any blinking
 * characters.  updateScreen() maintains a global count (cBlinkVisible) of blinking characters, to simplify the
 * decision of when to redraw the screen.
 */
VideoX86.ATTRS = {};
VideoX86.ATTRS.FGND_BLACK  = 0x00;
VideoX86.ATTRS.FGND_ULINE  = 0x01;
VideoX86.ATTRS.FGND_WHITE  = 0x07;
VideoX86.ATTRS.FGND_BRIGHT = 0x08;
VideoX86.ATTRS.BGND_BLACK  = 0x00;
VideoX86.ATTRS.BGND_WHITE  = 0x70;
VideoX86.ATTRS.BGND_BLINK  = 0x80;
VideoX86.ATTRS.BGND_BRIGHT = 0x80;
VideoX86.ATTRS.DRAW_FGND   = 0x100;        // this is an internal attribute bit, indicating the foreground should be drawn
VideoX86.ATTRS.DRAW_CURSOR = 0x200;        // this is an internal attribute bit, indicating when the cursor should be drawn

/*
 * Here's a "cheat sheet" for attribute byte combinations that the IBM MDA could have supported.  The original (Aug 1981)
 * IBM Tech Ref is very terse and implies that only those marked with * are actually supported.
 *
 *     *0x00: non-display                       ATTR_FGND_BLACK |                    ATTR_BGND_BLACK
 *     *0x01: underline                         ATTR_FGND_ULINE |                    ATTR_BGND_BLACK
 *     *0x07: normal (white on black)           ATTR_FGND_WHITE |                    ATTR_BGND_BLACK
 *    **0x09: bright underline                  ATTR_FGND_ULINE | ATTR_FGND_BRIGHT | ATTR_BGND_BLACK
 *    **0x0F: bold (bright white on black)      ATTR_FGND_WHITE | ATTR_FGND_BRIGHT | ATTR_BGND_BLACK
 *     *0x70: reverse (black on white)          ATTR_FGND_BLACK |                  | ATTR_BGND_WHITE
 *      0x81: blinking underline                ATTR_FGND_ULINE |                  | ATTR_BGND_BLINK (or dim background if blink disabled)
 *    **0x87: blinking normal                   ATTR_FGND_WHITE |                  | ATTR_BGND_BLINK (or dim background if blink disabled)
 *      0x89: blinking bright underline         ATTR_FGND_ULINE | ATTR_FGND_BRIGHT | ATTR_BGND_BLINK (or dim background if blink disabled)
 *    **0x8F: blinking bold                     ATTR_FGND_WHITE | ATTR_FGND_BRIGHT | ATTR_BGND_BLINK (or dim background if blink disabled)
 *    **0xF0: blinking reverse                  ATTR_FGND_WHITE | ATTR_FGND_BRIGHT | ATTR_BGND_BLINK (or bright background if blink disabled)
 *
 * Unsupported attributes reportedly display as "normal" (ATTR_FGND_WHITE | ATTR_BGND_BLACK).  However, precisely which
 * attributes are unsupported on the MDA varies depending on the source.  Some sources (eg, the IBM Tech Ref) imply that
 * only those marked by * are supported, while others (eg, some--but not all--Peter Norton guides) include those marked
 * by **, and still others include ALL the combinations listed above.
 *
 * Furthermore, according to http://www.seasip.info/VintagePC/mda.html:
 *
 *      Attributes 0x00, 0x08, 0x80 and 0x88 display as black space;
 *      Attribute 0x78 displays as dark green on green; depending on the monitor, there may be a green "halo" where the dark and bright bits meet;
 *      Attribute 0xF0 displays as a blinking version of 0x70 if blink enabled, and black on bright green otherwise;
 *      Attribute 0xF8 displays as a blinking version of 0x78 if blink enabled, and as dark green on bright green otherwise.
 *
 * However, I'm rather skeptical about supporting 0x78 and 0xF8, until I see some evidence that "bright black" actually
 * produced dark green on IBM equipment; it also doesn't sound like a combination many people would have used.  I'll probably
 * treat all of 0x08, 0x80 and 0x88 the same as 0x00, only because it seems logical (they're all "black on black" combinations
 * with only BRIGHT and/or BLINK bits set). Beyond that, I'll likely treat any other combination not listed in the above cheat
 * sheet as "normal".
 *
 * All the discrepancies/disagreements I've found are probably due in part to the proliferation of IBM and non-IBM MDA
 * cards, combined with IBM and non-IBM monochrome monitors, and people assuming that their non-IBM card and/or monitor
 * behaved exactly like the original IBM equipment, which probably wasn't true in all cases.
 *
 * I would like to limit my MDA display support to EXACTLY everything that the IBM MDA supported and nothing more, but
 * since there will be combinations that will logically "fall out" unless I specifically exclude them, it's very likely
 * this implementation will end up being a superset.
 */

/*
 * CGA attribute byte definitions; these simply extend the set of MDA attributes, with the exception of ATTR_FNGD_ULINE,
 * which the CGA can treat only as ATTR_FGND_BLUE.
 */
VideoX86.ATTRS.FGND_BLUE       = 0x01;
VideoX86.ATTRS.FGND_GREEN      = 0x02;
VideoX86.ATTRS.FGND_CYAN       = 0x03;
VideoX86.ATTRS.FGND_RED        = 0x04;
VideoX86.ATTRS.FGND_MAGENTA    = 0x05;
VideoX86.ATTRS.FGND_BROWN      = 0x06;

VideoX86.ATTRS.BGND_BLUE       = 0x10;
VideoX86.ATTRS.BGND_GREEN      = 0x20;
VideoX86.ATTRS.BGND_CYAN       = 0x30;
VideoX86.ATTRS.BGND_RED        = 0x40;
VideoX86.ATTRS.BGND_MAGENTA    = 0x50;
VideoX86.ATTRS.BGND_BROWN      = 0x60;

/*
 * For the MDA, there are currently three distinct "colors": off, normal, and intense.  There are
 * also two variations of normal and intense: with and without underlining.  Technically, underlining
 * makes no difference in the actual color, but because different fonts must be built for each, and
 * because the presence of underlining is determined by character's attribute (aka "color") bits, we
 * use separate color indices for each variation; so ODD color indices are used for underlining and
 * EVEN indices are not.
 *
 * I'm still not sure about dark green (see comments above); if it exists on a standard IBM monitor
 * (model 5151), then I may need to support another "color": dark.  For now, the attributes that may
 * require dark (ie, 0x78 and 0xF8) have their foreground attribute (0x8) mapped to 0x0 (off) instead.
 */
VideoX86.aMDAColors = [
    [0x00, 0x00, 0x00, 0xff],       // 0: off
    [0x09, 0xcc, 0x50, 0xff],       // 1: normal (with underlining)
    [0x09, 0xcc, 0x50, 0xff],       // 2: normal
    [0x3c, 0xff, 0x83, 0xff],       // 3: intense (with underlining)
    [0x3c, 0xff, 0x83, 0xff]        // 4: intense
];
/*
 * Each of the following FGND attribute values are mapped to one of the above "colors":
 *
 *      0x0: black font (per above, attribute value 0x8 is also mapped to attribute 0x0)
 *      0x1: green font with underlining
 *      0x7: green font without underlining (attribute values 0x2-0x6 are mapped to attribute 0x7)
 *      0x9: bright green font with underlining
 *      0xf: bright green font without underlining (attribute values 0xa-0xe are mapped to attribute 0xf)
 *
 * MDA attributes form an index into aMDAColorMap, which in turn provides an index into aMDAColors.
 */
VideoX86.aMDAColorMap = [0x0, 0x1, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x0, 0x3, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4];

VideoX86.aCGAColors = [
    [0x00, 0x00, 0x00, 0xff],   // 0x00: ATTR_FGND_BLACK
    [0x00, 0x00, 0xaa, 0xff],   // 0x01: ATTR_FGND_BLUE
    [0x00, 0xaa, 0x00, 0xff],   // 0x02: ATTR_FGND_GREEN
    [0x00, 0xaa, 0xaa, 0xff],   // 0x03: ATTR_FGND_CYAN
    [0xaa, 0x00, 0x00, 0xff],   // 0x04: ATTR_FGND_RED
    [0xaa, 0x00, 0xaa, 0xff],   // 0x05: ATTR_FGND_MAGENTA
    [0xaa, 0x55, 0x00, 0xff],   // 0x06: ATTR_FGND_BROWN
    [0xaa, 0xaa, 0xaa, 0xff],   // 0x07: ATTR_FGND_WHITE                      (aka light gray)
    [0x55, 0x55, 0x55, 0xff],   // 0x08: ATTR_FGND_BLACK   | ATTR_FGND_BRIGHT (aka gray)
    [0x55, 0x55, 0xff, 0xff],   // 0x09: ATTR_FGND_BLUE    | ATTR_FGND_BRIGHT
    [0x55, 0xff, 0x55, 0xff],   // 0x0A: ATTR_FGND_GREEN   | ATTR_FGND_BRIGHT
    [0x55, 0xff, 0xff, 0xff],   // 0x0B: ATTR_FGND_CYAN    | ATTR_FGND_BRIGHT
    [0xff, 0x55, 0x55, 0xff],   // 0x0C: ATTR_FGND_RED     | ATTR_FGND_BRIGHT
    [0xff, 0x55, 0xff, 0xff],   // 0x0D: ATTR_FGND_MAGENTA | ATTR_FGND_BRIGHT
    [0xff, 0xff, 0x55, 0xff],   // 0x0E: ATTR_FGND_BROWN   | ATTR_FGND_BRIGHT (aka yellow)
    [0xff, 0xff, 0xff, 0xff]    // 0x0F: ATTR_FGND_WHITE   | ATTR_FGND_BRIGHT (aka white)
];

VideoX86.aCGAColorSet0 = [VideoX86.ATTRS.FGND_GREEN, VideoX86.ATTRS.FGND_RED,     VideoX86.ATTRS.FGND_BROWN];
VideoX86.aCGAColorSet1 = [VideoX86.ATTRS.FGND_CYAN,  VideoX86.ATTRS.FGND_MAGENTA, VideoX86.ATTRS.FGND_WHITE];

/*
 * Here is the EGA BIOS default ATC palette register set for color text modes, from which getCardColors()
 * builds a default RGB array, similar to aCGAColors above.
 */
VideoX86.aEGAPalDef = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x14, 0x07, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F];

VideoX86.aEGAByteToDW = [
    0x00000000,   0x000000ff,   0x0000ff00,   0x0000ffff,
    0x00ff0000,   0x00ff00ff,   0x00ffff00,   0x00ffffff,
    0xff000000|0, 0xff0000ff|0, 0xff00ff00|0, 0xff00ffff|0,
    0xffff0000|0, 0xffff00ff|0, 0xffffff00|0, 0xffffffff|0
];

VideoX86.aEGADWToByte = [];
VideoX86.aEGADWToByte[0x00000000]   = 0x0;
VideoX86.aEGADWToByte[0x00000080]   = 0x1;
VideoX86.aEGADWToByte[0x00008000]   = 0x2;
VideoX86.aEGADWToByte[0x00008080]   = 0x3;
VideoX86.aEGADWToByte[0x00800000]   = 0x4;
VideoX86.aEGADWToByte[0x00800080]   = 0x5;
VideoX86.aEGADWToByte[0x00808000]   = 0x6;
VideoX86.aEGADWToByte[0x00808080]   = 0x7;
VideoX86.aEGADWToByte[0x80000000|0] = 0x8;
VideoX86.aEGADWToByte[0x80000080|0] = 0x9;
VideoX86.aEGADWToByte[0x80008000|0] = 0xa;
VideoX86.aEGADWToByte[0x80008080|0] = 0xb;
VideoX86.aEGADWToByte[0x80800000|0] = 0xc;
VideoX86.aEGADWToByte[0x80800080|0] = 0xd;
VideoX86.aEGADWToByte[0x80808000|0] = 0xe;
VideoX86.aEGADWToByte[0x80808080|0] = 0xf;

/*
 * Card Specifications
 *
 * We support dynamically switching between MDA and CGA cards by simply flipping switches on
 * the virtual SW1 switch block and resetting the machine.  However, I'm not sure I'll support
 * dynamically switching the EGA card the same way; there's certainly no UI for it at this point.
 *
 * For each supported card, there is a cardSpec array that the Card class uses to initialize the
 * card's defaults:
 *
 *      [0]: card descriptor
 *      [1]: default CRTC port address
 *      [2]: default video buffer address
 *      [3]: default video buffer size
 *      [4]: total on-board memory (if no "memory" parm was specified)
 *      [5]: default monitor type
 *
 * If total on-board memory is zero, then addMemory() will simply add the specified video buffer
 * to the address space; otherwise, we will allocate an internal buffer (adwMemory) and tell addMemory()
 * to map it to the video buffer address.  The latter approach gives us total control over the buffer;
 * refer to getMemoryAccess().
 */
VideoX86.cardSpecs = [];
VideoX86.cardSpecs[VideoX86.CARD.MDA] = ["MDA", Card.MDA.CRTC.INDX.PORT, 0xB0000, 0x01000, 0x01000, ChipSet.MONITOR.MONO];
VideoX86.cardSpecs[VideoX86.CARD.CGA] = ["CGA", Card.CGA.CRTC.INDX.PORT, 0xB8000, 0x04000, 0x04000, ChipSet.MONITOR.COLOR];
VideoX86.cardSpecs[VideoX86.CARD.EGA] = ["EGA", Card.CGA.CRTC.INDX.PORT, 0xB8000, 0x04000, 0x10000, ChipSet.MONITOR.EGACOLOR];
VideoX86.cardSpecs[VideoX86.CARD.VGA] = ["VGA", Card.CGA.CRTC.INDX.PORT, 0xB8000, 0x04000, 0x40000, ChipSet.MONITOR.VGACOLOR];

/*
 * Values for nTouchConfig; a value will be selected based on the sTouchScreen configuration parameter.
 */
VideoX86.TOUCH = {
    NONE:       0,
    DEFAULT:    1,
    KEYGRID:    2,
    MOUSE:      3
};

/*
 * Why simulate a SPACE if the tap is in the middle third (center) of the screen?  Well, apparently
 * I didn't explain earlier that the WHOLE reason I originally added KEYGRID support (before it was
 * even called KEYGRID support) was to make the 1985 game "Rogue" (pcjs.org/apps/pcx86/1985/rogue)
 * more fun to play on an iPad (the space-bar is a commonly required key).
 */
VideoX86.KEYGRID = [
    [Kbdx86.SIMCODE.HOME, Kbdx86.SIMCODE.UP,    Kbdx86.SIMCODE.PGUP],
    [Kbdx86.SIMCODE.LEFT, Kbdx86.SIMCODE.SPACE, Kbdx86.SIMCODE.RIGHT],
    [Kbdx86.SIMCODE.END,  Kbdx86.SIMCODE.DOWN,  Kbdx86.SIMCODE.PGDN],
];


//TODO PARALLEL PORT?
let ParallelPort = {in:[],out:[]}



let Mouse = {};

Mouse.INPORT = {
    ADDR: {
        PORT:       0x23C,
        STATUS:     0x00,       // InPort Status Register
        X:          0x01,       // InPort X Movement Register
        Y:          0x02,       // InPort Y Movement Register
        ISTAT:      0x05,       // InPort Interface Status Register
        ICTRL:      0x06,       // InPort Interface Control Register
        MODE:       0x07        // InPort Mode Register
    },
    DATA: {
        /*
         * The internal register read or written via this port is determined by the value written to ADDR.PORT
         */
        PORT:       0x23D,
        STATUS:     {           // InPort Status Register (0)
            B3:     0x01,       // Status button 3
            B2:     0x02,       // Status button 2
            B1:     0x04,       // Status button 1
            DB3:    0x08,       // Delta button 3
            DB2:    0x10,       // Delta button 2
            DB1:    0x20,       // Delta button 1
            MOVE:   0x40,       // Movement
            PACKET: 0x80        // Packet complete
        },
        MODE: {                 // InPort Mode Register (7)
            HOLD:   0x20        // hold the status for reading
        }
    },
    ID: {
        /*
         * The initial read returns the Chip ID; alternate reads return a byte containing the InPort revision number
         * in the low nibble and the InPort version number in the high nibble.
         */
        PORT:       0x23E,
        CHIP:       0xDE        // InPort Chip ID
    },
    TEST: {
        PORT:       0x23F
    }
};

/*
 * From http://paulbourke.net/dataformats/serialmouse:
 *
 *      The old MicroSoft serial mouse, while no longer in general use, can be employed to provide a low cost input device,
 *      for example, coupling the internal mechanism to other moving objects. The serial protocol for the mouse is:
 *
 *          1200 baud, 7 bit, 1 stop bit, no parity.
 *
 *      The pinout of the connector follows the standard serial interface, as shown below:
 *
 *          Pin     Abbr    Description
 *          1       DCD     Data Carrier Detect
 *          2       RD      Receive Data            [serial data from mouse to host]
 *          3       TD      Transmit Data
 *          4       DTR     Data Terminal Ready     [used to provide positive voltage to mouse, plus reset/detection]
 *          5       SG      Signal Ground
 *          6       DSR     Data Set Ready
 *          7       RTS     Request To Send         [used to provide positive voltage to mouse]
 *          8       CTS     Clear To Send
 *          9       RI      Ring
 *
 *      Every time the mouse changes state (moved or button pressed) a three byte "packet" is sent to the serial interface.
 *      For reasons known only to the engineers, the data is arranged as follows, most notably the two high order bits for the
 *      x and y coordinates share the first byte with the button status.
 *
 *                      D6  D5  D4  D3  D2  D1  D0
 *          1st byte    1   LB  RB  Y7  Y6  X7  X6
 *          2nd byte    0   X5  X4  X3  X2  X1  X0
 *          3rd byte    0   Y5  Y4  Y3  Y2  Y1  Y0
 *
 *      where:
 *
 *          LB is the state of the left button, 1 = pressed, 0 = released.
 *          RB is the state of the right button, 1 = pressed, 0 = released
 *          X0-7 is movement of the mouse in the X direction since the last packet. Positive movement is toward the right.
 *          Y0-7 is movement of the mouse in the Y direction since the last packet. Positive movement is back, toward the user.
 *
 * From http://www.kryslix.com/nsfaq/Q.12.html:
 *
 *      The Microsoft serial mouse is the most popular 2-button mouse. It is supported by all major operating systems.
 *      The maximum tracking rate for a Microsoft mouse is 40 reports/second * 127 counts per report, in other words, 5080 counts
 *      per second. The most common range for mice is is 100 to 400 CPI (counts per inch) but can be up to 1000 CPI. A 100 CPI mouse
 *      can discriminate motion up to 50.8 inches/second while a 400 CPI mouse can only discriminate motion up to 12.7 inches/second.
 *
 *          9-pin  25-pin    Line    Comments
 *          shell  1         GND
 *          3      2         TD      Serial data from host to mouse (only for power)
 *          2      3         RD      Serial data from mouse to host
 *          7      4         RTS     Positive voltage to mouse
 *          8      5         CTS
 *          6      6         DSR
 *          5      7         SGND
 *          4      20        DTR     Positive voltage to mouse and reset/detection
 *
 *      To function correctly, both the RTS and DTR lines must be positive. DTR/DSR and RTS/CTS must NOT be shorted.
 *      RTS may be toggled negative for at least 100ms to reset the mouse. (After a cold boot, the RTS line is usually negative.
 *      This provides an automatic toggle when RTS is brought positive). When DTR is toggled the mouse should send a single byte
 *      (0x4D, ASCII 'M').
 *
 *      Serial data parameters: 1200bps, 7 data bits, 1 stop bit
 *
 *      Data is sent in 3 byte packets for each event (a button is pressed or released, or the mouse moves):
 *
 *                  D7  D6  D5  D4  D3  D2  D1  D0
 *          Byte 1  X   1   LB  RB  Y7  Y6  X7  X6
 *          Byte 2  X   0   X5  X4  X3  X2  X1  X0
 *          Byte 3  X   0   Y5  Y4  Y3  Y2  Y1  Y0
 *
 *      LB is the state of the left button (1 means down).
 *      RB is the state of the right button (1 means down).
 *      X7-X0 movement in X direction since last packet (signed byte).
 *      Y7-Y0 movement in Y direction since last packet (signed byte).
 *      The high order bit of each byte (D7) is ignored. Bit D6 indicates the start of an event, which allows the software to
 *      synchronize with the mouse.
 */
Mouse.SERIAL = {
    ID:     0x4D
};

let FDC = {};

/*
 * FDC Data Register (0x3F5, read-write)
 */
FDC.REG_DATA = {
    PORT:      0x3F5,
    /*
     * FDC Commands
     *
     * NOTE: FDC command bytes need to be masked with FDC.REG_DATA.CMD.MASK before comparing to the values below, since a
     * number of commands use the following additional bits as follows:
     *
     *      SK (0x20): Skip Deleted Data Address Mark
     *      MF (0x40): Modified Frequency Modulation (as opposed to FM or Frequency Modulation)
     *      MT (0x80): multi-track operation (ie, data processed under both head 0 and head 1)
     *
     * We don't support MT (Multi-Track) operations at this time, and the MF and SK designations cannot be supported as long
     * as our diskette images contain only the original data bytes without any formatting information.
     */
    CMD: {
        READ_TRACK:     0x02,
        SPECIFY:        0x03,
        SENSE_DRIVE:    0x04,
        WRITE_DATA:     0x05,
        READ_DATA:      0x06,
        RECALIBRATE:    0x07,
        SENSE_INT:      0x08,           // this command is used to clear the FDC interrupt following the clearing/setting of FDC.REG_OUTPUT.ENABLE
        WRITE_DEL_DATA: 0x09,
        READ_ID:        0x0A,
        READ_DEL_DATA:  0x0C,
        FORMAT_TRACK:   0x0D,
        SEEK:           0x0F,
        SCAN_EQUAL:     0x11,
        SCAN_LO_EQUAL:  0x19,
        SCAN_HI_EQUAL:  0x1D,
        MASK:           0x1F,
        SK:             0x20,           // SK (Skip Deleted Data Address Mark)
        MF:             0x40,           // MF (Modified Frequency Modulation)
        MT:             0x80            // MT (Multi-Track; ie, data under both heads will be processed)
    },
    /*
     * FDC status/error results, generally assigned according to the corresponding ST0, ST1, ST2 or ST3 status bit.
     *
     * TODO: Determine when EQUIP_CHECK is *really* set; also, "77 step pulses" sounds suspiciously like a typo (it's not 79?)
     */
    RES: {
        NONE:           0x00000000,     // ST0 (IC): Normal termination of command (NT)
        NOT_READY:      0x00000008,     // ST0 (NR): When the FDD is in the not-ready state and a read or write command is issued, this flag is set; if a read or write command is issued to side 1 of a single sided drive, then this flag is set
        EQUIP_CHECK:    0x00000010,     // ST0 (EC): If a fault signal is received from the FDD, or if the track 0 signal fails to occur after 77 step pulses (recalibrate command), then this flag is set
        SEEK_END:       0x00000020,     // ST0 (SE): When the FDC completes the Seek command, this flag is set to 1 (high)
        INCOMPLETE:     0x00000040,     // ST0 (IC): Abnormal termination of command (AT); execution of command was started, but was not successfully completed
        RESET:          0x000000C0,     // ST0 (IC): Abnormal termination because during command execution the ready signal from the drive changed state
        INVALID:        0x00000080,     // ST0 (IC): Invalid command issue (IC); command which was issued was never started
        ST0:            0x000000FF,
        NO_ID_MARK:     0x00000100,     // ST1 (MA): If the FDC cannot detect the ID Address Mark, this flag is set; at the same time, the MD (Missing Address Mark in Data Field) of Status Register 2 is set
        NOT_WRITABLE:   0x00000200,     // ST1 (NW): During Execution of a Write Data, Write Deleted Data, or Format a Cylinder command, if the FDC detects a write protect signal from the FDD, then this flag is set
        NO_DATA:        0x00000400,     // ST1 (ND): FDC cannot find specified sector (or specified ID if READ_ID command)
        DMA_OVERRUN:    0x00001000,     // ST1 (OR): If the FDC is not serviced by the main systems during data transfers within a certain time interval, this flag is set
        CRC_ERROR:      0x00002000,     // ST1 (DE): When the FDC detects a CRC error in either the ID field or the data field, this flag is set
        END_OF_CYL:     0x00008000,     // ST1 (EN): When the FDC tries to access a sector beyond the final sector of a cylinder, this flag is set
        ST1:            0x0000FF00,
        NO_DATA_MARK:   0x00010000,     // ST2 (MD): When data is read from the medium, if the FDC cannot find a Data Address Mark or Deleted Data Address Mark, then this flag is set
        BAD_CYL:        0x00020000,     // ST2 (BC): This bit is related to the ND bit, and when the contents of C on the medium are different from that stored in the ID Register, and the content of C is FF, then this flag is set
        SCAN_FAILED:    0x00040000,     // ST2 (SN): During execution of the Scan command, if the FDC cannot find a sector on the cylinder which meets the condition, then this flag is set
        SCAN_EQUAL:     0x00080000,     // ST2 (SH): During execution of the Scan command, if the condition of "equal" is satisfied, this flag is set
        WRONG_CYL:      0x00100000,     // ST2 (WC): This bit is related to the ND bit, and when the contents of C on the medium are different from that stored in the ID Register, this flag is set
        DATA_FIELD:     0x00200000,     // ST2 (DD): If the FDC detects a CRC error in the data, then this flag is set
        STRL_MARK:      0x00400000,     // ST2 (CM): During execution of the Read Data or Scan command, if the FDC encounters a sector which contains a Deleted Data Address Mark, this flag is set
        ST2:            0x00FF0000,
        DRIVE:          0x03000000,     // ST3 (Ux): Status of the "Drive Select" signals from the diskette drive
        HEAD:           0x04000000,     // ST3 (HD): Status of the "Side Select" signal from the diskette drive
        TWOSIDE:        0x08000000,     // ST3 (TS): Status of the "Two Side" signal from the diskette drive
        TRACK0:         0x10000000,     // ST3 (T0): Status of the "Track 0" signal from the diskette drive
        READY:          0x20000000,     // ST3 (RY): Status of the "Ready" signal from the diskette drive
        WRITEPROT:      0x40000000,     // ST3 (WP): Status of the "Write Protect" signal from the diskette drive
        FAULT:          0x80000000|0,   // ST3 (FT): Status of the "Fault" signal from the diskette drive
        ST3:            0xFF000000|0
    }
};


let HDC = {};

/*
 * HDC defaults, in case drive parameters weren't specified
 */
HDC.DEFAULT_DRIVE_NAME = "Hard Drive";

/*
 * Starting with the IBM PC XT, the ROM defined a "Fixed Disk Parameter Table" (FD_TBL) that contained 16 bytes
 * at the following offsets for each of 4 drive types (see IBM 5160 Tech Ref, April 1983, p. A-94):
 *
 *      0: maximum number of cylinders (word)
 *      2: maximum number of heads
 *      3: starting reduced write current cylinder (word)
 *      5: starting write precompensation cylinder (word)
 *      7: maximum ECC data burst length
 *      8: control byte (drive step option)
 *          bit 7: disable disk-access retries
 *          bit 6: disable ECC retries
 *          bits 5-3: zero
 *          bits 2-0: drive option
 *      9: standard time-out value
 *      A: time-out value for format drive
 *      B: time-out value for check drive
 *      C: reserved
 *      D: reserved
 *      E: reserved
 *      F: reserved
 *
 * Starting with the IBM PC AT, the ROM defined a "Fixed Disk Parameter Table" (FD_TBL) that contained 16 bytes
 * at the following offsets for each of 47 drive types (see IBM 5170 Tech Ref, March 1986, p. 5-185):
 *
 *      0: maximum number of cylinders (word)
 *      2: maximum number of heads
 *      3: not used
 *      5: starting write precompensation cylinder (word)
 *      7: not used
 *      8: control byte (drive step option)
 *          bit 7: disable retries -OR-
 *          bit 6: disable retries
 *          bit 3: more than 8 heads
 *      9: not used
 *      A: not used
 *      B: not used
 *      C: landing zone (word)
 *      E: number of sectors/track (NOTE: all PC AT drive types specified 17 sectors/track)
 *      F: reserved
 *
 * NOTE: While drive type 0 was a valid type in the PC XT, it was NOT a valid drive type in the PC AT; zero was used
 * to indicate that no hard drive was installed.
 *
 * Of the 47 PC AT drive types, the first 14 (1-E) could be selected by 4 bits in CMOS byte 0x12.  Drive type 15 was not
 * a valid type but rather an indicator that CMOS byte 0x19 (or 0x1A) contained the actual drive type, which technically
 * could contain any value from 0-255, but was documented as being limited to values 16-255.  And in fact, the ROM only
 * contained entries for drive types 1-47, and of those, only drive types 1-14 and 16-23 were valid; the rest (15 and 24-47)
 * were marked "RESERVED" and contained zeros.
 *
 * If a system needed a drive type that wasn't defined by the ROM, it could be placed in RAM, as the ROM explained:
 *
 *      To dynamically define a set of parameters, build a table for up to 15 types and place
 *      the corresponding vector into interrupt 0x41 for drive 0 and interrupt 0x46 for drive 1.
 *
 * To make PCjs easier to configure, we have three drive tables (for XT, AT, and COMPAQ machines), each of which
 * contains DriveArrays for the various DriveTypes supported by each machine.  Each DriveArray contains the following
 * subset of "Fixed Disk Parameter Table" information:
 *
 *      [0]: total cylinders
 *      [1]: total heads
 *      [2]: total sectors/tracks (optional; default is 17)
 *      [3]: total bytes/sector (optional; default is 512)
 *
 * verifyDrive() attempts to confirm that these values agree with the programmed drive characteristics.
 *
 * NOTE: For the record, PCjs considers 1Kb to be 1 kilobyte (1,024 bytes, not 1,000 bytes) and 1Mb to be 1 megabyte
 * (1024*1024 or 1,048,576 bytes, not 1,000,000 bytes).
 *
 * Apparently, in 1998, it was decided that a kilobyte should be 1,000 bytes and a megabyte should be 1,000,000 bytes,
 * and that if you really meant 2^10 (1,024) or 2^20 (1,048,576), you should use "kibibyte" (KiB) or "mebibyte" (MiB)
 * instead.  But since PCjs simulates machines that pre-date 1998, I have chosen to retain the more "traditional"
 * understanding of Kb and Mb; I never use KiB or MiB.
 */

/*
 * Drive type tables differed across IBM controller models (XTC drive types don't match ATC drive types) and across OEMs
 * (e.g., COMPAQ drive types only match a few IBM drive types), so you must use iDriveTable to index the correct table type
 * inside both aDriveTables and aDriveTypes.
 */
HDC.aDriveTables = ["XTC", "ATC", "COMPAQ"];

HDC.aDriveTypes = [
    /*
     * aDriveTypes[0] is for the IBM PC XT (XTC) controller.
     */
    {
         0: [306, 2],
         1: [375, 8],
         2: [306, 6],
         3: [306, 4]            // 10Mb (10.16Mb: 306*4*17*512 or 10,653,696 bytes) (default XTC drive type: 3)
    },
    /*
     * aDriveTypes[1] is for the IBM PC AT (ATC) controller.
     *
     * The following is a more complete description of the drive types supported by the MODEL_5170, where C is
     * Cylinders, H is Heads, WP is Write Pre-Comp, and LZ is Landing Zone (in practice, we don't need WP or LZ).
     *
     * Type    C    H   WP   LZ
     * ----  ---   --  ---  ---
     *   1   306    4  128  305
     *   2   615    4  300  615
     *   3   615    6  300  615
     *   4   940    8  512  940
     *   5   940    6  512  940
     *   6   615    4   no  615
     *   7   462    8  256  511
     *   8   733    5   no  733
     *   9   900   15   no  901
     *  10   820    3   no  820
     *  11   855    5   no  855
     *  12   855    7   no  855
     *  13   306    8  128  319
     *  14   733    7   no  733
     *  15  (reserved--all zeros)
     *  16   612    4  all  663
     *  17   977    5  300  977
     *  18   977    7   no  977
     *  19  1024    7  512 1023
     *  20   733    5  300  732
     *  21   733    7  300  732
     *  22   733    5  300  733
     *  23   306    4   no  336
     */
    {
         0: [1024,16,21,2048],  // arbitrary (reserved for CD-ROMs)
         1: [306,  4],          // 10Mb (10.16Mb:  306*4*17*512 or 10,653,696 bytes)
         2: [615,  4],          // 20Mb (20.42Mb:  615*4*17*512 or 21,411,840 bytes) (default ATC drive type)
         3: [615,  6],          // 31Mb (30.63Mb:  615*6*17*512 or 32,117,760 bytes)
         4: [940,  8],          // 62Mb (62.42Mb:  940*8*17*512 or 65,454,080 bytes)
         5: [940,  6],          // 47Mb (46.82Mb:  940*6*17*512 or 49,090,560 bytes)
         6: [615,  4],
         7: [462,  8],
         8: [733,  5],
         9: [900, 15],
        10: [820,  3],
        11: [855,  5],
        12: [855,  7],
        13: [306,  8],
        14: [733,  7],
        /*
         * Since the remaining drive types are > 14, they must be stored in either EXTHDRIVE0 or EXTHDRIVE1 CMOS bytes (0x19 or 0x1A)
         */
        16: [612,  4],
        17: [977,  5],
        18: [977,  7],
        19: [1024, 7],
        20: [733,  5],
        21: [733,  7],
        22: [733,  5],
        23: [306,  4]
    },
    /*
     * aDriveTypes[2] is for the COMPAQ DeskPro (ATC) controller.
     *
     * NOTE: According to COMPAQ, drive type 25 (0x19) must be used with their 130Mb drive when using MS-DOS 3.1
     * or earlier, or when using any [unspecified] application software that supports only 17 sectors per track;
     * otherwise, use drive type 35 (0x23), which uses the drive's full capacity of 34 sectors per track.
     */
    {
         0: [1024,16,21,2048],  // arbitrary (reserved for CD-ROMs)
         1: [306,  4],          // 10Mb (10.16Mb:  306*4*17*512 or 10,653,696 bytes) (same as IBM)
         2: [615,  4],          // 20Mb (20.42Mb:  615*4*17*512 or 21,411,840 bytes) (same as IBM)
         3: [615,  6],          // 31Mb (30.63Mb:  615*6*17*512 or 32,117,760 bytes) (same as IBM)
         4: [1023, 8],          // 68Mb (67.93Mb: 1023*8*17*512 or 71,233,536 bytes) (TODO: Cylinders is listed as 1024 in the COMPAQ TechRef; confirm)
         5: [940,  6],          // 47Mb (46.82Mb:  940*6*17*512 or 49,090,560 bytes) (same as IBM)
         6: [697,  5],
         7: [462,  8],          // same as IBM
         8: [925,  5],
         9: [900, 15],          // same as IBM
        10: [980,  5],
        11: [925,  7],
        12: [925,  9],          // 70Mb (69.10Mb: 925*9*17*512 or 72,460,800 bytes)
        13: [612,  8],
        14: [980,  4],
        /*
         * Since the remaining drive types are > 14, they must be stored in either EXTHDRIVE0 or EXTHDRIVE1 CMOS bytes (0x19 or 0x1A)
         */
        16: [612,  4],          // same as IBM
        17: [980,  5],          // 40Mb (40.67Mb: 980*5*17*512 or 42,649,600 bytes)
        18: [966,  6],
        19: [1023, 8],
        20: [733,  5],          // same as IBM
        21: [733,  7],          // same as IBM
        22: [524,  4, 40],
        23: [924,  8],
        24: [966, 14],
        25: [966, 16],          // 130Mb (128.30Mb: 966*16*17*512 or 134,529,024 bytes)
        26: [1023,14],
        27: [832,  6, 33],
        28: [1222,15, 34],
        29: [1240, 7, 34],
        30: [615,  4, 25],
        31: [615,  8, 25],
        32: [905,  9, 25],
        33: [832,  8, 33],      // 110Mb (107.25Mb: 832*8*33*512 or 112,459,776 bytes)
        34: [966,  7, 34],
        35: [966,  8, 34],      // 130Mb (128.30Mb: 966*8*34*512 or 134,529,024 bytes)
        36: [966,  9, 34],
        37: [966,  5, 34],
        38: [612, 16, 63],      // 300Mb (301.22Mb: 612*16*63*512 or 315,850,752 bytes) (TODO: Cylinders is listed as 611 in the COMPAQ TechRef; confirm)
        39: [1023,11, 33],
        40: [1023,15, 34],
        41: [1630,15, 52],
        42: [1023,16, 63],
        43: [805,  4, 26],
        44: [805,  2, 26],
        45: [748,  8, 33],
        46: [748,  6, 33],
        47: [966,  5, 25]
    }
];

/*
 * ATC (AT Controller) Registers
 *
 * The "IBM Personal Computer AT Fixed Disk and Diskette Drive Adapter", aka the HFCOMBO card, contains what we refer
 * to here as the ATC (AT Controller).  Even though that card contains both Fixed Disk and Diskette Drive controllers,
 * this component (HDC) still deals only with the "Fixed Disk" portion.  Fortunately, the "Diskette Drive Adapter"
 * portion of the card is compatible with the existing FDC component, so that component continues to be responsible
 * for all diskette operations.
 *
 * ATC ports default to their primary addresses; secondary port addresses are 0x80 lower (e.g., 0x170 instead of 0x1F0).
 *
 * It's important to know that the MODEL_5170 BIOS has a special relationship with the "Combo Hard File/Diskette
 * (HFCOMBO) Card" (see @F000:144C).  Initially, the ChipSet component intercepted reads for HFCOMBO's STATUS port
 * and returned the BUSY bit clear to reduce boot time; however, it turned out that was also a prerequisite for the
 * BIOS to write test patterns to the CYLLO port (0x1F4) and set the "DUAL" bit (bit 0) of the "HFCNTRL" byte at 40:8Fh
 * if those CYLLO operations succeeded (now that the HDC is "ATC-aware", the ChipSet port intercepts have been removed).
 *
 * Without the "DUAL" bit set, when it came time later to report the diskette drive type, the "DISK_TYPE" function
 * (@F000:273D) would branch to one of two almost-identical blocks of code -- specifically, a block that disallowed
 * diskette drive types >= 2 (ChipSet.CMOS.FDRIVE.FD360) instead of >= 3 (ChipSet.CMOS.FDRIVE.FD1200).
 *
 * In other words, the "Fixed Disk" portion of the HFCOMBO controller has to be present and operational if the user
 * wants to use high-capacity (80-track) diskettes with "Diskette Drive" portion of the controller.  This may not be
 * immediately obvious to anyone creating a 5170 machine configuration with the FDC component but no HDC component.
 *
 * TODO: Investigate what a MODEL_5170 can do, if anything, with diskettes if an "HFCOMBO card" was NOT installed;
 * e.g., was there Diskette-only Controller that could be installed, and if so, did it support high-capacity diskette
 * drives?  Also, consider making the FDC component able to detect when the HDC is missing and provide the same minimal
 * HFCOMBO port intercepts that ChipSet once provided (this is not a requirement, just a usability improvement).
 *
 * UPDATE: I later discovered that newer (ie, REV2 and REV3) 5170 ROMs are even less happy when no HDC is installed,
 * *unless* an undocumented FDC "DIAGNOSTIC" register (port 0x3F1) provides a "MULTIPLE DATA RATE" response, bypassing
 * the HDC port tests described above.  This may also imply that those newer 5170 revisions are incompatible with FD360
 * diskette drives, because if none of the "MULTIPLE DATA RATE" tests succeed, a "601-Diskette Error" always occurs.
 */
HDC.ATC = {
    DATA:   {                   // no register (read-write)
        PORT1:      0x1F0,      // data port address for primary interface
        PORT2:      0x170       // data port address for secondary interface
    },
    DIAG:   {                   // this.regError (read-only)
        PORT1:      0x1F1,
        PORT2:      0x171,
        NO_ERROR:    0x01,
        CTRL_ERROR:  0x02,
        SEC_ERROR:   0x03,
        ECC_ERROR:   0x04,
        PROC_ERROR:  0x05
    },
    ERROR: {                    // this.regError (read-only)
        PORT1:      0x1F1,
        PORT2:      0x171,
        NONE:        0x00,
        NO_DAM:      0x01,      // Data Address Mark (DAM) not found
        NO_TRK0:     0x02,      // Track 0 not detected
        CMD_ABORT:   0x04,      // Aborted Command
        NO_CHS:      0x10,      // ID field with the specified C:H:S not found
        ECC_ERR:     0x40,      // Data ECC Error
        BAD_BLOCK:   0x80       // Bad Block Detect
    },
    WPREC:  {                   // this.regWPreC (write-only)
        PORT1:      0x1F1,
        PORT2:      0x171
    },
    SECCNT: {                   // this.regSecCnt (read-write; 0 implies a 256-sector request)
        PORT1:      0x1F2,
        PORT2:      0x172,
        PACKET_CD:   0x01,      // for PACKET command, bit 0 set upon transfer of packet command
        PACKET_IO:   0x02       // for PACKET command, bit 1 set upon transfer of packet response
    },
    SECNUM: {                   // this.regSecNum (read-write)
        PORT1:      0x1F3,
        PORT2:      0x173
    },
    CYLLO:  {                   // this.regCylLo (read-write; all 8 bits are used)
        PORT1:      0x1F4,
        PORT2:      0x174
    },
    CYLHI:  {                   // this.regCylHi (read-write; only bits 0-1 are used, for a total of 10 bits, or 1024 max cylinders)
        PORT1:      0x1F5,
        PORT2:      0x175,
        MASK:        0x03
    },
    DRVHD:  {                   // this.regDrvHd (read-write)
        PORT1:      0x1F6,
        PORT2:      0x176,
        HEAD_MASK:   0x0F,      // set this to the max number of heads before issuing a SET PARAMETERS command
        DRIVE_MASK:  0x10,
        SET_MASK:    0xE0,
        SET_BITS:    0xA0       // for whatever reason, these bits must always be set
    },
    STATUS: {                   // this.regStatus (read-only; reading clears IRQ.ATC1 or IRQ.ATC2 as appropriate)
        PORT1:      0x1F7,
        PORT2:      0x177,
        ERROR:       0x01,      // set when the previous command ended in an error; one or more bits are set in the ERROR register (the next command to the controller resets the ERROR bit)
        INDEX:       0x02,      // set once for every revolution of the disk
        CORRECTED:   0x04,
        DATA_REQ:    0x08,      // indicates that "the sector buffer requires servicing during a Read or Write command. If either bit 7 (BUSY) or this bit is active, a command is being executed. Upon receipt of any command, this bit is reset."
        SEEK_OK:     0x10,      // seek operation complete
        WFAULT:      0x20,      // write fault
        READY:       0x40,      // if this is set (along with the SEEK_OK bit), the drive is ready to read/write/seek again
        BUSY:        0x80       // if this is set, no other STATUS bits are valid
    },
    COMMAND: {                  // this.regCommand (write-only)
        PORT1:      0x1F7,
        PORT2:      0x177,
        NO_RETRY:    0x01,      // optional bit for READ_DATA, WRITE_DATA, and READ_VERF commands
        WITH_ECC:    0x02,      // optional bit for READ_DATA and WRITE_DATA commands
        STEP_RATE:   0x0F,      // optional bits for stepping rate used with RESTORE and SEEK commands
                                // (low nibble x 500us equals stepping rate, except for 0, which corresponds to 35us)
        /*
         * The following 8 commands comprised the original PC AT (ATA) command set.  You may see other later command
         * set definitions that show "mandatory" commands, such as READ_MULT (0xC4) or WRITE_MULT (0xC5), but those didn't
         * exist until the introduction of later interface enhancements (e.g., ATA-1, ATA-2, IDE, EIDE, ATAPI, etc).
         */
        RESTORE:     0x10,      // aka RECALIBRATE
        READ_DATA:   0x20,      // also supports NO_RETRY and/or WITH_ECC
        WRITE_DATA:  0x30,      // also supports NO_RETRY and/or WITH_ECC
        READ_VERF:   0x40,      // also supports NO_RETRY
        FORMAT_TRK:  0x50,      // TODO
        SEEK:        0x70,      //
        DIAGNOSE:    0x90,      //
        SETPARMS:    0x91,      //
        /*
         * Additional commands go here.  As for when these commands were introduced, I may try to include
         * that information parenthetically, but I'm not going to pretend this is in any way authoritative.
         */
        RESET:       0x08,      // Device Reset (ATAPI)
        PACKET:      0xA0,      // Packet Request (ATAPI)
        IDPACKET:    0xA1,      // Identify Packet Device (ATAPI)
        IDDEVICE:    0xEC       // Identify Device (ATA-1)
    },
    FDR: {                      // this.regFDR
        PORT1:      0x3F6,
        PORT2:      0x376,
        INT_DISABLE: 0x02,      // a logical 0 enables fixed disk interrupts
        RESET:       0x04,      // a logical 1 enables reset fixed disk function
        HS3:         0x08,      // a logical 1 enables head select 3 (a logical 0 enables reduced write current)
        RESERVED:    0xF1
    }
};

/*
 * Much of the following IDENTIFY structure information came from a Seagate ATA Reference Manual,
 * 36111-001, Rev. C, dated 21 May 1993 (111-1c.pdf), a specification which I believe later became known
 * as ATA-1.
 *
 * All words are stored little-endian; also note some definitions of CUR_CAPACITY define it as two
 * 16-bit words, since as a 32-bit dword, it would be misaligned if the structure began on a dword boundary
 * (and, of course, if it did NOT begin on a dword boundary, then LBA_CAPACITY would be misaligned).
 * Alignment considerations are of no great concern on Intel platforms, however.
 */
HDC.ATC.IDENTIFY = {
    CONFIG: {                   // WORD: GENERAL_CONFIG
        OFFSET:         0x00,
        ATA_RESERVED:   0x0001, // always clear (ATA reserved)
        HARD_SECTORED:  0x0002, // set if hard sectored
        SOFT_SECTORED:  0x0004, // set if soft sectored
        NOT_MFM:        0x0008, // set if not MFM encoded
        HDSW_15MS:      0x0010, // set if head switch time > 15usec
        SPINDLE_OPT:    0x0020, // set if spindle motor control option implemented
        FIXED:          0x0040, // set if fixed drive
        REMOVABLE:      0x0080, // set if removable cartridge drive
        RATE_5MBIT:     0x0100, // set if disk transfer rate <= 5Mbit/sec
        RATE_10MBIT:    0x0200, // set if disk transfer rate <= 10Mbit/sec and > 5Mbit/sec
        RATE_FASTER:    0x0400, // set if disk transfer rate > 10Mbit/sec
        ROT_TOLERANCE:  0x0800, // set if rotational speed tolerance is > 0.5%
        STROBE_OPT:     0x1000, // set if data strobe offset option available
        TRACK_OPT:      0x2000, // set if track offset option available
        FMT_TOLERANCE:  0x4000, // set if format speed tolerance gap required
        NM_RESERVED:    0x8000  // always clear (reserved for non-magnetic drives)
    },
    CYLS:               0x02,   // WORD: number of physical cylinders
    CONFIG2:            0x04,   // WORD: SPECIFIC_CONFIG
    HEADS:              0x06,   // WORD: number of physical heads
    TRACK_BYTES:        0x08,   // WORD: bytes per track
    SECBYTES:           0x0A,   // WORD: bytes per sector
    SECTORS:            0x0C,   // WORD: sectors per track
                                // (reserved words at 0x0E, 0x10, and 0x12)
    SERIAL_NUMBER:      0x14,   // CHAR: 20 ASCII characters
    BUFFER_TYPE:        0x28,   // WORD: 0=unspecified, 1=single, 2=dual, 3=caching
    BUFFER_SIZE:        0x2A,   // WORD: 512-byte increments
    ECC_BYTES:          0x2C,   // WORD: number of ECC bytes on read/write long commands
    FIRMWARE_REV:       0x2E,   // CHAR: 8 ASCII characters
    MODEL_NUMBER:       0x36,   // CHAR: 40 ASCII characters
    MAX_MULTISEC:       0x5E,   // BYTE: if non-zero, number of transferable sectors per interrupt
                                // (reserved byte at 0x5F)
    DWORD_IO:           0x60,   // WORD: 0x0001 if double-word I/O supported, 0x0000 if not
                                // (reserved byte at 0x62)
    CAPABILITY:         0x63,   // BYTE: bit0=DMA, bit1=LBA, bit2=IORDYsw, bit3=IORDYsup
                                // (reserved word at 0x64; reserved byte at 0x66)
    PIO_TIMING:         0x67,   // BYTE: 0=slow, 1=medium, 2=fast
                                // (reserved byte at 0x68)
    DMA_TIMING:         0x69,   // BYTE: 0=slow, 1=medium, 2=fast
    NEXT5_VALID:        0x6A,   // WORD: bit0=1 if next 5 words are valid, 0 if not
    CUR_CYLS:           0x6C,   // WORD: number of logical cylinders
    CUR_HEADS:          0x6E,   // WORD: number of logical heads
    CUR_SECTORS:        0x70,   // WORD: number of logical sectors per track
    CUR_CAPACITY:       0x72,   // LONG: logical capacity in sectors
    MULTISECT:          0x76,   // BYTE: current multiple sector count
    MULTISECT_VALID:    0x77,   // BYTE: bit0=1 if MULTSECT is valid, 0 if not
    LBA_CAPACITY:       0x78,   // LONG: total number of sectors
    DMA_SINGLE:         0x7C,   // BYTE
    DMA_SINGLE_ACTIVE:  0x7D,   // BYTE
    DMA_MULTI:          0x7E,   // BYTE
    DMA_MULTI_ACTIVE:   0x7F,   // BYTE
    /*
     * The rest of this 512-byte structure (words 64 through 255) was reserved at the time of the ATA-1 spec,
     * so I will not delve any deeper into this structure now.
     *
     * Further details can be found at:
     *
     *      https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ata/ns-ata-_identify_device_data
     *      https://chromium.googlesource.com/chromiumos/third_party/u-boot-next/+/master/include/ata.h
     *
     * Regrettably, those more modern documents don't bother mentioning at what point any fields were added
     * to the specification, and they treat some of the early obsolete fields as too old to warrant any explanation,
     * calling them simply "Retired" or "Obsolete".  Not particularly helpful to anyone who cares about history.
     */
};

HDC.ATC.PACKET = {
    COMMAND: {
        TEST_UNIT:      0x00,   // Test Unit Ready
        REQ_SENSE:      0x03,   // Request Sense
        INQUIRY:        0x12,   // Inquiry
        READ:           0x28,   // Read
        SEEK:           0x2B,   // Seek
        READ_TOC:       0x43,   // Read TOC (Table of Contents), PMA (Program Memory Area), and ATIP (Absolute Time in Pre-Groove)
        PLAY_AUDIO:     0x45,   // Play Audio
        MODE_SENSE:     0x5A    // Mode Sense
    },
    /*
     * Finding a succinct list of all the (SCSI) Page Codes in old ATAPI/SCSI specs is surprisingly hard,
     * but there is a nice summary on Wikipedia (https://en.wikipedia.org/wiki/SCSI_mode_page).  For details
     * on Page Code contents, check out the ANSI X3.304-1997 spec (e.g., page 72 for Page Code 0x2A).
     */
    PAGECODE: {
        RW_ERRREC:      0x01,   // Read-Write Error Recovery Page
        CD_STATUS:      0x2A    // CD Capabilities and Mechanical Status Page
    },
    ADR: {                      // ADR Q sub-channel values (0x4-0xF reserved)
        NONE:           0x0,
        CUR_POS:        0x1,
        MEDIA_CAT_NO:   0x2,
        ISRC:           0x3
    },
    CONTROL: {                  // CONTROL Q sub-channel values
        DATA_TRACK:     0x4
    }
};

/*
 * XTC (XT Controller) Registers
 */
HDC.XTC = {
    /*
     * XTC Data Register (0x320, read-write)
     *
     * Writes to this register are discussed below; see HDC Commands.
     *
     * Reads from this register after a command has been executed retrieve a "status byte",
     * which must NOT be confused with the Status Register (see below).  This data "status byte"
     * contains only two bits of interest: XTC.DATA.STATUS.ERROR and XTC.DATA.STATUS.UNIT.
     */
    DATA: {
        PORT:          0x320,   // port address
        STATUS: {
            OK:         0x00,   // no error
            ERROR:      0x02,   // error occurred during command execution
            UNIT:       0x20    // logical unit number of the drive
        },
        /*
         * XTC Commands, as issued to XTC_DATA
         *
         * Commands are multi-byte sequences sent to XTC_DATA, starting with a XTC_DATA.CMD byte,
         * and followed by 5 more bytes, for a total of 6 bytes, which collectively are called a
         * Device Control Block (DCB).  Not all commands use all 6 bytes, but all 6 bytes must be present;
         * unused bytes are simply ignored.
         *
         *      XTC_DATA.CMD    (3-bit class code, 5-bit operation code)
         *      XTC_DATA.HEAD   (1-bit drive number, 5-bit head number)
         *      XTC_DATA.CLSEC  (upper bits of 10-bit cylinder number, 6-bit sector number)
         *      XTC_DATA.CH     (lower bits of 10-bit cylinder number)
         *      XTC_DATA.COUNT  (8-bit interleave or block count)
         *      XTC_DATA.CTRL   (8-bit control field)
         *
         * One command, HDC.XTC.DATA.CMD.INIT_DRIVE, must include 8 additional bytes following the DCB:
         *
         *      maximum number of cylinders (high)
         *      maximum number of cylinders (low)
         *      maximum number of heads
         *      start reduced write current cylinder (high)
         *      start reduced write current cylinder (low)
         *      start write precompensation cylinder (high)
         *      start write precompensation cylinder (low)
         *      maximum ECC data burst length
         *
         * Note that the 3 word values above are stored in "big-endian" format (high byte followed by low byte),
         * rather than the "little-endian" format (low byte followed by high byte) you typically find on Intel machines.
         */
        CMD: {
            TEST_READY:     0x00,       // Test Drive Ready
            RECALIBRATE:    0x01,       // Recalibrate
            REQ_SENSE:      0x03,       // Request Sense Status
            FORMAT_DRIVE:   0x04,       // Format Drive
            READ_VERF:      0x05,       // Read Verify
            FORMAT_TRK:     0x06,       // Format Track
            FORMAT_BAD:     0x07,       // Format Bad Track
            READ_DATA:      0x08,       // Read
            WRITE_DATA:     0x0A,       // Write
            SEEK:           0x0B,       // Seek
            INIT_DRIVE:     0x0C,       // Initialize Drive Characteristics
            READ_ECC_BURST: 0x0D,       // Read ECC Burst Error Length
            READ_BUFFER:    0x0E,       // Read Data from Sector Buffer
            WRITE_BUFFER:   0x0F,       // Write Data to Sector Buffer
            RAM_DIAGNOSTIC: 0xE0,       // RAM Diagnostic
            DRV_DIAGNOSTIC: 0xE3,       // HDC BIOS: CHK_DRV_CMD
            CTL_DIAGNOSTIC: 0xE4,       // HDC BIOS: CNTLR_DIAG_CMD
            READ_LONG:      0xE5,       // HDC BIOS: RD_LONG_CMD
            WRITE_LONG:     0xE6        // HDC BIOS: WR_LONG_CMD
        },
        ERR: {
            /*
             * HDC error conditions, as returned in byte 0 of the (4) bytes returned by the Request Sense Status command
             */
            NONE:           0x00,
            NO_INDEX:       0x01,       // no index signal detected
            SEEK_INCOMPLETE:0x02,       // no seek-complete signal
            WRITE_FAULT:    0x03,
            NOT_READY:      0x04,       // after the controller selected the drive, the drive did not respond with a ready signal
            NO_TRACK:       0x06,       // after stepping the max number of cylinders, the controller did not receive the track 00 signal from the drive
            STILL_SEEKING:  0x08,
            ECC_ID_ERROR:   0x10,
            ECC_DATA_ERROR: 0x11,
            NO_ADDR_MARK:   0x12,
            NO_SECTOR:      0x14,
            BAD_SEEK:       0x15,       // seek error: the cylinder and/or head address did not compare with the expected target address
            ECC_CORRECTABLE:0x18,       // correctable data error
            BAD_TRACK:      0x19,
            BAD_CMD:        0x20,
            BAD_DISK_ADDR:  0x21,
            RAM:            0x30,
            CHECKSUM:       0x31,
            POLYNOMIAL:     0x32,
            MASK:           0x3F
        },
        SENSE: {
            ADDR_VALID:     0x80
        }
    },
    /*
     * XTC Status Register (0x321, read-only)
     *
     * WARNING: The IBM Technical Reference Manual *badly* confuses the XTC_DATA "status byte" (above)
     * that the controller sends following an HDC.XTC.DATA.CMD operation with the Status Register (below).
     * In fact, it's so badly confused that it completely fails to document any of the Status Register
     * bits below; I'm forced to guess at their meanings from the HDC BIOS listing.
     */
    STATUS: {
        PORT:          0x321,   // port address
        NONE:           0x00,
        REQ:            0x01,   // HDC BIOS: request bit
        IOMODE:         0x02,   // HDC BIOS: mode bit (GUESS: set whenever XTC_DATA contains a response?)
        BUS:            0x04,   // HDC BIOS: command/data bit (GUESS: set whenever XTC_DATA ready for request?)
        BUSY:           0x08,   // HDC BIOS: busy bit
        INTERRUPT:      0x20    // HDC BIOS: interrupt bit
    }
};

/*
 * XTC Config Register (0x322, read-only)
 *
 * This register is used to read HDC card switch settings that defined the "Drive Type" for
 * drives 0 and 1.  SW[1],SW[2] (for drive 0) and SW[3],SW[4] (for drive 1) are set as follows:
 *
 *      ON,  ON     Drive Type 0   (306 cylinders, 2 heads)
 *      ON,  OFF    Drive Type 1   (375 cylinders, 8 heads)
 *      OFF, ON     Drive Type 2   (306 cylinders, 6 heads)
 *      OFF, OFF    Drive Type 3   (306 cylinders, 4 heads)
 */

/*
 * HDC Command Sequences
 *
 * Unlike the FDC, all the HDC commands have fixed-length command request sequences (well, OK, except for
 * HDC.XTC.DATA.CMD.INIT_DRIVE) and fixed-length response sequences (well, OK, except for HDC.XTC.DATA.CMD.REQ_SENSE),
 * so a table of byte-lengths isn't much use, but having names for all the commands is still handy for debugging.
 */
HDC.aATACommands = {
    0x08: "Device Reset",           // ATAPI
    0x10: "Restore (Recalibrate)",  // ATA
    0x20: "Read",                   // ATA
    0x30: "Write",                  // ATA
    0x40: "Read Verify",            // ATA
    0x50: "Format Track",           // ATA
    0x70: "Seek",                   // ATA
    0x90: "Diagnose",               // ATA
    0x91: "Set Parameters",         // ATA
    0xA0: "Packet Request",         // ATAPI
    0xA1: "Identify Packet Device", // ATAPI
    0xEC: "Identify Device"         // ATA-1
};

HDC.aATAPICommands = {
    [HDC.ATC.PACKET.COMMAND.TEST_UNIT]:     "Test Unit Ready",
    [HDC.ATC.PACKET.COMMAND.REQ_SENSE]:     "Request Sense",
    [HDC.ATC.PACKET.COMMAND.INQUIRY]:       "Inquiry",
    [HDC.ATC.PACKET.COMMAND.READ]:          "Read",
    [HDC.ATC.PACKET.COMMAND.SEEK]:          "Seek",
    [HDC.ATC.PACKET.COMMAND.READ_TOC]:      "Read TOC",
    [HDC.ATC.PACKET.COMMAND.PLAY_AUDIO]:    "Play Audio",
    [HDC.ATC.PACKET.COMMAND.MODE_SENSE]:    "Mode Sense",
};

HDC.aXTACommands = {
    0x00: "Test Drive Ready",
    0x01: "Recalibrate",
    0x03: "Request Sense Status",
    0x04: "Format Drive",
    0x05: "Read Verify",
    0x06: "Format Track",
    0x07: "Format Bad Track",
    0x08: "Read",
    0x0A: "Write",
    0x0B: "Seek",
    0x0C: "Initialize Drive Characteristics",
    0x0D: "Read ECC Burst Error Length",
    0x0E: "Read Data from Sector Buffer",
    0x0F: "Write Data to Sector Buffer",
    0xE0: "RAM Diagnostic",
    0xE3: "Drive Diagnostic",
    0xE4: "Controller Diagnostic",
    0xE5: "Read Long",
    0xE6: "Write Long"
};

/*
 * Port input notification tables
 */
HDC.aXTCPortInput = {
    0x320:  HDC.prototype.inXTCData,
    0x321:  HDC.prototype.inXTCStatus,
    0x322:  HDC.prototype.inXTCConfig
};

/*
 * For future reference, the REV2 and REV3 PC AT ROM BIOS also refer to a "FIXED DISK DIAGNOSTIC REGISTER" at
 * port 0x5F7, but I have no documentation on it, and failure to respond is non-fatal.  See the discussion of the
 * FDC diagnostic register in inFDCDiagnostic() for more details.
 */
HDC.aATCPortInputPrimary = {
    0x1F0:  HDC.prototype.inATCData,
    0x1F1:  HDC.prototype.inATCError,
    0x1F2:  HDC.prototype.inATCSecCnt,
    0x1F3:  HDC.prototype.inATCSecNum,
    0x1F4:  HDC.prototype.inATCCylLo,
    0x1F5:  HDC.prototype.inATCCylHi,
    0x1F6:  HDC.prototype.inATCDrvHd,
    0x1F7:  HDC.prototype.inATCStatus
};

HDC.aATCPortInputSecondary = {
    0x170:  HDC.prototype.inATCData,
    0x171:  HDC.prototype.inATCError,
    0x172:  HDC.prototype.inATCSecCnt,
    0x173:  HDC.prototype.inATCSecNum,
    0x174:  HDC.prototype.inATCCylLo,
    0x175:  HDC.prototype.inATCCylHi,
    0x176:  HDC.prototype.inATCDrvHd,
    0x177:  HDC.prototype.inATCStatus
};

/*
 * Port output notification tables
 */
HDC.aXTCPortOutput = {
    0x320:  HDC.prototype.outXTCData,
    0x321:  HDC.prototype.outXTCReset,
    0x322:  HDC.prototype.outXTCPulse,
    0x323:  HDC.prototype.outXTCPattern,
    /*
     * The PC XT Fixed Disk BIOS includes some additional "housekeeping" that it performs
     * not only on port 0x323 but also on three additional ports, at increments of 4 (see all
     * references to "RESET INT/DMA MASK" in the Fixed Disk BIOS).  It's not clear to me if
     * those ports refer to additional HDC controllers, and I haven't seen other references to
     * them, but in any case, they represent a lot of "I/O noise" that we simply squelch here.
     */
    0x327:  HDC.prototype.outXTCNoise,
    0x32B:  HDC.prototype.outXTCNoise,
    0x32F:  HDC.prototype.outXTCNoise
};

HDC.aATCPortOutputPrimary = {
    0x1F0:  HDC.prototype.outATCData,
    0x1F1:  HDC.prototype.outATCWPreC,
    0x1F2:  HDC.prototype.outATCSecCnt,
    0x1F3:  HDC.prototype.outATCSecNum,
    0x1F4:  HDC.prototype.outATCCylLo,
    0x1F5:  HDC.prototype.outATCCylHi,
    0x1F6:  HDC.prototype.outATCDrvHd,
    0x1F7:  HDC.prototype.outATCCommand,
    0x3F6:  HDC.prototype.outATCFDR
};

HDC.aATCPortOutputSecondary = {
    0x170:  HDC.prototype.outATCData,
    0x171:  HDC.prototype.outATCWPreC,
    0x172:  HDC.prototype.outATCSecCnt,
    0x173:  HDC.prototype.outATCSecNum,
    0x174:  HDC.prototype.outATCCylLo,
    0x175:  HDC.prototype.outATCCylHi,
    0x176:  HDC.prototype.outATCDrvHd,
    0x177:  HDC.prototype.outATCCommand,
    0x376:  HDC.prototype.outATCFDR
};