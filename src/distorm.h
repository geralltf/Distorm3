/* diStorm 3.5.3 */

/*
distorm.h

diStorm3 - Powerful disassembler for X86/AMD64
http://ragestorm.net/distorm/
distorm at gmail dot com
Copyright (C) 2003-2021 Gil Dabah
This library is licensed under the BSD license. See the file COPYING.
*/


#ifndef DISTORM_H
#define DISTORM_H

#include <stdio.h>

/*
 * 64 bit offsets support:
 * If the diStorm library you use was compiled with 64 bits offsets,
 * make sure you compile your own code with the following macro set:
 * SUPPORT_64BIT_OFFSET
 * Otherwise comment it out, or you will get a linker error of an unresolved symbol...
 * Turned on by default!
 */

#if !(defined(DISTORM_STATIC) || defined(DISTORM_DYNAMIC))
	/* Define this macro for outer projects by default. */
	#define SUPPORT_64BIT_OFFSET
#endif

/* TINYC has a problem with some 64bits library functions, so ignore 64 bit offsets. */
#ifdef __TINYC__
	#undef SUPPORT_64BIT_OFFSET
#endif

#ifndef _MSC_VER
#include <stdint.h>
#else
/* Since MSVC < 2010 isn't shipped with stdint.h,
 * here are those from MSVC 2017, which also match
 * those in tinycc/libc. */
typedef signed char        int8_t;
typedef short              int16_t;
typedef int                int32_t;
typedef long long          int64_t;
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;
#endif

#ifdef SUPPORT_64BIT_OFFSET
#define OFFSET_INTEGER uint64_t
#else
/* 32 bit offsets are used. */
#define OFFSET_INTEGER uint32_t
#endif

/* Support C++ compilers */
#ifdef __cplusplus
 extern "C" {
#endif


/* ***  Helper Macros  *** */

/* Get the ISC of the instruction, used with the definitions below. */
#define META_GET_ISC(meta) (((meta) >> 8) & 0x1f)
#define META_SET_ISC(di, isc) (((di)->meta) |= ((isc) << 8))
/* Get the flow control flags of the instruction, see 'features for decompose' below. */
#define META_GET_FC(meta) ((meta) & 0xf)

/* Get the target address of a branching instruction. O_PC operand type. */
#define INSTRUCTION_GET_TARGET(di) ((_OffsetType)(((di)->addr + (di)->imm.addr + (di)->size)))
/* Get the target address of a RIP-relative memory indirection. */
#define INSTRUCTION_GET_RIP_TARGET(di) ((_OffsetType)(((di)->addr + (di)->disp + (di)->size)))

/*
 * Operand Size or Adderss size are stored inside the flags:
 * 00 - 16 bits
 * 01 - 32 bits
 * 10 - 64 bits
 * 11 - reserved
 *
 * If you call these set-macros more than once, you will have to clean the bits before doing so.
 */
#define FLAG_SET_OPSIZE(di, size) ((di->flags) |= (((size) & 3) << 8))
#define FLAG_SET_ADDRSIZE(di, size) ((di->flags) |= (((size) & 3) << 10))
#define FLAG_GET_OPSIZE(flags) (((flags) >> 8) & 3)
#define FLAG_GET_ADDRSIZE(flags) (((flags) >> 10) & 3)
/* To get the LOCK/REPNZ/REP prefixes. */
#define FLAG_GET_PREFIX(flags) (((unsigned int)((int16_t)flags)) & 7)
/* Indicates whether the instruction is privileged. */
#define FLAG_GET_PRIVILEGED(flags) (((flags) & FLAG_PRIVILEGED_INSTRUCTION) != 0)

/*
 * Macros to extract segment registers from 'segment':
 */
#define SEGMENT_DEFAULT 0x80
#define SEGMENT_GET(segment) (((segment) == R_NONE) ? R_NONE : ((segment) & 0x7f))
#define SEGMENT_GET_UNSAFE(segment) ((segment) & 0x7f)
#define SEGMENT_IS_DEFAULT(segment) (((int8_t)segment) < -1) /* Quick check it's a negative number that isn't -1, so it's (0x80 | SEGREG). */
#define SEGMENT_IS_DEFAULT_OR_NONE(segment) (((uint8_t)(segment)) > 0x80)

/* Decodes modes of the disassembler, 16 bits or 32 bits or 64 bits for AMD64, x86-64. */
typedef enum { Decode16Bits = 0, Decode32Bits = 1, Decode64Bits = 2 } _DecodeType;

typedef OFFSET_INTEGER _OffsetType;

typedef struct {
	_OffsetType codeOffset, addrMask;
	_OffsetType nextOffset; /* nextOffset is OUT only. */
	const uint8_t* code;
	int codeLen; /* Using signed integer makes it easier to detect an underflow. */
	_DecodeType dt;
	unsigned int features;
} _CodeInfo;

typedef enum { O_NONE, O_REG, O_IMM, O_IMM1, O_IMM2, O_DISP, O_SMEM, O_MEM, O_PC, O_PTR } _OperandType;

typedef union {
	/* Used by O_IMM: */
	int8_t sbyte;
	uint8_t byte;
	int16_t sword;
	uint16_t word;
	int32_t sdword;
	uint32_t dword;
	int64_t sqword; /* All immediates are SIGN-EXTENDED to 64 bits! */
	uint64_t qword;

	/* Used by O_PC: (Use GET_TARGET_ADDR).*/
	_OffsetType addr; /* It's a relative offset as for now. */

	/* Used by O_PTR: */
	struct {
		uint16_t seg;
		/* Can be 16 or 32 bits, size is in ops[n].size. */
		uint32_t off;
	} ptr;

	/* Used by O_IMM1 (i1) and O_IMM2 (i2). ENTER instruction only. */
	struct {
		uint32_t i1;
		uint32_t i2;
	} ex;
} _Value;

typedef struct {
	/* Type of operand:
		O_NONE: operand is to be ignored.
		O_REG: index holds global register index.
		O_IMM: instruction.imm.
		O_IMM1: instruction.imm.ex.i1.
		O_IMM2: instruction.imm.ex.i2.
		O_DISP: memory dereference with displacement only, instruction.disp.
		O_SMEM: simple memory dereference with optional displacement (a single register memory dereference).
		O_MEM: complex memory dereference (optional fields: s/i/b/disp).
		O_PC: the relative address of a branch instruction (instruction.imm.addr).
		O_PTR: the absolute target address of a far branch instruction (instruction.imm.ptr.seg/off).
	*/
	uint8_t type; /* _OperandType */

	/* Index of:
		O_REG: holds global register index
		O_SMEM: holds the 'base' register. E.G: [ECX], [EBX+0x1234] are both in operand.index.
		O_MEM: holds the 'index' register. E.G: [EAX*4] is in operand.index.
	*/
	uint8_t index;

	/* Size in bits of:
		O_REG: register
		O_IMM: instruction.imm
		O_IMM1: instruction.imm.ex.i1
		O_IMM2: instruction.imm.ex.i2
		O_DISP: instruction.disp
		O_SMEM: size of indirection.
		O_MEM: size of indirection.
		O_PC: size of the relative offset
		O_PTR: size of instruction.imm.ptr.off (16 or 32)
	*/
	uint16_t size;
} _Operand;

#define OPCODE_ID_NONE 0
/* Instruction could not be disassembled. */
#define FLAG_NOT_DECODABLE ((uint16_t)-1)
/* The instruction locks memory access. */
#define FLAG_LOCK (1 << 0)
/* The instruction is prefixed with a REPNZ. */
#define FLAG_REPNZ (1 << 1)
/* The instruction is prefixed with a REP, this can be a REPZ, it depends on the specific instruction. */
#define FLAG_REP (1 << 2)
/* Indicates there is a hint taken for Jcc instructions only. */
#define FLAG_HINT_TAKEN (1 << 3)
/* Indicates there is a hint non-taken for Jcc instructions only. */
#define FLAG_HINT_NOT_TAKEN (1 << 4)
/* The Imm value is signed extended (E.G in 64 bit decoding mode, a 32 bit imm is usually sign extended into 64 bit imm). */
#define FLAG_IMM_SIGNED (1 << 5)
/* The destination operand is writable. */
#define FLAG_DST_WR (1 << 6)
/* The instruction uses RIP-relative indirection. */
#define FLAG_RIP_RELATIVE (1 << 7)

/* See flag FLAG_GET_XXX macros above. */

/* The instruction is privileged and can only be used from Ring0. */
#define FLAG_PRIVILEGED_INSTRUCTION (1 << 15)

/* No register was defined. */
#define R_NONE ((uint8_t)-1)

#define REGS64_BASE 0
#define REGS32_BASE 16
#define REGS16_BASE 32
#define REGS8_BASE 48
#define REGS8_REX_BASE 64
#define SREGS_BASE 68
#define FPUREGS_BASE 75
#define MMXREGS_BASE 83
#define SSEREGS_BASE 91
#define AVXREGS_BASE 107
#define CREGS_BASE 123
#define DREGS_BASE 132

#define OPERANDS_NO (4)

typedef struct {
	/* Used by ops[n].type == O_IMM/O_IMM1&O_IMM2/O_PTR/O_PC. Its size is ops[n].size. */
	_Value imm;
	/* Used by ops[n].type == O_SMEM/O_MEM/O_DISP. Its size is dispSize. */
	uint64_t disp;
	/* Virtual address of first byte of instruction. */
	_OffsetType addr;
	/* General flags of instruction, holds prefixes and more, if FLAG_NOT_DECODABLE, instruction is invalid. */
	uint16_t flags;
	/* Unused prefixes mask, for each bit that is set that prefix is not used (LSB is byte [addr + 0]). */
	uint16_t unusedPrefixesMask;
	/* Mask of registers that were used in the operands, only used for quick look up, in order to know *some* operand uses that register class. */
	uint32_t usedRegistersMask;
	/* ID of opcode in the global opcode table. Use for mnemonic look up. */
	uint16_t opcode;
	/* Up to four operands per instruction, ignored if ops[n].type == O_NONE. */
	_Operand ops[OPERANDS_NO];
	/* Number of valid ops entries. */
	uint8_t opsNo;
	/* Size of the whole instruction in bytes. */
	uint8_t size;
	/* Segment information of memory indirection, default segment, or overriden one, can be -1. Use SEGMENT macros. */
	uint8_t segment;
	/* Used by ops[n].type == O_MEM. Base global register index (might be R_NONE), scale size (2/4/8), ignored for 0 or 1. */
	uint8_t base, scale;
	uint8_t dispSize;
	/* Meta defines the instruction set class, and the flow control flags. Use META macros. */
	uint16_t meta;
	/* The CPU flags that the instruction operates upon, set only with DF_FILL_EFLAGS enabled, otherwise 0. */
	uint16_t modifiedFlagsMask, testedFlagsMask, undefinedFlagsMask;
} _DInst;

#ifndef DISTORM_LIGHT

/* Static size of strings. Do not change this value. Keep Python wrapper in sync. */
#define MAX_TEXT_SIZE (48)
typedef struct {
	unsigned int length;
	unsigned char p[MAX_TEXT_SIZE]; /* p is a null terminated string. */
} _WString;

/*
 * Old decoded instruction structure in text format.
 * Used only for backward compatibility with diStorm64.
 * This structure holds all information the disassembler generates per instruction.
 */
typedef struct {
	_OffsetType offset; /* Start offset of the decoded instruction. */
	unsigned int size; /* Size of decoded instruction in bytes. */
	_WString mnemonic; /* Mnemonic of decoded instruction, prefixed if required by REP, LOCK etc. */
	_WString operands; /* Operands of the decoded instruction, up to 3 operands, comma-seperated. */
	_WString instructionHex; /* Hex dump - little endian, including prefixes. */
} _DecodedInst;

#endif /* DISTORM_LIGHT */

/* Register masks for quick look up, each mask indicates one of a register-class that is being used in some operand. */
#define RM_AX 1     /* AL, AH, AX, EAX, RAX */
#define RM_CX 2     /* CL, CH, CX, ECX, RCX */
#define RM_DX 4     /* DL, DH, DX, EDX, RDX */
#define RM_BX 8     /* BL, BH, BX, EBX, RBX */
#define RM_SP 0x10  /* SPL, SP, ESP, RSP */
#define RM_BP 0x20  /* BPL, BP, EBP, RBP */
#define RM_SI 0x40  /* SIL, SI, ESI, RSI */
#define RM_DI 0x80  /* DIL, DI, EDI, RDI */
#define RM_FPU 0x100 /* ST(0) - ST(7) */
#define RM_MMX 0x200 /* MM0 - MM7 */
#define RM_SSE 0x400 /* XMM0 - XMM15 */
#define RM_AVX 0x800 /* YMM0 - YMM15 */
#define RM_CR 0x1000 /* CR0, CR2, CR3, CR4, CR8 */
#define RM_DR 0x2000 /* DR0, DR1, DR2, DR3, DR6, DR7 */
#define RM_R8 0x4000 /* R8B, R8W, R8D, R8 */
#define RM_R9 0x8000 /* R9B, R9W, R9D, R9 */
#define RM_R10 0x10000 /* R10B, R10W, R10D, R10 */
#define RM_R11 0x20000 /* R11B, R11W, R11D, R11 */
#define RM_R12 0x40000 /* R12B, R12W, R12D, R12 */
#define RM_R13 0x80000 /* R13B, R13W, R13D, R13 */
#define RM_R14 0x100000 /* R14B, R14W, R14D, R14 */
#define RM_R15 0x200000 /* R15B, R15W, R15D, R15 */
#define RM_SEG 0x400000 /* CS, SS, DS, ES, FS, GS */

/* RIP should be checked using the 'flags' field and FLAG_RIP_RELATIVE.
 * Segments should be checked using the segment macros.
 * For now R8 - R15 are not supported and non general purpose registers map into same RM.
 */

/* CPU flags that instructions modify, test or undefine (are EFLAGS compatible!). */
#define D_CF 1		/* Carry */
#define D_PF 4		/* Parity */
#define D_AF 0x10	/* Auxiliary */
#define D_ZF 0x40	/* Zero */
#define D_SF 0x80	/* Sign */
#define D_IF 0x200	/* Interrupt */
#define D_DF 0x400	/* Direction */
#define D_OF 0x800	/* Overflow */

/*
 * Instructions Set classes:
 * if you want a better understanding of the available classes, look at disOps project, file: x86sets.py.
 */
/* Indicates the instruction belongs to the General Integer set. */
#define ISC_INTEGER 1
/* Indicates the instruction belongs to the 387 FPU set. */
#define ISC_FPU 2
/* Indicates the instruction belongs to the P6 set. */
#define ISC_P6 3
/* Indicates the instruction belongs to the MMX set. */
#define ISC_MMX 4
/* Indicates the instruction belongs to the SSE set. */
#define ISC_SSE 5
/* Indicates the instruction belongs to the SSE2 set. */
#define ISC_SSE2 6
/* Indicates the instruction belongs to the SSE3 set. */
#define ISC_SSE3 7
/* Indicates the instruction belongs to the SSSE3 set. */
#define ISC_SSSE3 8
/* Indicates the instruction belongs to the SSE4.1 set. */
#define ISC_SSE4_1 9
/* Indicates the instruction belongs to the SSE4.2 set. */
#define ISC_SSE4_2 10
/* Indicates the instruction belongs to the AMD's SSE4.A set. */
#define ISC_SSE4_A 11
/* Indicates the instruction belongs to the 3DNow! set. */
#define ISC_3DNOW 12
/* Indicates the instruction belongs to the 3DNow! Extensions set. */
#define ISC_3DNOWEXT 13
/* Indicates the instruction belongs to the VMX (Intel) set. */
#define ISC_VMX 14
/* Indicates the instruction belongs to the SVM (AMD) set. */
#define ISC_SVM 15
/* Indicates the instruction belongs to the AVX (Intel) set. */
#define ISC_AVX 16
/* Indicates the instruction belongs to the FMA (Intel) set. */
#define ISC_FMA 17
/* Indicates the instruction belongs to the AES/AVX (Intel) set. */
#define ISC_AES 18
/* Indicates the instruction belongs to the CLMUL (Intel) set. */
#define ISC_CLMUL 19

/* Features for decompose: */
#define DF_NONE 0
/* The decoder will limit addresses to a maximum of 16 bits. */
#define DF_MAXIMUM_ADDR16 1
/* The decoder will limit addresses to a maximum of 32 bits. */
#define DF_MAXIMUM_ADDR32 2
/* The decoder will return only flow control instructions (and filter the others internally). */
#define DF_RETURN_FC_ONLY 4
/* The decoder will stop and return to the caller when the instruction 'CALL' (near and far) was decoded. */
#define DF_STOP_ON_CALL 8
/* The decoder will stop and return to the caller when the instruction 'RET' (near and far) was decoded. */
#define DF_STOP_ON_RET 0x10
/* The decoder will stop and return to the caller when the instruction system-call/ret was decoded. */
#define DF_STOP_ON_SYS 0x20
/* The decoder will stop and return to the caller when any of the branch 'JMP', (near and far) instructions were decoded. */
#define DF_STOP_ON_UNC_BRANCH 0x40
/* The decoder will stop and return to the caller when any of the conditional branch instruction were decoded. */
#define DF_STOP_ON_CND_BRANCH 0x80
/* The decoder will stop and return to the caller when the instruction 'INT' (INT, INT1, INTO, INT 3) was decoded. */
#define DF_STOP_ON_INT 0x100
/* The decoder will stop and return to the caller when any of the 'CMOVxx' instruction was decoded. */
#define DF_STOP_ON_CMOV 0x200
/* The decoder will stop and return to the caller when it encounters the HLT instruction. */
#define DF_STOP_ON_HLT 0x400
/* The decoder will stop and return to the caller when it encounters a privileged instruction. */
#define DF_STOP_ON_PRIVILEGED 0x800
/* The decoder will stop and return to the caller when an instruction couldn't be decoded. */
#define DF_STOP_ON_UNDECODEABLE 0x1000
/* The decoder will not synchronize to the next byte after the previosuly decoded instruction, instead it will start decoding at the next byte. */
#define DF_SINGLE_BYTE_STEP 0x2000
/* The decoder will fill in the eflags fields for the decoded instruction. */
#define DF_FILL_EFLAGS 0x4000
/* The decoder will use the addrMask in CodeInfo structure instead of DF_MAXIMUM_ADDR16/32. */
#define DF_USE_ADDR_MASK 0x8000

/* The decoder will stop and return to the caller when any flow control instruction was decoded. */
#define DF_STOP_ON_FLOW_CONTROL (DF_STOP_ON_CALL | DF_STOP_ON_RET | DF_STOP_ON_SYS | DF_STOP_ON_UNC_BRANCH | DF_STOP_ON_CND_BRANCH | DF_STOP_ON_INT | DF_STOP_ON_CMOV | DF_STOP_ON_HLT)

/* Indicates the instruction is not a flow-control instruction. */
#define FC_NONE 0
/* Indicates the instruction is one of: CALL, CALL FAR. */
#define FC_CALL 1
/* Indicates the instruction is one of: RET, IRET, RETF. */
#define FC_RET 2
/* Indicates the instruction is one of: SYSCALL, SYSRET, SYSENTER, SYSEXIT. */
#define FC_SYS 3
/* Indicates the instruction is one of: JMP, JMP FAR. */
#define FC_UNC_BRANCH 4
/*
 * Indicates the instruction is one of:
 * JCXZ, JO, JNO, JB, JAE, JZ, JNZ, JBE, JA, JS, JNS, JP, JNP, JL, JGE, JLE, JG, LOOP, LOOPZ, LOOPNZ.
 */
#define FC_CND_BRANCH 5
/* Indiciates the instruction is one of: INT, INT1, INT 3, INTO, UD2. */
#define FC_INT 6
/* Indicates the instruction is one of: CMOVxx. */
#define FC_CMOV 7
/* Indicates the instruction is HLT. */
#define FC_HLT 8

/* Return code of the decoding function. */
typedef enum { DECRES_NONE, DECRES_SUCCESS, DECRES_MEMORYERR, DECRES_INPUTERR } _DecodeResult;

/* Define the following interface functions only for outer projects. */
#if !(defined(DISTORM_STATIC) || defined(DISTORM_DYNAMIC))

/* distorm_decode
 * Input:
 *         offset - Origin of the given code (virtual address that is), NOT an offset in code.
 *         code - Pointer to the code buffer to be disassembled.
 *         length - Amount of bytes that should be decoded from the code buffer.
 *         dt - Decoding mode, 16 bits (Decode16Bits), 32 bits (Decode32Bits) or AMD64 (Decode64Bits).
 *         result - Array of type _DecodeInst which will be used by this function in order to return the disassembled instructions.
 *         maxInstructions - The maximum number of entries in the result array that you pass to this function, so it won't exceed its bound.
 *         usedInstructionsCount - Number of the instruction that successfully were disassembled and written to the result array.
 * Output: usedInstructionsCount will hold the number of entries used in the result array
 *         and the result array itself will be filled with the disassembled instructions.
 * Return: DECRES_SUCCESS on success (no more to disassemble), DECRES_INPUTERR on input error (null code buffer, invalid decoding mode, etc...),
 *         DECRES_MEMORYERR when there are not enough entries to use in the result array, BUT YOU STILL have to check for usedInstructionsCount!
 * Side-Effects: Even if the return code is DECRES_MEMORYERR, there might STILL be data in the
 *               array you passed, this function will try to use as much entries as possible!
 * Notes:  1)The minimal size of maxInstructions is 15.
 *         2)You will have to synchronize the offset,code and length by yourself if you pass code fragments and not a complete code block!
 */

/* distorm_decompose
 * See more documentation online at the GitHub project's wiki.
 *
 */
#ifdef SUPPORT_64BIT_OFFSET

	_DecodeResult distorm_decompose64(_CodeInfo* ci, _DInst result[], unsigned int maxInstructions, unsigned int* usedInstructionsCount);
	#define distorm_decompose distorm_decompose64

#ifndef DISTORM_LIGHT
	/* If distorm-light is defined, we won't export these text-formatting functionality. */
	_DecodeResult distorm_decode64(_OffsetType codeOffset, const unsigned char* code, int codeLen, _DecodeType dt, _DecodedInst result[], unsigned int maxInstructions, unsigned int* usedInstructionsCount);
	void distorm_format64(const _CodeInfo* ci, const _DInst* di, _DecodedInst* result);
	#define distorm_decode distorm_decode64
	#define distorm_format distorm_format64
#endif /*DISTORM_LIGHT*/

#else /*SUPPORT_64BIT_OFFSET*/

	_DecodeResult distorm_decompose32(_CodeInfo* ci, _DInst result[], unsigned int maxInstructions, unsigned int* usedInstructionsCount);
	#define distorm_decompose distorm_decompose32

#ifndef DISTORM_LIGHT
	/* If distorm-light is defined, we won't export these text-formatting functionality. */
	_DecodeResult distorm_decode32(_OffsetType codeOffset, const unsigned char* code, int codeLen, _DecodeType dt, _DecodedInst result[], unsigned int maxInstructions, unsigned int* usedInstructionsCount);
	void distorm_format32(const _CodeInfo* ci, const _DInst* di, _DecodedInst* result);
	#define distorm_decode distorm_decode32
	#define distorm_format distorm_format32
#endif /*DISTORM_LIGHT*/

#endif

/*
 * distorm_version
 * Input:
 *        none
 *
 * Output: unsigned int - version of compiled library.
 */
unsigned int distorm_version(void);

#endif /* DISTORM_STATIC */

#ifdef __cplusplus
} /* End Of Extern */
#endif

#endif /* DISTORM_H */
