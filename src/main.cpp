// diStorm64 library sample
// http://ragestorm.net/distorm/
// Arkon, Stefan, 2005

/* 
Contains source code obtained from pe-parse project which consists of the portable executable PE parser
see below license for parts from the PE - parser:
*/

/*
The MIT License (MIT)

Copyright (c) 2013 Andrew Ruef

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/


//#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <stdlib.h>

#include "distorm.h"

#include <cstring>
#include <iomanip>
#include <ios>
#include <iostream>
#include <sstream>

#include "parse.h"

#include "argh.h"

using namespace peparse;

// The number of the array of instructions the decoder function will use to return the disassembled instructions.
// Play with this value for performance...
#define MAX_INSTRUCTIONS (1000)

typedef unsigned char       BYTE;
#define IMAGE_SYM_CLASS_END_OF_FUNCTION     (BYTE )-1

//bool FileReadString(char* filename, unsigned char** filebuffer, size_t* file_length, uint64_t offset)
//{
//	//uint64_t relative_offset = offset;
//
//	unsigned char* buffer = *filebuffer;
//	size_t length;
//	FILE* f = fopen(filename, "rb");
//
//	if (f)
//	{
//		fseek(f, 0, SEEK_END);
//		length = ftell(f);
//		*file_length = length;
//		fseek(f, 0, SEEK_SET);
//
//		//if (fseek(f, offset, SEEK_SET) != 0) {
//		//	perror("Error seeking in file");
//		//	fclose(f);
//		//	return 1;
//		//}
//
//		buffer = (unsigned char*)malloc(sizeof(unsigned char) * length + 1);
//		if (buffer)
//		{
//			fread(buffer, 1, length, f);
//			buffer[length] = '\0';
//		}
//		fclose(f);
//
//		*filebuffer = buffer;
//
//		return true;
//	}
//	else
//	{
//		return false;
//	}
//}

int printExps(void* N,
    const VA& funcAddr,
    std::uint16_t ordinal,
    const std::string& mod,
    const std::string& func,
    const std::string& fwd) {
    static_cast<void>(N);

    auto address = static_cast<std::uint32_t>(funcAddr);

    // save default formatting
    std::ios initial(nullptr);
    initial.copyfmt(std::cout);

    std::cout << "EXP #";
    std::cout << ordinal;
    std::cout << ": ";
    std::cout << mod;
    std::cout << "!";
    std::cout << func;
    std::cout << ": ";
    if (!fwd.empty()) {
        std::cout << fwd;
    }
    else {
        std::cout << std::showbase << std::hex << address;
    }
    std::cout << "\n";

    // restore default formatting
    std::cout.copyfmt(initial);
    return 0;
}

int printImports(void* N,
    const VA& impAddr,
    const std::string& modName,
    const std::string& symName) {
    static_cast<void>(N);

    auto address = static_cast<std::uint32_t>(impAddr);

    std::cout << "0x" << std::hex << address << " " << modName << "!" << symName;
    std::cout << "\n";
    return 0;
}

int printRelocs(void* N, const VA& relocAddr, const reloc_type& type) {
    static_cast<void>(N);

    std::cout << "TYPE: ";
    switch (type) {
    case RELOC_ABSOLUTE:
        std::cout << "ABSOLUTE";
        break;
    case RELOC_HIGH:
        std::cout << "HIGH";
        break;
    case RELOC_LOW:
        std::cout << "LOW";
        break;
    case RELOC_HIGHLOW:
        std::cout << "HIGHLOW";
        break;
    case RELOC_HIGHADJ:
        std::cout << "HIGHADJ";
        break;
    case RELOC_MIPS_JMPADDR:
        std::cout << "MIPS_JMPADDR";
        break;
    case RELOC_MIPS_JMPADDR16:
        std::cout << "MIPS_JMPADD16";
        break;
    case RELOC_DIR64:
        std::cout << "DIR64";
        break;
    default:
        std::cout << "UNKNOWN";
        break;
    }

    std::cout << " VA: 0x" << std::hex << relocAddr << "\n";

    return 0;
}

int printDebugs(void* N,
    const std::uint32_t& type,
    const bounded_buffer* data) {
    static_cast<void>(N);

    std::cout << "Debug Directory Type: ";
    switch (type) {
    case 0:
        std::cout << "IMAGE_DEBUG_TYPE_UNKNOWN";
        break;
    case 1:
        std::cout << "IMAGE_DEBUG_TYPE_COFF";
        break;
    case 2:
        std::cout << "IMAGE_DEBUG_TYPE_CODEVIEW";
        break;
    case 3:
        std::cout << "IMAGE_DEBUG_TYPE_FPO";
        break;
    case 4:
        std::cout << "IMAGE_DEBUG_TYPE_MISC";
        break;
    case 5:
        std::cout << "IMAGE_DEBUG_TYPE_EXCEPTION";
        break;
    case 6:
        std::cout << "IMAGE_DEBUG_TYPE_FIXUP";
        break;
    case 7:
        std::cout << "IMAGE_DEBUG_TYPE_OMAP_TO_SRC";
        break;
    case 8:
        std::cout << "IMAGE_DEBUG_TYPE_OMAP_FROM_SRC";
        break;
    case 9:
        std::cout << "IMAGE_DEBUG_TYPE_BORLAND";
        break;
    case 10:
        std::cout << "IMAGE_DEBUG_TYPE_RESERVED10";
        break;
    case 11:
        std::cout << "IMAGE_DEBUG_TYPE_CLSID";
        break;
    case 12:
        std::cout << "IMAGE_DEBUG_TYPE_VC_FEATURE";
        break;
    case 13:
        std::cout << "IMAGE_DEBUG_TYPE_POGO";
        break;
    case 14:
        std::cout << "IMAGE_DEBUG_TYPE_ILTCG";
        break;
    case 15:
        std::cout << "IMAGE_DEBUG_TYPE_MPX";
        break;
    case 16:
        std::cout << "IMAGE_DEBUG_TYPE_REPRO";
        break;
    case 20:
        std::cout << "IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS";
        break;
    default:
        std::cout << "INVALID";
        break;
    }
    std::cout << "\n";
    std::cout << "Debug Directory Data: ";
    for (uint32_t i = 0; i < data->bufLen; i++) {
        std::cout << " 0x" << std::hex << static_cast<int>(data->buf[i]);
    }
    std::cout << "\n";

    return 0;
}

int printSymbols(void* N,
    const std::string& strName,
    const uint32_t& value,
    const int16_t& sectionNumber,
    const uint16_t& type,
    const uint8_t& storageClass,
    const uint8_t& numberOfAuxSymbols) {
    static_cast<void>(N);

    std::cout << "Symbol Name: " << strName << "\n";
    std::cout << "Symbol Value: 0x" << std::hex << value << "\n";

    std::cout << "Symbol Section Number: ";
    switch (sectionNumber) {
    case IMAGE_SYM_UNDEFINED:
        std::cout << "UNDEFINED";
        break;
    case IMAGE_SYM_ABSOLUTE:
        std::cout << "ABSOLUTE";
        break;
    case IMAGE_SYM_DEBUG:
        std::cout << "DEBUG";
        break;
    default:
        std::cout << sectionNumber;
        break;
    }
    std::cout << "\n";

    std::cout << "Symbol Type: ";
    switch (type) {
    case IMAGE_SYM_TYPE_NULL:
        std::cout << "NULL";
        break;
    case IMAGE_SYM_TYPE_VOID:
        std::cout << "VOID";
        break;
    case IMAGE_SYM_TYPE_CHAR:
        std::cout << "CHAR";
        break;
    case IMAGE_SYM_TYPE_SHORT:
        std::cout << "SHORT";
        break;
    case IMAGE_SYM_TYPE_INT:
        std::cout << "INT";
        break;
    case IMAGE_SYM_TYPE_LONG:
        std::cout << "LONG";
        break;
    case IMAGE_SYM_TYPE_FLOAT:
        std::cout << "FLOAT";
        break;
    case IMAGE_SYM_TYPE_DOUBLE:
        std::cout << "DOUBLE";
        break;
    case IMAGE_SYM_TYPE_STRUCT:
        std::cout << "STRUCT";
        break;
    case IMAGE_SYM_TYPE_UNION:
        std::cout << "UNION";
        break;
    case IMAGE_SYM_TYPE_ENUM:
        std::cout << "ENUM";
        break;
    case IMAGE_SYM_TYPE_MOE:
        std::cout << "IMAGE_SYM_TYPE_MOE";
        break;
    case IMAGE_SYM_TYPE_BYTE:
        std::cout << "BYTE";
        break;
    case IMAGE_SYM_TYPE_WORD:
        std::cout << "WORD";
        break;
    case IMAGE_SYM_TYPE_UINT:
        std::cout << "UINT";
        break;
    case IMAGE_SYM_TYPE_DWORD:
        std::cout << "DWORD";
        break;
    default:
        std::cout << "UNKNOWN";
        break;
    }
    std::cout << "\n";

    std::cout << "Symbol Storage Class: ";
    switch (storageClass) {
    case IMAGE_SYM_CLASS_END_OF_FUNCTION:
        std::cout << "FUNCTION";
        break;
    case IMAGE_SYM_CLASS_NULL:
        std::cout << "NULL";
        break;
    case IMAGE_SYM_CLASS_AUTOMATIC:
        std::cout << "AUTOMATIC";
        break;
    case IMAGE_SYM_CLASS_EXTERNAL:
        std::cout << "EXTERNAL";
        break;
    case IMAGE_SYM_CLASS_STATIC:
        std::cout << "STATIC";
        break;
    case IMAGE_SYM_CLASS_REGISTER:
        std::cout << "REGISTER";
        break;
    case IMAGE_SYM_CLASS_EXTERNAL_DEF:
        std::cout << "EXTERNAL DEF";
        break;
    case IMAGE_SYM_CLASS_LABEL:
        std::cout << "LABEL";
        break;
    case IMAGE_SYM_CLASS_UNDEFINED_LABEL:
        std::cout << "UNDEFINED LABEL";
        break;
    case IMAGE_SYM_CLASS_MEMBER_OF_STRUCT:
        std::cout << "MEMBER OF STRUCT";
        break;
    default:
        std::cout << "UNKNOWN";
        break;
    }
    std::cout << "\n";

    std::cout << "Symbol Number of Aux Symbols: "
        << static_cast<std::uint32_t>(numberOfAuxSymbols) << "\n";

    return 0;
}

int printRich(void* N, const rich_entry& r) {
    static_cast<void>(N);
    std::cout << std::dec;
    std::cout << std::setw(10) << "ProdId:" << std::setw(7) << r.ProductId;
    std::cout << std::setw(10) << "Build:" << std::setw(7) << r.BuildNumber;
    std::cout << std::setw(10) << "Name:" << std::setw(40)
        << GetRichProductName(r.BuildNumber) << " "
        << GetRichObjectType(r.ProductId);
    std::cout << std::setw(10) << "Count:" << std::setw(7) << r.Count << "\n";
    return 0;
}

int printRsrc(void* N, const resource& r) {
    static_cast<void>(N);

    if (r.type_str.length())
        std::cout << "Type (string): " << r.type_str << "\n";
    else
        std::cout << "Type: 0x" << std::hex << r.type << "\n";

    if (r.name_str.length())
        std::cout << "Name (string): " << r.name_str << "\n";
    else
        std::cout << "Name: 0x" << std::hex << r.name << "\n";

    if (r.lang_str.length())
        std::cout << "Lang (string): " << r.lang_str << "\n";
    else
        std::cout << "Lang: 0x" << std::hex << r.lang << "\n";

    std::cout << "Codepage: 0x" << std::hex << r.codepage << "\n";
    std::cout << "RVA: " << std::dec << r.RVA << "\n";
    std::cout << "Size: " << std::dec << r.size << "\n";
    return 0;
}

int printSecs(void* N,
    const VA& secBase,
    const std::string& secName,
    const image_section_header& s,
    const bounded_buffer* data) {
    static_cast<void>(N);
    static_cast<void>(s);

    std::cout << "Sec Name: " << secName << "\n";
    std::cout << "Sec Base: 0x" << std::hex << secBase << "\n";
    if (data)
        std::cout << "Sec Size: " << std::dec << data->bufLen << "\n";
    else
        std::cout << "Sec Size: 0"
        << "\n";
    return 0;
}

#define DUMP_FIELD(x)           \
  std::cout << "" #x << ": 0x"; \
  std::cout << std::hex << static_cast<std::uint64_t>(p->peHeader.x) << "\n";
#define DUMP_DEC_FIELD(x)     \
  std::cout << "" #x << ": "; \
  std::cout << std::dec << static_cast<std::uint64_t>(p->peHeader.x) << "\n";
#define DUMP_BOOL_FIELD(x)    \
  std::cout << "" #x << ": "; \
  std::cout << std::boolalpha << static_cast<bool>(p->peHeader.x) << "\n";


int main(int argc, char** argv)
{
	char* filename;
	size_t filesize = 0;

	// Version of used compiled library.
	unsigned long dver = 0;
	// Holds the result of the decoding.
	_DecodeResult res;
	// Decoded instruction information.
	_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
	// next is used for instruction's offset synchronization.
	// decodedInstructionsCount holds the count of filled instructions' array by the decoder.
	unsigned int decodedInstructionsCount = 0;
	unsigned int i, next;

	// Default decoding mode is 32 bits, could be set by command line.
	_DecodeType dt = Decode32Bits;

	// Default offset for buffer is 0, could be set in command line.
	_OffsetType offset = 0;
	char* errch = NULL;

	// Index to file name in argv.
	int param = 1;

	// Buffer to disassemble.
	unsigned char* buf, * buf2;

	// Disassembler version.
	dver = distorm_version();
	printf("diStorm version: %d.%d.%d\n", (dver >> 16), ((dver) >> 8) & 0xff, dver & 0xff);

	// Check params.
	if (argc < 2 || argc > 4) {
		printf("Usage: disasm.exe [-b16] [-b64] filename [memory offset]\r\nRaw disassembler output.\r\nMemory offset is origin of binary file in memory (address in hex).\r\nDefault decoding mode is -b32.\r\nexample:   disasm -b16 demo.com 789a\r\n");
		return -1;
	}

	if (strncmp(argv[param], "-b16", 4) == 0) {
		dt = Decode16Bits;
		param++;
	}
	else if (strncmp(argv[param], "-b64", 4) == 0) {
		dt = Decode64Bits;
		param++;
	}
	else if (*argv[param] == '-') {
		printf("Decoding mode size isn't specified!");
		return -1;
	}
	else if (argc == 4) {
		printf("Too many parameters are set.");
		return -1;
	}
	if (param >= argc) {
		printf("Filename is missing.");
		return -1;
	}
	if (param + 1 == argc - 1) { // extra param?
#ifdef SUPPORT_64BIT_OFFSET
		offset = _strtoui64(argv[param + 1], &errch, 16);
#else
		offset = strtoul(argv[param + 1], &errch, 16);
#endif
		if (*errch != '\0') {
			printf("Offset couldn't be converted.");
			return -1;
		}
	}

	filename = argv[param];
	//offset = 810; // 0x1410
    
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    argh::parser cmdl(argv);

    //if (cmdl[{"-h", "--help"}] || argc <= 1) {
    //    std::cout << "dump-pe utility from Trail of Bits\n";
    //    std::cout << "Repository: https://github.com/trailofbits/pe-parse\n\n";
    //    std::cout << "Usage:\n\tdump-pe /path/to/executable.exe\n";
    //    return 0;
    //}
    //else if (cmdl[{"-v", "--version"}]) {
    //    std::cout << "dump-pe (pe-parse) version " << PEPARSE_VERSION << "\n";
    //    return 0;
    //}

    parsed_pe* p = ParsePEFromFile(cmdl[1].c_str());


    if (p == nullptr) {
        std::cout << "Error: " << GetPEErr() << " (" << GetPEErrString() << ")"
            << "\n";
        std::cout << "Location: " << GetPEErrLoc() << "\n";
        return 1;
    }

    if (p != NULL) {
        // Print DOS header
        DUMP_FIELD(dos.e_magic);
        DUMP_FIELD(dos.e_cp);
        DUMP_FIELD(dos.e_crlc);
        DUMP_FIELD(dos.e_cparhdr);
        DUMP_FIELD(dos.e_minalloc);
        DUMP_FIELD(dos.e_maxalloc);
        DUMP_FIELD(dos.e_ss);
        DUMP_FIELD(dos.e_sp);
        DUMP_FIELD(dos.e_csum);
        DUMP_FIELD(dos.e_ip);
        DUMP_FIELD(dos.e_cs);
        DUMP_FIELD(dos.e_lfarlc);
        DUMP_FIELD(dos.e_ovno);
        DUMP_FIELD(dos.e_res[0]);
        DUMP_FIELD(dos.e_res[1]);
        DUMP_FIELD(dos.e_res[2]);
        DUMP_FIELD(dos.e_res[3]);
        DUMP_FIELD(dos.e_oemid);
        DUMP_FIELD(dos.e_oeminfo);
        DUMP_FIELD(dos.e_res2[0]);
        DUMP_FIELD(dos.e_res2[1]);
        DUMP_FIELD(dos.e_res2[2]);
        DUMP_FIELD(dos.e_res2[3]);
        DUMP_FIELD(dos.e_res2[4]);
        DUMP_FIELD(dos.e_res2[5]);
        DUMP_FIELD(dos.e_res2[6]);
        DUMP_FIELD(dos.e_res2[7]);
        DUMP_FIELD(dos.e_res2[8]);
        DUMP_FIELD(dos.e_res2[9]);
        DUMP_FIELD(dos.e_lfanew);
        // Print Rich header info
        DUMP_BOOL_FIELD(rich.isPresent);
        if (p->peHeader.rich.isPresent) {
            DUMP_FIELD(rich.DecryptionKey);
            DUMP_FIELD(rich.Checksum);
            DUMP_BOOL_FIELD(rich.isValid);
            IterRich(p, printRich, NULL);
        }
        // print out some things
        DUMP_FIELD(nt.Signature);
        DUMP_FIELD(nt.FileHeader.Machine);
        DUMP_FIELD(nt.FileHeader.NumberOfSections);
        DUMP_DEC_FIELD(nt.FileHeader.TimeDateStamp);
        DUMP_FIELD(nt.FileHeader.PointerToSymbolTable);
        DUMP_DEC_FIELD(nt.FileHeader.NumberOfSymbols);
        DUMP_FIELD(nt.FileHeader.SizeOfOptionalHeader);
        DUMP_FIELD(nt.FileHeader.Characteristics);
        if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
            DUMP_FIELD(nt.OptionalHeader.Magic);
            DUMP_DEC_FIELD(nt.OptionalHeader.MajorLinkerVersion);
            DUMP_DEC_FIELD(nt.OptionalHeader.MinorLinkerVersion);
            DUMP_FIELD(nt.OptionalHeader.SizeOfCode);
            DUMP_FIELD(nt.OptionalHeader.SizeOfInitializedData);
            DUMP_FIELD(nt.OptionalHeader.SizeOfUninitializedData);
            DUMP_FIELD(nt.OptionalHeader.AddressOfEntryPoint);
            DUMP_FIELD(nt.OptionalHeader.BaseOfCode);
            DUMP_FIELD(nt.OptionalHeader.BaseOfData);
            DUMP_FIELD(nt.OptionalHeader.ImageBase);
            DUMP_FIELD(nt.OptionalHeader.SectionAlignment);
            DUMP_FIELD(nt.OptionalHeader.FileAlignment);
            DUMP_DEC_FIELD(nt.OptionalHeader.MajorOperatingSystemVersion);
            DUMP_DEC_FIELD(nt.OptionalHeader.MinorOperatingSystemVersion);
            DUMP_DEC_FIELD(nt.OptionalHeader.Win32VersionValue);
            DUMP_FIELD(nt.OptionalHeader.SizeOfImage);
            DUMP_FIELD(nt.OptionalHeader.SizeOfHeaders);
            DUMP_FIELD(nt.OptionalHeader.CheckSum);
            DUMP_FIELD(nt.OptionalHeader.Subsystem);
            DUMP_FIELD(nt.OptionalHeader.DllCharacteristics);
            DUMP_FIELD(nt.OptionalHeader.SizeOfStackReserve);
            DUMP_FIELD(nt.OptionalHeader.SizeOfStackCommit);
            DUMP_FIELD(nt.OptionalHeader.SizeOfHeapReserve);
            DUMP_FIELD(nt.OptionalHeader.SizeOfHeapCommit);
            DUMP_FIELD(nt.OptionalHeader.LoaderFlags);
            DUMP_DEC_FIELD(nt.OptionalHeader.NumberOfRvaAndSizes);
        }
        else {
            DUMP_FIELD(nt.OptionalHeader64.Magic);
            DUMP_DEC_FIELD(nt.OptionalHeader64.MajorLinkerVersion);
            DUMP_DEC_FIELD(nt.OptionalHeader64.MinorLinkerVersion);
            DUMP_FIELD(nt.OptionalHeader64.SizeOfCode);
            DUMP_FIELD(nt.OptionalHeader64.SizeOfInitializedData);
            DUMP_FIELD(nt.OptionalHeader64.SizeOfUninitializedData);
            DUMP_FIELD(nt.OptionalHeader64.AddressOfEntryPoint);
            DUMP_FIELD(nt.OptionalHeader64.BaseOfCode);
            DUMP_FIELD(nt.OptionalHeader64.ImageBase);
            DUMP_FIELD(nt.OptionalHeader64.SectionAlignment);
            DUMP_FIELD(nt.OptionalHeader64.FileAlignment);
            DUMP_DEC_FIELD(nt.OptionalHeader64.MajorOperatingSystemVersion);
            DUMP_DEC_FIELD(nt.OptionalHeader64.MinorOperatingSystemVersion);
            DUMP_DEC_FIELD(nt.OptionalHeader64.Win32VersionValue);
            DUMP_FIELD(nt.OptionalHeader64.SizeOfImage);
            DUMP_FIELD(nt.OptionalHeader64.SizeOfHeaders);
            DUMP_FIELD(nt.OptionalHeader64.CheckSum);
            DUMP_FIELD(nt.OptionalHeader64.Subsystem);
            DUMP_FIELD(nt.OptionalHeader64.DllCharacteristics);
            DUMP_FIELD(nt.OptionalHeader64.SizeOfStackReserve);
            DUMP_FIELD(nt.OptionalHeader64.SizeOfStackCommit);
            DUMP_FIELD(nt.OptionalHeader64.SizeOfHeapReserve);
            DUMP_FIELD(nt.OptionalHeader64.SizeOfHeapCommit);
            DUMP_FIELD(nt.OptionalHeader64.LoaderFlags);
            DUMP_DEC_FIELD(nt.OptionalHeader64.NumberOfRvaAndSizes);
        }


#undef DUMP_FIELD
#undef DUMP_DEC_FIELD

        std::cout << "Imports: "
            << "\n";
        IterImpVAString(p, printImports, NULL);
        std::cout << "Relocations: "
            << "\n";
        IterRelocs(p, printRelocs, NULL);
        std::cout << "Debug Directories: "
            << "\n";
        IterDebugs(p, printDebugs, NULL);
        std::cout << "Symbols (symbol table): "
            << "\n";
        IterSymbols(p, printSymbols, NULL);
        std::cout << "Sections: "
            << "\n";
        IterSec(p, printSecs, NULL);
        std::cout << "Exports: "
            << "\n";
        IterExpFull(p, printExps, NULL);

        // read the first 8 bytes from the entry point and print them
        VA entryPoint;
        if (GetEntryPoint(p, entryPoint)) {
            std::cout << "First 8 bytes from entry point (0x";
            std::cout << std::hex << entryPoint << "):"
                << "\n";
            for (std::size_t i = 0; i < 8; i++) {
                std::uint8_t b;
                if (!ReadByteAtVA(p, i + entryPoint, b)) {
                    std::cout << " ERR";
                }
                else {
                    std::cout << " 0x" << std::hex << static_cast<int>(b);
                }
            }

            std::cout << "\n";
        }
        
        std::cout << "Resources: " << "\n";
        IterRsrc(p, printRsrc, NULL);

        //////////////////////////// diStorm 3 merged with pe_parser ////////////////////////////

        uint32_t buffer_size;

        buffer_size = ReadSectionSize(p, entryPoint);

        filesize = buffer_size;



        buf = (unsigned char*)malloc(sizeof(unsigned char) * buffer_size);

        if (ReadBytesAtVA(p, entryPoint, buf, buffer_size))
        {

        }
        else 
        {

        }
        offset = entryPoint;

        std::cout << std::endl;

        // DECODER.
        printf("bits: %d\nfilename: %s\norigin: ", dt == Decode16Bits ? 16 : dt == Decode32Bits ? 32 : 64, argv[param]);
#ifdef SUPPORT_64BIT_OFFSET
        if (dt != Decode64Bits) printf("%08I64x\n", offset);
        else printf("%016I64x\n", offset);
#else
        printf("%08x\n", offset);
#endif

        // Decode the buffer at given offset (virtual address).
        //while (1) {
            // If you get an unresolved external symbol linker error for the following line,
            // change the SUPPORT_64BIT_OFFSET in distorm.h.
            res = distorm_decode(offset, (const unsigned char*)(buf), filesize, dt, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);
            if (res == DECRES_INPUTERR) {
                // Null buffer? Decode type not 16/32/64?
                printf("Input error, halting!");
                //free(buf2);
                return -4;
            }

            for (i = 0; i < decodedInstructionsCount; i++) {
    #ifdef SUPPORT_64BIT_OFFSET
                printf("%0*I64x (%02d) %-24s %s%s%s\n", dt != Decode64Bits ? 8 : 16, decodedInstructions[i].offset, decodedInstructions[i].size, (char*)decodedInstructions[i].instructionHex.p, (char*)decodedInstructions[i].mnemonic.p, decodedInstructions[i].operands.length != 0 ? " " : "", (char*)decodedInstructions[i].operands.p);
    #else
                printf("%08x (%02d) %-24s %s%s%s\n", decodedInstructions[i].offset, decodedInstructions[i].size, (char*)decodedInstructions[i].instructionHex.p, (char*)decodedInstructions[i].mnemonic.p, decodedInstructions[i].operands.length != 0 ? " " : "", (char*)decodedInstructions[i].operands.p);
    #endif
            }

            //if (res == DECRES_SUCCESS) break; // All instructions were decoded.
            //else if (decodedInstructionsCount == 0) break;

            // Synchronize:
            //next = (unsigned long)(decodedInstructions[decodedInstructionsCount - 1].offset - offset);
            //next += decodedInstructions[decodedInstructionsCount - 1].size;
            // Advance ptr and recalc offset.
            //buf += next;
            //filesize -= next;
            //offset += next;
        //}

        // Release buffer
        free(buf);

        DestructParsedPE(p);
    }



	return 0;
}