using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace AnalysisLibrary
{
    public class PortableExecutableStruct
    {
        /// <summary>
        /// MAGIC Type
        /// </summary>
        public readonly static ushort IMAGE_ROM_OPTIONAL_HDR_MAGIC = 0x107;
        public readonly static ushort IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b;
        public readonly static ushort IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;
        /// <summary>
        ///  Directory Entries
        /// </summary>
        public readonly static ushort IMAGE_DIRECTORY_ENTRY_EXPORT = 0;   // Export Directory
        public readonly static ushort IMAGE_DIRECTORY_ENTRY_IMPORT = 1;  // Import Directory
        public readonly static ushort IMAGE_DIRECTORY_ENTRY_RESOURCE = 2; // Resource Directory
        public readonly static ushort IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3;  // Exception Directory
        public readonly static ushort IMAGE_DIRECTORY_ENTRY_SECURITY = 4;  // Security Directory
        public readonly static ushort IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;  // Base Relocation Table
        public readonly static ushort IMAGE_DIRECTORY_ENTRY_DEBUG = 6;  // Debug Directory
        //IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
        public readonly static ushort IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7; // Architecture Specific Data
        public readonly static ushort IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8; // RVA of GP
        public readonly static ushort IMAGE_DIRECTORY_ENTRY_TLS = 9; // TLS Directory
        public readonly static ushort IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10; // Load Configuration Directory
        public readonly static ushort IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11; // Bound Import Directory in headers
        public readonly static ushort IMAGE_DIRECTORY_ENTRY_IAT = 12; // Import Address Table
        public readonly static ushort IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13; // Delay Load Import Descriptors
        public readonly static ushort IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14; // COM Runtime descriptor
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _IMAGE_DOS_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.ByValTStr, SizeConst = 2)]
            public char[] e_magic;         // Magic number
            public ushort e_cblp;          // bytes on last page of file
            public ushort e_cp;            // Pages in file
            public ushort e_crlc;          // Relocations
            public ushort e_cparhdr;       // Size of header in paragraphs
            public ushort e_minalloc;      // Minimum extra paragraphs needed
            public ushort e_maxalloc;      // Maximum extra paragraphs needed
            public ushort e_ss;            // Initial (relative) SS value
            public ushort e_sp;            // Initial SP value
            public ushort e_csum;          // Checksum
            public ushort e_ip;            // Initial IP value
            public ushort e_cs;            // Initial (relative) CS value
            public ushort e_lfarlc;        // File address of relocation table
            public ushort e_ovno;          // Overlay number
            [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.U2, SizeConst = 4)]
            public ushort[] e_res;        // Reserved ushorts
            public ushort e_oemid;         // OEM identifier (for e_oeminfo)
            public ushort e_oeminfo;       // OEM information; e_oemid specific
            [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.U2, SizeConst = 10)]
            public ushort[] e_res2;      // Reserved ushorts
            public Int32 e_lfanew;        // File address of new exe header
        }
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        };
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _IMAGE_OPTIONAL_HEADER32
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public uint BaseOfData;
            public uint ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public uint SizeOfStackReserve;
            public uint SizeOfStackCommit;
            public uint SizeOfHeapReserve;
            public uint SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
        }
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _IMAGE_OPTIONAL_HEADER64
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public UInt64 ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public UInt64 SizeOfStackReserve;
            public UInt64 SizeOfStackCommit;
            public UInt64 SizeOfHeapReserve;
            public UInt64 SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
        }
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _IMAGE_NT_HEADERS32
        {
            public uint Signature;
            public _IMAGE_FILE_HEADER FileHeader;
            public _IMAGE_OPTIONAL_HEADER32 OptionalHeader;
        }
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _IMAGE_NT_HEADERS64
        {
            public uint Signature;
            public _IMAGE_FILE_HEADER FileHeader;
            public _IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] Name;
            public uint Misc;//VirtualSize PhysicalAddress
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
            public uint PointerToRelocations;
            public uint PointerToLinenumbers;
            public ushort NumberOfRelocations;
            public ushort NumberOfLinenumbers;
            public uint Characteristics;
        }
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _IMAGE_EXPORT_DIRECTORY
        {
            public uint Characteristics;
            public uint TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public uint Name;
            public uint Base;
            public uint NumberOfFunctions;
            public uint NumberOfNames;
            public uint AddressOfFunctions;
            public uint AddressOfNames;
            public uint AddressOfNameOrdinals;
        }
        public struct _IMAGE_EXPORT_DIRECTORY_LIST
        {
            public _IMAGE_EXPORT_DIRECTORY IMAGE_EXPORT_DIRECTORY;
            public uint[] FunctionsAddressList;
            public uint[] NameAddressList;
            public ushort[] NameOrdinalsList;
        }
        public struct _EXPORT_FUNCTION
        {
            public uint Ordinal;
            public UInt64 RVAAddressOfFunctions;
            public UInt64 RVAAddressOfNames;
            public UInt64 RVAAddressOfNameOrdinals;
            public UInt64 AddressOfFunctions;
            public UInt64 AddressOfNames;
            public UInt64 AddressOfNameOrdinals;
            public string FunctionName;

        }

    }
}
