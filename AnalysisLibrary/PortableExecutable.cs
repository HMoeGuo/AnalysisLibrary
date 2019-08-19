using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using static AnalysisLibrary.PortableExecutableStruct;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace AnalysisLibrary
{
    public class PortableExecutable
    {



        //IMAGE_DOS_HEADER
        private byte[] _imageDataStream;
        public _IMAGE_DOS_HEADER IMAGE_DOS_HEADER;
        public _IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS32;
        public _IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS64;
        public List<_IMAGE_DATA_DIRECTORY> IMAGE_DATA_DIRECTORYS;
        public List<_IMAGE_SECTION_HEADER> IMAGE_SECTION_HEADERS;
        public _IMAGE_EXPORT_DIRECTORY_LIST IMAGE_EXPORT_DIRECTORY_LIST;
        public List<_EXPORT_FUNCTION> EXPORT_FUNCTIONS;



        public bool IsHDR32
        {
            get
            {
                return IMAGE_NT_OPTIONAL_HDR32_MAGIC == IMAGE_NT_HEADERS32.OptionalHeader.Magic;
            }
        }

        public bool IsHDR64
        {
            get
            {
                return IMAGE_NT_OPTIONAL_HDR64_MAGIC == IMAGE_NT_HEADERS32.OptionalHeader.Magic;
            }
        }

        public _IMAGE_SECTION_HEADER GetSectionByDataDirectoriesIndex(int IMAGE_DIRECTORY_ENTRY_ID)
        {
            var result = from s in IMAGE_SECTION_HEADERS
                         where s.VirtualAddress <= IMAGE_DATA_DIRECTORYS[IMAGE_DIRECTORY_ENTRY_ID].VirtualAddress &&
                         IMAGE_DATA_DIRECTORYS[IMAGE_DIRECTORY_ENTRY_ID].VirtualAddress <= (s.VirtualAddress + s.Misc)
                         select s;
            _IMAGE_SECTION_HEADER r = result.FirstOrDefault();
            if (r.VirtualAddress != IMAGE_DATA_DIRECTORYS[IMAGE_DIRECTORY_ENTRY_ID].VirtualAddress)
            {
                uint offset = r.VirtualAddress - IMAGE_DATA_DIRECTORYS[IMAGE_DIRECTORY_ENTRY_ID].VirtualAddress;
                r.PointerToRawData = r.PointerToRawData - offset;
                r.VirtualAddress = IMAGE_DATA_DIRECTORYS[IMAGE_DIRECTORY_ENTRY_ID].VirtualAddress;
                r.SizeOfRawData = IMAGE_DATA_DIRECTORYS[IMAGE_DIRECTORY_ENTRY_ID].Size;

            }
            return r;
        }

        private void _initPEInfo()
        {
            IMAGE_DOS_HEADER = Helper.BytesToStruct<_IMAGE_DOS_HEADER>(_imageDataStream, 0);
            IMAGE_NT_HEADERS32 = Helper.BytesToStruct<_IMAGE_NT_HEADERS32>(_imageDataStream, IMAGE_DOS_HEADER.e_lfanew);
            IMAGE_NT_HEADERS64 = Helper.BytesToStruct<_IMAGE_NT_HEADERS64>(_imageDataStream, IMAGE_DOS_HEADER.e_lfanew);
            //Init IMAGE_DATA_DIRECTORY
            int nowPoint = 0;
            if (IsHDR32)
            {
                IMAGE_DATA_DIRECTORYS = new List<_IMAGE_DATA_DIRECTORY>(Convert.ToInt32(IMAGE_NT_HEADERS32.OptionalHeader.NumberOfRvaAndSizes));
                for (int i = 0; i < IMAGE_NT_HEADERS32.OptionalHeader.NumberOfRvaAndSizes; i++)
                {
                    IMAGE_DATA_DIRECTORYS.Add(Helper.BytesToStruct<_IMAGE_DATA_DIRECTORY>(_imageDataStream,
                        IMAGE_DOS_HEADER.e_lfanew + Marshal.SizeOf<_IMAGE_NT_HEADERS32>() + i * Marshal.SizeOf<_IMAGE_DATA_DIRECTORY>()));
                    nowPoint = IMAGE_DOS_HEADER.e_lfanew + Marshal.SizeOf<_IMAGE_NT_HEADERS32>() + (i + 1) * Marshal.SizeOf<_IMAGE_DATA_DIRECTORY>();
                }

                IMAGE_SECTION_HEADERS = new List<_IMAGE_SECTION_HEADER>();
                for (int i = 0; i < IMAGE_NT_HEADERS32.FileHeader.NumberOfSections; i++)
                {
                    IMAGE_SECTION_HEADERS.Add(Helper.BytesToStruct<_IMAGE_SECTION_HEADER>(_imageDataStream, nowPoint));
                    nowPoint = nowPoint += Marshal.SizeOf<_IMAGE_SECTION_HEADER>();
                }

            }
            else if (IsHDR64)
            {
                IMAGE_DATA_DIRECTORYS = new List<_IMAGE_DATA_DIRECTORY>(Convert.ToInt32(IMAGE_NT_HEADERS32.OptionalHeader.NumberOfRvaAndSizes));
                for (int i = 0; i < IMAGE_NT_HEADERS64.OptionalHeader.NumberOfRvaAndSizes; i++)
                {
                    IMAGE_DATA_DIRECTORYS.Add(Helper.BytesToStruct<_IMAGE_DATA_DIRECTORY>(_imageDataStream,
                        IMAGE_DOS_HEADER.e_lfanew + Marshal.SizeOf<_IMAGE_NT_HEADERS64>() + i * Marshal.SizeOf<_IMAGE_DATA_DIRECTORY>()));
                    nowPoint = IMAGE_DOS_HEADER.e_lfanew + Marshal.SizeOf<_IMAGE_NT_HEADERS32>() + (i + 1) * Marshal.SizeOf<_IMAGE_DATA_DIRECTORY>();
                }
                nowPoint += 16;
                IMAGE_SECTION_HEADERS = new List<_IMAGE_SECTION_HEADER>();
                for (int i = 0; i < IMAGE_NT_HEADERS64.FileHeader.NumberOfSections; i++)
                {
                    IMAGE_SECTION_HEADERS.Add(Helper.BytesToStruct<_IMAGE_SECTION_HEADER>(_imageDataStream, nowPoint));
                    nowPoint = nowPoint += Marshal.SizeOf<_IMAGE_SECTION_HEADER>();
                }
            }
            //Load IMAGE_EXPORT_DIRECTORY
            var ExportSectionInfo = GetSectionByDataDirectoriesIndex(PortableExecutableStruct.IMAGE_DIRECTORY_ENTRY_EXPORT);
            IMAGE_EXPORT_DIRECTORY_LIST.IMAGE_EXPORT_DIRECTORY = Helper.BytesToStruct<_IMAGE_EXPORT_DIRECTORY>(_imageDataStream, Convert.ToInt32(ExportSectionInfo.PointerToRawData));
            //Load Function Table
            IMAGE_EXPORT_DIRECTORY_LIST.FunctionsAddressList = new uint[IMAGE_EXPORT_DIRECTORY_LIST.IMAGE_EXPORT_DIRECTORY.NumberOfFunctions];
            IMAGE_EXPORT_DIRECTORY_LIST.NameAddressList = new uint[IMAGE_EXPORT_DIRECTORY_LIST.IMAGE_EXPORT_DIRECTORY.NumberOfNames];
            IMAGE_EXPORT_DIRECTORY_LIST.NameOrdinalsList = new ushort[IMAGE_EXPORT_DIRECTORY_LIST.IMAGE_EXPORT_DIRECTORY.NumberOfNames];


            for (int i = 0; i < IMAGE_EXPORT_DIRECTORY_LIST.IMAGE_EXPORT_DIRECTORY.NumberOfFunctions; i++)
            {
                IMAGE_EXPORT_DIRECTORY_LIST.FunctionsAddressList[i] = BitConverter.ToUInt32(_imageDataStream, i * sizeof(uint) + Convert.ToInt32(IMAGE_EXPORT_DIRECTORY_LIST.IMAGE_EXPORT_DIRECTORY.AddressOfFunctions - ExportSectionInfo.VirtualAddress + ExportSectionInfo.PointerToRawData));
            }
            for (int i = 0; i < IMAGE_EXPORT_DIRECTORY_LIST.IMAGE_EXPORT_DIRECTORY.NumberOfNames; i++)
            {
                IMAGE_EXPORT_DIRECTORY_LIST.NameAddressList[i] = BitConverter.ToUInt32(_imageDataStream, i * sizeof(uint) + Convert.ToInt32(IMAGE_EXPORT_DIRECTORY_LIST.IMAGE_EXPORT_DIRECTORY.AddressOfNames - ExportSectionInfo.VirtualAddress + ExportSectionInfo.PointerToRawData));
            }
            for (int i = 0; i < IMAGE_EXPORT_DIRECTORY_LIST.IMAGE_EXPORT_DIRECTORY.NumberOfNames; i++)
            {
                IMAGE_EXPORT_DIRECTORY_LIST.NameOrdinalsList[i] = BitConverter.ToUInt16(_imageDataStream, i * sizeof(ushort) + Convert.ToInt32(IMAGE_EXPORT_DIRECTORY_LIST.IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals - ExportSectionInfo.VirtualAddress + ExportSectionInfo.PointerToRawData));
            }

            EXPORT_FUNCTIONS = new List<_EXPORT_FUNCTION>();
            for (int i = 0; i < IMAGE_EXPORT_DIRECTORY_LIST.IMAGE_EXPORT_DIRECTORY.NumberOfNames; i++)
            {
                EXPORT_FUNCTIONS.Add(new _EXPORT_FUNCTION
                {
                    Ordinal = Convert.ToUInt32(i),
                    RVAAddressOfFunctions = IMAGE_EXPORT_DIRECTORY_LIST.FunctionsAddressList[Convert.ToUInt32(IMAGE_EXPORT_DIRECTORY_LIST.NameOrdinalsList[i])],
                    RVAAddressOfNames = IMAGE_EXPORT_DIRECTORY_LIST.NameAddressList[i],
                    RVAAddressOfNameOrdinals = IMAGE_EXPORT_DIRECTORY_LIST.NameOrdinalsList[i],
                    AddressOfFunctions = IMAGE_EXPORT_DIRECTORY_LIST.FunctionsAddressList[Convert.ToUInt32(IMAGE_EXPORT_DIRECTORY_LIST.NameOrdinalsList[i])] - ExportSectionInfo.VirtualAddress + ExportSectionInfo.PointerToRawData,
                    AddressOfNames = IMAGE_EXPORT_DIRECTORY_LIST.NameAddressList[i] - ExportSectionInfo.VirtualAddress + ExportSectionInfo.PointerToRawData,
                    AddressOfNameOrdinals = IMAGE_EXPORT_DIRECTORY_LIST.NameOrdinalsList[i],
                    FunctionName = Helper.ReadString(_imageDataStream, Convert.ToInt32(IMAGE_EXPORT_DIRECTORY_LIST.NameAddressList[i] - ExportSectionInfo.VirtualAddress + ExportSectionInfo.PointerToRawData))
                });
            }

        }


        public PortableExecutable(string modelFilename)
        {
            FileStream fs = new FileStream(modelFilename, FileMode.Open, FileAccess.Read);
            _imageDataStream = new byte[fs.Length];
            fs.Read(_imageDataStream, 0, (int)fs.Length);
            fs.Close();
            _initPEInfo();

        }



    }
}
