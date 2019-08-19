using System;
using System.IO;
using System.Runtime.InteropServices;
using static AnalysisLibrary.PortableExecutableStruct;
using System.Collections;
using System.Collections.Generic;

namespace AnalysisLibrary
{
    public class PortableExecutable
    {



        //IMAGE_DOS_HEADER
        private byte[] _imageDataStream;
        private _IMAGE_DOS_HEADER IMAGE_DOS_HEADER;
        private _IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS32;
        private _IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS64;
        private _IMAGE_DATA_DIRECTORY[] IMAGE_DATA_DIRECTORYS;
        private _IMAGE_SECTION_HEADER[] IMAGE_SECTION_HEADERS;

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

        private void _initPEInfo()
        {
            IMAGE_DOS_HEADER = Helper.BytesToStruct<_IMAGE_DOS_HEADER>(_imageDataStream, 0);
            IMAGE_NT_HEADERS32 = Helper.BytesToStruct<_IMAGE_NT_HEADERS32>(_imageDataStream, IMAGE_DOS_HEADER.e_lfanew);
            IMAGE_NT_HEADERS64 = Helper.BytesToStruct<_IMAGE_NT_HEADERS64>(_imageDataStream, IMAGE_DOS_HEADER.e_lfanew);
            //Init IMAGE_DATA_DIRECTORY
            int nowPoint = 0;
            if (IsHDR32)
            {
                IMAGE_DATA_DIRECTORYS = new _IMAGE_DATA_DIRECTORY[IMAGE_NT_HEADERS32.OptionalHeader.NumberOfRvaAndSizes];
                for (int i = 0; i < IMAGE_NT_HEADERS32.OptionalHeader.NumberOfRvaAndSizes; i++)
                {
                    IMAGE_DATA_DIRECTORYS[i] = Helper.BytesToStruct<_IMAGE_DATA_DIRECTORY>(_imageDataStream,
                        IMAGE_DOS_HEADER.e_lfanew + Marshal.SizeOf<_IMAGE_NT_HEADERS32>() + i * Marshal.SizeOf<_IMAGE_DATA_DIRECTORY>());
                    nowPoint = IMAGE_DOS_HEADER.e_lfanew + Marshal.SizeOf<_IMAGE_NT_HEADERS32>() + (i + 1) * Marshal.SizeOf<_IMAGE_DATA_DIRECTORY>();
                }
                IMAGE_SECTION_HEADERS = new _IMAGE_SECTION_HEADER[IMAGE_NT_HEADERS32.FileHeader.NumberOfSections];
                for (int i = 0; i < IMAGE_NT_HEADERS32.FileHeader.NumberOfSections; i++)
                {
                    IMAGE_SECTION_HEADERS[i] = Helper.BytesToStruct<_IMAGE_SECTION_HEADER>(_imageDataStream, nowPoint);
                    nowPoint = nowPoint += Marshal.SizeOf<_IMAGE_SECTION_HEADER>();
                }

            }
            else if (IsHDR64)
            {

                IMAGE_DATA_DIRECTORYS = new _IMAGE_DATA_DIRECTORY[IMAGE_NT_HEADERS64.OptionalHeader.NumberOfRvaAndSizes];
                for (int i = 0; i < IMAGE_NT_HEADERS64.OptionalHeader.NumberOfRvaAndSizes; i++)
                {
                    IMAGE_DATA_DIRECTORYS[i] = Helper.BytesToStruct<_IMAGE_DATA_DIRECTORY>(_imageDataStream,
                        IMAGE_DOS_HEADER.e_lfanew + Marshal.SizeOf<_IMAGE_NT_HEADERS64>() + i * Marshal.SizeOf<_IMAGE_DATA_DIRECTORY>());
                    nowPoint = IMAGE_DOS_HEADER.e_lfanew + Marshal.SizeOf<_IMAGE_NT_HEADERS32>() + (i + 1) * Marshal.SizeOf<_IMAGE_DATA_DIRECTORY>();
                }
                nowPoint += 16;
                IMAGE_SECTION_HEADERS = new _IMAGE_SECTION_HEADER[IMAGE_NT_HEADERS64.FileHeader.NumberOfSections];
                for (int i = 0; i < IMAGE_NT_HEADERS64.FileHeader.NumberOfSections; i++)
                {
                    IMAGE_SECTION_HEADERS[i] = Helper.BytesToStruct<_IMAGE_SECTION_HEADER>(_imageDataStream, nowPoint);
                    nowPoint = nowPoint += Marshal.SizeOf<_IMAGE_SECTION_HEADER>();
                }
            }






            System.Console.Read();

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
