using System;
using System.Runtime.InteropServices;
using AnalysisLibrary;
using System.IO;
using System.Text;

namespace TestConsole
{
    class Program
    {
        static void Main(string[] args)
        {
            while (true)
            {
                PortableExecutable pe = new PortableExecutable(System.Console.ReadLine());
                foreach (var i in pe.IMAGE_SECTION_HEADERS)
                {
                    System.Console.WriteLine("{0}\t0x{1:x}", Encoding.UTF8.GetString(i.Name), i.PointerToRawData);
                }
                System.Console.WriteLine("Name\tRawAddress");
                foreach (var i in pe.EXPORT_FUNCTIONS)
                {
                    System.Console.WriteLine("{0}\t0x{1:x}", i.FunctionName, i.AddressOfFunctions);
                }
            }

        }
    }
}
