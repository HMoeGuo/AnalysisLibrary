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
            PortableExecutable pe = new PortableExecutable(@"C:\WINDOWS\system32\kernel32.dll");
            foreach (var i in pe.IMAGE_SECTION_HEADERS)
            {
                System.Console.WriteLine("{0}\t0x{1:x}", Encoding.UTF8.GetString(i.Name), i.PointerToRawData);
            }
            System.Console.WriteLine("Name\tRawAddress");
            foreach(var i in pe.EXPORT_FUNCTIONS)
            {
                System.Console.WriteLine("{0}\t0x{1:x}",i.FunctionName, i.AddressOfFunctions);
            }
            
            System.Console.Read();
        }
    }
}
