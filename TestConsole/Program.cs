using System;
using System.Runtime.InteropServices;
using AnalysisLibrary;
using System.IO;

namespace TestConsole
{
    class Program
    {
        static void Main(string[] args)
        {
            PortableExecutable pe = new PortableExecutable(@"d:\Users\moegu\Desktop\test.dll");
            System.Console.Read();
        }
    }
}
