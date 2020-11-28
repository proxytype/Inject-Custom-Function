using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace launcher
{

    class Program
    {
        static IntPtr setLibrary(string dll, string function)
        {
            IntPtr h = NativeApi.GetModuleHandle(dll);
            return NativeApi.GetProcAddress(h, function);
        }

        static IntPtr injectLibray(string dll, int pid)
        {
            //get requested process pointer
            IntPtr processPtr = NativeApi.OpenProcess(NativeApi.PROCESS_CREATE_THREAD | NativeApi.PROCESS_QUERY_INFORMATION | NativeApi.PROCESS_VM_OPERATION | NativeApi.PROCESS_VM_WRITE | NativeApi.PROCESS_VM_READ, false, pid);

            //getting the pointer to LoadLibraryA in kernel32.dll
            IntPtr loadLibraryPtr = setLibrary("kernel32.dll", "LoadLibraryA");

            //allocate payload path
            IntPtr allocMemAddress = NativeApi.VirtualAllocEx(processPtr, IntPtr.Zero, (uint)((dll.Length + 1) * Marshal.SizeOf(typeof(char))), (uint)NativeApi.AllocationType.Commit | (uint)NativeApi.AllocationType.Reserve, NativeApi.PAGE_READWRITE);

            //write to process memory
            UIntPtr bytesWritten;
            NativeApi.WriteProcessMemory(processPtr, allocMemAddress, Encoding.Default.GetBytes(dll), (uint)((dll.Length + 1) * Marshal.SizeOf(typeof(char))), out bytesWritten);

            //create thread in process, execute loadlibrary and call the allocated path
            IntPtr thread = NativeApi.CreateRemoteThread(processPtr, IntPtr.Zero, 0, loadLibraryPtr, allocMemAddress, 0, IntPtr.Zero);
            NativeApi.WaitForSingleObject(thread, NativeApi.INFINITE);

            NativeApi.FreeLibrary(loadLibraryPtr);
            NativeApi.WaitForSingleObject(loadLibraryPtr, NativeApi.INFINITE);

            NativeApi.VirtualFreeEx(processPtr, allocMemAddress, 0, NativeApi.AllocationType.Release);

            return processPtr;
        }


        static void Main(string[] args)
        {
            if (args.Length < 4) {

                Console.WriteLine("Execute Payload Function With Args:");
                Console.WriteLine("<Payload Path> <Process Name> <Payload Function> <PayloadArgs>");
                Console.WriteLine("Example:");
                Console.WriteLine("C:\\payload.dll notepad injectString \"my string\"");
                Console.WriteLine("By Proxytype - https://github.com/proxytype");
                return;

            }

            string payload = args[0];
            string injectTo = args[1];
            string payloadFunc = args[2];
            string payloadFuncArg = args[3];

            Process[] ps = Process.GetProcessesByName(injectTo);

            if (ps.Length != 0)
            {
                //remote process injection
                IntPtr remoteProcess = injectLibray(payload, ps[0].Id);

                //local process injection
                IntPtr localProcess = injectLibray(payload, Process.GetCurrentProcess().Id);

                //get injection function address from local process
                IntPtr injectFunction = NativeApi.GetProcAddress(NativeApi.GetModuleHandle(payload), payloadFunc);

                NativeApi.CloseHandle(localProcess);

                byte[] funcArgs = Encoding.Unicode.GetBytes(payloadFuncArg);

                IntPtr allocMemAddress = NativeApi.VirtualAllocEx(remoteProcess, IntPtr.Zero, (uint)funcArgs.Length + 1, (uint)NativeApi.AllocationType.Commit | (uint)NativeApi.AllocationType.Reserve, NativeApi.PAGE_READWRITE);

                UIntPtr bytesWritten;
                NativeApi.WriteProcessMemory(remoteProcess, allocMemAddress, funcArgs, (uint)funcArgs.Length + 1, out bytesWritten);

                IntPtr thread = NativeApi.CreateRemoteThread(remoteProcess, IntPtr.Zero, 0, injectFunction, allocMemAddress, 0, IntPtr.Zero);
                NativeApi.WaitForSingleObject(thread, NativeApi.INFINITE);

                NativeApi.VirtualFreeEx(remoteProcess, allocMemAddress, 0, NativeApi.AllocationType.Release);
                NativeApi.CloseHandle(remoteProcess);
            }
        }
    }
}
