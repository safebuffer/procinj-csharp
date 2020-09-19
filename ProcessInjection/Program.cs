using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ProcessInjection
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] d = { 0x90, 0x90};
            IntPtr s = utils.GetCurrentProcHandle();
            IntPtr w = utils.AllocInProc(d, s);
            exec.FibersMethod(w);


            Console.ReadLine();
        }
    }
}
