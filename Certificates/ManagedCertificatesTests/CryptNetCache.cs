using System.Diagnostics;

namespace CertificateToolbox
{
    public class CryptNetCache
    {
        public static void Clear()
        {
            Execute("certutil", "-URLcache * delete");
            Execute("certutil", "-setreg chain\\ChainCacheResyncFiletime @now");
        }

        private static void Execute(string program, string arguments)
        {
            Process process = new Process();
            process.StartInfo.FileName = program;
            process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            process.StartInfo.Arguments = arguments;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            process.Start();
            process.WaitForExit();
        }
    }
}
