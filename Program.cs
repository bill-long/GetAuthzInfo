using System;
using System.Security.Principal;
using Vanara.InteropServices;
using Vanara.PInvoke;
using static Vanara.PInvoke.AdvApi32;

namespace GetAuthzInfo
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Please specify a SID.");
            }

            var sidString = args[0];

            var success = Authz.AuthzInitializeResourceManager(Authz.AuthzResourceManagerFlags.AUTHZ_RM_FLAG_NO_AUDIT, null, null, null, "", out var rm);
            if (!success)
            {
                ReportLastError("AuthzInitializeResourceManager");
                return;
            }

            var sid = new SecurityIdentifier(sidString);
            var sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);
            var psid = new SafePSID(sidBytes);
            success = Authz.AuthzInitializeContextFromSid(Authz.AuthzContextFlags.DEFAULT, psid, rm, IntPtr.Zero, new LUID(), IntPtr.Zero, out var context);
            if (!success)
            {
                ReportLastError("AuthzInitializeContextFromSid");
                Authz.AuthzFreeResourceManager(rm);
                return;
            }

            success = Authz.AuthzGetInformationFromContext(context, Authz.AUTHZ_CONTEXT_INFORMATION_CLASS.AuthzContextInfoGroupsSids, 0, out var sizeRequired, IntPtr.Zero);
            if (!success && Win32Error.GetLastError() != Win32Error.ERROR_INSUFFICIENT_BUFFER)
            {
                ReportLastError("AuthzGetInformationFromContext part 1");
                Authz.AuthzFreeContext(context);
                Authz.AuthzFreeResourceManager(rm);
                return;
            }

            if (sizeRequired == 0)
            {
                Console.WriteLine("No context information available?");
                Authz.AuthzFreeContext(context);
                Authz.AuthzFreeResourceManager(rm);
                return;
            }

            uint size = sizeRequired;
            var buffer = new SafeHGlobalHandle(size);
            success = Authz.AuthzGetInformationFromContext(context, Authz.AUTHZ_CONTEXT_INFORMATION_CLASS.AuthzContextInfoGroupsSids, size, out sizeRequired, buffer);
            if (!success)
            {
                ReportLastError("AuthzGetInformationFromContext part 2");
                Authz.AuthzFreeContext(context);
                Authz.AuthzFreeResourceManager(rm);
                return;
            }

            var tokenGroups = buffer.ToArray<TOKEN_GROUPS>(1);
            for (var i = 0; i < tokenGroups[0].GroupCount; i++)
            {
                var tokenGroup = tokenGroups[0].Groups[i];
                var thisSid = new SecurityIdentifier(tokenGroup.Sid.GetBinaryForm(), 0);
                string accountName = null;
                try
                {
                    accountName = thisSid.Translate(typeof(NTAccount)).Value;
                }
                catch
                { }
                Console.WriteLine($"{thisSid} {accountName ?? tokenGroup.ToString()}");
            }
        }

        static void ReportLastError(string failedFunction)
        {
            var error = Win32Error.GetLastError();
            Console.WriteLine($"{failedFunction} failed with error {error}");
        }
    }
}
