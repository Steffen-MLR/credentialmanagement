using System.Runtime.InteropServices;
using System.Text;
//using static CredentialManagement.NativeMethods;

namespace CredentialManagement
{
    internal static class NativeMethods
    {

        [StructLayout(LayoutKind.Sequential)]
        public struct CREDENTIAL
        {
            public int Flags;
            public int Type;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string? TargetName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string Comment;
            public long LastWritten;
            public int CredentialBlobSize;
            public IntPtr CredentialBlob;
            public int Persist;
            public int AttributeCount;
            public IntPtr Attributes;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string TargetAlias;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string UserName;
        }

        public enum CREDErrorCodes
        {
            NO_ERROR = 0,
            ERROR_NOT_FOUND = 1168,
            ERROR_NO_SUCH_LOGON_SESSION = 1312,
            ERROR_INVALID_PARAMETER = 87,
            ERROR_INVALID_FLAGS = 1004,
            ERROR_BAD_USERNAME = 2202,
            SCARD_E_NO_READERS_AVAILABLE = (int)(0x8010002E - 0x100000000),
            SCARD_E_NO_SMARTCARD = (int)(0x8010000C - 0x100000000),
            SCARD_W_REMOVED_CARD = (int)(0x80100069 - 0x100000000),
            SCARD_W_WRONG_CHV = (int)(0x8010006B - 0x100000000)
        }

        [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
        //internal unsafe static extern bool CredRead(string target, CredentialType type, int reservedFlag, out IntPtr CredentialPtr);
        public unsafe static extern bool CredRead(string target, CredentialType type, int reservedFlag, out CredentialHandle handle);

        [DllImport("advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CredWrite(ref CREDENTIAL userCredential, uint flags);

        [DllImport("advapi32.dll", SetLastError = true)]
        public unsafe static extern void CredFree(IntPtr cred);

        [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode)]
        public static extern bool CredDelete(string target, CredentialType type, int flags);

        [DllImport("advapi32.dll", EntryPoint = "CredEnumerateW", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CredEnumerate(string filter, int flag, out uint count, out CredentialHandle handle);
        //internal unsafe static extern bool CredEnumerateW(string filter, int flag, out uint count, out IntPtr pCredentials);

        //[DllImport("credui.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        //internal static extern Boolean CredPackAuthenticationBuffer(int dwFlags, StringBuilder pszUserName, StringBuilder pszPassword, IntPtr pPackedCredentials, ref int pcbPackedCredentials);

        //[DllImport("credui.dll", CharSet = CharSet.Unicode)]
        //internal static extern bool CredUnPackAuthenticationBuffer(int dwFlags, IntPtr pAuthBuffer, uint cbAuthBuffer, StringBuilder pszUserName, ref int pcchMaxUserName, StringBuilder pszDomainName, ref int pcchMaxDomainame, StringBuilder pszPassword, ref int pcchMaxPassword);

        [DllImport("kernel32.dll", EntryPoint = "RtlZeroMemory")]
        public unsafe static extern bool ZeroMemory(IntPtr destination, int length);
        //internal unsafe static extern bool ZeroMemory(byte* destination, int length);

        public sealed class CredentialHandle : SensitiveStructHandle<CREDENTIAL>
        {
            public CredentialHandle() : this(null) { }
            public CredentialHandle(IntPtr? h = null) : base(h) { }

            protected override bool FreeUnmanagedHandle()
            {
                CredFree(handle);
                return true;
            }

            public static CredentialHandle? Create(string Target, CredentialType Type)
            {
                var ok = CredRead(Target, Type, 0, out var credentialHandle);
                return ok ? credentialHandle : null;
            }

            public static CredentialHandle? Enumerate(string Target, out uint count)
            {
                var ok = CredEnumerate(Target, 0, out count, out var result);
                return ok ? result : null;
            }
        }
    }

}
