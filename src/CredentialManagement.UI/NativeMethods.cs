﻿using System.Runtime.InteropServices;
using System.Text;

namespace CredentialManagement.UI
{
    public class NativeMethods
    {

        public const int CREDUI_MAX_USERNAME_LENGTH = 513;
        public const int CREDUI_MAX_PASSWORD_LENGTH = 256;
        public const int CREDUI_MAX_MESSAGE_LENGTH = 32767;
        public const int CREDUI_MAX_CAPTION_LENGTH = 128;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CREDUI_INFO
        {
            public int cbSize;
            public IntPtr hwndParent;
            public string pszMessageText;
            public string pszCaptionText;
            public IntPtr hbmBanner;
        }

        [Flags]
        internal enum WINXP_CREDUI_FLAGS
        {
            INCORRECT_PASSWORD = 0x00001,
            DO_NOT_PERSIST = 0x00002,
            REQUEST_ADMINISTRATOR = 0x00004,
            EXCLUDE_CERTIFICATES = 0x00008,
            REQUIRE_CERTIFICATE = 0x00010,
            SHOW_SAVE_CHECK_BOX = 0x00040,
            ALWAYS_SHOW_UI = 0x00080,
            REQUIRE_SMARTCARD = 0x00100,
            PASSWORD_ONLY_OK = 0x00200,
            VALIDATE_USERNAME = 0x00400,
            COMPLETE_USERNAME = 0x00800,
            PERSIST = 0x01000,
            SERVER_CREDENTIAL = 0x04000,
            EXPECT_CONFIRMATION = 0x20000,
            GENERIC_CREDENTIALS = 0x40000,
            USERNAME_TARGET_CREDENTIALS = 0x80000,
            KEEP_USERNAME = 0x100000,
        }

        [Flags]
        internal enum WINVISTA_CREDUI_FLAGS
        {
            /// <summary>
            /// The caller is requesting that the credential provider return the user name and password in plain text.
            /// This value cannot be combined with SECURE_PROMPT.
            /// </summary>
            CREDUIWIN_GENERIC = 0x1,
            /// <summary>
            /// The Save check box is displayed in the dialog box.
            /// </summary>
            CREDUIWIN_CHECKBOX = 0x2,
            /// <summary>
            /// Only credential providers that support the authentication package specified by the authPackage parameter should be enumerated.
            /// This value cannot be combined with CREDUIWIN_IN_CRED_ONLY.
            /// </summary>
            CREDUIWIN_AUTHPACKAGE_ONLY = 0x10,
            /// <summary>
            /// Only the credentials specified by the InAuthBuffer parameter for the authentication package specified by the authPackage parameter should be enumerated.
            /// If this flag is set, and the InAuthBuffer parameter is NULL, the function fails.
            /// This value cannot be combined with CREDUIWIN_AUTHPACKAGE_ONLY.
            /// </summary>
            CREDUIWIN_IN_CRED_ONLY = 0x20,
            /// <summary>
            /// Credential providers should enumerate only administrators. This value is intended for User Account Control (UAC) purposes only. We recommend that external callers not set this flag.
            /// </summary>
            CREDUIWIN_ENUMERATE_ADMINS = 0x100,
            /// <summary>
            /// Only the incoming credentials for the authentication package specified by the authPackage parameter should be enumerated.
            /// </summary>
            CREDUIWIN_ENUMERATE_CURRENT_USER = 0x200,
            /// <summary>
            /// The credential dialog box should be displayed on the secure desktop. This value cannot be combined with CREDUIWIN_GENERIC.
            /// Windows Vista: This value is not supported until Windows Vista with SP1.
            /// </summary>
            CREDUIWIN_SECURE_PROMPT = 0x1000,
            /// <summary>
            /// The credential provider should align the credential BLOB pointed to by the refOutAuthBuffer parameter to a 32-bit boundary, even if the provider is running on a 64-bit system.
            /// </summary>
            CREDUIWIN_PACK_32_WOW = 0x10000000,
        }

        internal enum CredUIReturnCodes
        {
            NO_ERROR = 0,
            ERROR_CANCELLED = 1223,
            ERROR_NO_SUCH_LOGON_SESSION = 1312,
            ERROR_NOT_FOUND = 1168,
            ERROR_INVALID_ACCOUNT_NAME = 1315,
            ERROR_INSUFFICIENT_BUFFER = 122,
            ERROR_BAD_ARGUMENTS = 160,
            ERROR_INVALID_PARAMETER = 87,
            ERROR_INVALID_FLAGS = 1004,
        }


        [DllImport("credui.dll", CharSet = CharSet.Unicode)]
        internal unsafe static extern CredUIReturnCodes CredUIPromptForCredentials(ref CREDUI_INFO creditUR, string targetName, IntPtr reserved1, int iError, StringBuilder userName, int maxUserName, StringBuilder password, int maxPassword, [MarshalAs(UnmanagedType.Bool)] ref bool pfSave, int flags);

        [DllImport("credui.dll", CharSet = CharSet.Unicode)]
        internal unsafe static extern CredUIReturnCodes CredUIPromptForWindowsCredentials(ref CREDUI_INFO notUsedHere, int authError, ref uint authPackage, IntPtr InAuthBuffer, uint InAuthBufferSize, out IntPtr refOutAuthBuffer, out uint refOutAuthBufferSize, ref bool fSave, int flags);

        [DllImport("credui.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern Boolean CredPackAuthenticationBuffer(int dwFlags, StringBuilder pszUserName, StringBuilder pszPassword, IntPtr pPackedCredentials, ref int pcbPackedCredentials);

        [DllImport("credui.dll", CharSet = CharSet.Unicode)]
        internal static extern bool CredUnPackAuthenticationBuffer(int dwFlags, IntPtr pAuthBuffer, uint cbAuthBuffer, StringBuilder pszUserName, ref int pcchMaxUserName, StringBuilder pszDomainName, ref int pcchMaxDomainame, StringBuilder pszPassword, ref int pcchMaxPassword);

    }
}
