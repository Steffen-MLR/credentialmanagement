using System.Runtime.InteropServices;

namespace CredentialManagement
{
    public static class CredentialFactory
    {
        public static IEnumerable<Credential> Load(string target) => Load<Credential>(target);

        public static IEnumerable<T> Load<T>(string target) where T : Credential, new()
        {
            Credential.CheckSpaces(target);
            if (target.Contains(Credential.All) && target[0] != Credential.All && target[^1] != Credential.All)
                throw new ArgumentException($"Parameter must not contain {Credential.All}", nameof(target));

            using var result = NativeMethods.CredentialHandle.Enumerate(target, out var count);
            //if (result == null)
            //    throw new Win32Exception(Marshal.GetLastWin32Error());

            if (result != null)
            {
                for (int i = 0; i < count; i++)
                {
                    //read in the pointer
                    using var handle = new NativeMethods.CredentialHandle(Marshal.ReadIntPtr(result.Handle, IntPtr.Size * i));
                    if (!handle.IsInvalid)
                    {
                        //create object
                        var e = new T();
                        e.Load(handle.Value);
                        yield return e;
                        //Add(e);
                    }
                }
            }

            //return this as List<T> ?? throw new NullReferenceException();
        }
    }
}