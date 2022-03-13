using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace CredentialManagement
{
    public abstract class SensitiveStructHandle<T> : SensitiveValueHandle<T>
    {

        /// <summary>
        /// Helper class defining getter for values, which are constructed from structs
        /// </summary>
        /// <param name="ownshandle"></param>
        protected SensitiveStructHandle(IntPtr? h = null) : base(h, Marshal.SizeOf<T>()) { }

        /// <summary>
        /// Masrhals pointer to C structure into <typeparamref name="T"/> object
        /// </summary>
        /// <exception cref="InvalidOperationException"></exception> when handle is invalid
        /// <exception cref="NullReferenceException"></exception> when pointer to structure does not return proper type
        public override T Value
        {
            get
            {
                if (IsInvalid)
                    throw new InvalidOperationException("Invalid CriticalHandle.");

                // Get the Credential from the mem location
                return Marshal.PtrToStructure(handle, typeof(T)) is T c ? c : throw new NullReferenceException("Critical handle returned null.");
            }
        }
    }

    public abstract class SensitiveValueHandle<T> : CriticalHandleZeroOrMinusOneIsInvalid
    {
        private readonly bool _ownshandle;
        private readonly int _size;

        /// <summary>
        /// overrides <see cref="CriticalHandleMinusOneIsInvalid.GetHandle()"/> method for better visibility
        /// overrides <see cref="CriticalHandleMinusOneIsInvalid.SetHandle(IntPtr)"/> method for better visibility
        /// </summary>
        public IntPtr Handle { get => handle; set => handle = value; }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="h">existing handle; handle will be released when disposing this object only if this handle is <see langword="null"/></param>
        /// <param name="size">size of memory to be securely wiped if > 0</param>
        protected SensitiveValueHandle(IntPtr? h = null, int size = 0) : base()
        {
            _ownshandle = h == null;
            _size = size;
            if (h != null)
                handle = (IntPtr)h;
        }

        /// <summary>
        /// When this instance owns handle, it calls <see cref="FreeUnmanagedHandle"/>, else sets handle as invalid.
        /// When this instance owns handle and contains sensitive data it also zeroes memory of pointer in the size of <typeparamref name="T"/>
        /// </summary>
        /// <returns></returns>
        override protected bool ReleaseHandle()
        {
            // If the handle was set, free it. Return success.
            var ok = true;
            if (_ownshandle)
            {
                // ZERO out the memory allocated to the handle, before free'ing it
                // so there are no traces of the sensitive data left in memory.
                if (_size > 0)
                    ok &= ZeroMemory(_size);
                //free handle
                ok &= FreeUnmanagedHandle();
            }
            // Mark the handle as invalid for future users.
            else
                SetHandleAsInvalid();
            return ok;
        }

        /// <summary>
        /// Executes memory wiping for the handle
        /// </summary>
        /// <param name="length"></param>
        /// <returns></returns>
        protected bool ZeroMemory(int length) => NativeMethods.ZeroMemory(handle, length);

        /// <summary>
        /// Implementation should provide a way to free the handle
        /// </summary>
        /// <returns><see langword="true"/> when operation is successful</returns>
        protected abstract bool FreeUnmanagedHandle();

        public abstract T Value { get; }

    }

}
