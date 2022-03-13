using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace CredentialManagement
{
    public class Credential : NetworkCredential
    {
        public static readonly char All = '*';
        //private bool _disposed;
        //private string _username = string.Empty;
        //private string _target = string.Empty;
        private string? _oldTarget = null;

        //private SecureString? _password;

        //public string Username { get => _username; set => _username = CheckSpaces(ref value); }
        /*
        public string? Password
        {
            get
            {
                var sp = SecurePassword;
                return sp == null ? null : SecureStringHelper.CreateString(sp);
            }
            set => SecurePassword = string.IsNullOrEmpty(value) ? null : SecureStringHelper.CreateSecureString(value);
        }

        public SecureString? SecurePassword
        {
            get => _password?.Copy();
            set
            {
                CheckNotDisposed();
                if (null != _password)
                {
                    _password.Clear();
                    _password.Dispose();
                }
                _password = value?.Copy();
            }
        }
        //*/

        public new string Domain {
            get => base.Domain ?? string.Empty;
            set => base.Domain = CheckDomain(value);
        }

        public string Description { get; set; } = string.Empty;

        public DateTime LastWriteTimeUtc { get; private set; } = DateTime.MinValue;

        public CredentialType Type { get; set; }

        public PersistanceType PersistanceType { get; set; } = PersistanceType.Session;

        public Credential() : this(CredentialType.Generic) { }
        public Credential(CredentialType type) : this(null, type) { } //=> Type = type;

        //public Credential(string username) : this(username, string.Empty) { }
        public Credential(string? domain, CredentialType type = CredentialType.Generic) : this(domain, null, null, type) { }// => Domain = target;

        //public Credential(string username, string password) : this(username, password, string.Empty) { }

        public Credential(string? domain, string? username, string? password, CredentialType type = CredentialType.Generic) : base(username, password, CheckDomain(domain)) => Type = type;
        //{
        //    Username = username;
        //    Password = password;
        //}

        public bool Save()
        {
            CheckHasDomain();

            var pw = Password;
            byte[] passwordBytes = pw != null ? Encoding.Unicode.GetBytes(pw) : Array.Empty<byte>();
            if (passwordBytes.Length > 512)
                throw new ArgumentOutOfRangeException("The password has exceeded 512 bytes.");

            NativeMethods.CREDENTIAL credential = new()
            {
                TargetName = Domain,
                UserName = UserName,
                CredentialBlobSize = passwordBytes.Length,
                Comment = Description,
                Type = (int)Type,
                Persist = (int)PersistanceType
            };
            try
            {
                credential.CredentialBlob = Marshal.StringToCoTaskMemUni(Password);
                bool result = NativeMethods.CredWrite(ref credential, 0);

                if (result)
                {
                    LastWriteTimeUtc = DateTime.UtcNow;
                    if (_oldTarget != null && !_oldTarget.Equals(Domain))
                    {
                        var c = new Credential(_oldTarget, Type);
                        result = c.Delete();
                    }
                    _oldTarget = Domain;
                }

                return result;
            }
            finally
            {
                NativeMethods.ZeroMemory(credential.CredentialBlob, credential.CredentialBlobSize);
                Marshal.FreeCoTaskMem(credential.CredentialBlob);
            }
        }

        public bool Delete()
        {
            CheckHasDomain();
            _oldTarget = null;
            return NativeMethods.CredDelete(Domain, Type, 0);
        }

        public bool Load()
        {
            CheckHasDomain();

            using var credentialHandle = NativeMethods.CredentialHandle.Create(Domain, Type);
            return credentialHandle != null && Load(credentialHandle.Value);
        }

        public bool Exists() => new Credential(Domain, Type).Load();

        internal bool Load(NativeMethods.CREDENTIAL credential)
        {
            UserName = credential.UserName ?? string.Empty;
            if (credential.CredentialBlobSize > 0)
                Password = Marshal.PtrToStringUni(credential.CredentialBlob, credential.CredentialBlobSize / 2);

            _oldTarget = Domain;
            Domain = credential.TargetName ?? string.Empty;
            Type = (CredentialType)credential.Type;
            PersistanceType = (PersistanceType)credential.Persist;
            Description = credential.Comment ?? string.Empty;
            LastWriteTimeUtc = DateTime.FromFileTimeUtc(credential.LastWritten);
            return true;
        }

        private void CheckHasDomain()
        {
            if (string.IsNullOrEmpty(Domain))
                throw new ArgumentException("Target must be specified.");
        }

        internal protected static string? CheckDomain(string ? inp) => inp != null && (string.IsNullOrWhiteSpace(inp) || inp.Contains(All)) ? throw new ArgumentException("Value must not be empty, whitespace or contain *.") : CheckSpaces(inp);
        internal protected static string? CheckSpaces(string? inp) => inp != null && (string.IsNullOrWhiteSpace(inp) || inp.StartsWith(' ') || inp.EndsWith(' ')) ? throw new ArgumentException("Argument must not start or end with a space.") : inp;
    }
}
