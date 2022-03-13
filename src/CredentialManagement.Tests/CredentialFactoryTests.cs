using System;
using System.Linq;
using Xunit;

namespace CredentialManagement.Tests
{
    public class CredentialFactoryTests
    {

        [Theory]
        [MemberData(nameof(DataSet))]
        public void FactoryTest(string addr, Credential[] creds)
        {

            foreach (var cred in creds)
                Assert.True(cred.Save());

            //var ok = !addr.Contains('*') || (addr.StartsWith('*') || addr.EndsWith('*'));
            //Assert.Equal(ok, cs.Load());

            var i = 0;
            foreach (var loaded in CredentialFactory.Load(addr))
            {
                i++;
                var original = creds.First(cc => cc.Domain.Equals(loaded.Domain));
                Assert.Equal(original.Domain, loaded.Domain);
                Assert.Equal(original.UserName, loaded.UserName);
                Assert.Equal(original.Password, loaded.Password);

                //do a rename and check if original name is loaded
                original.Domain += ".test";
                original.Save();
                Assert.False(loaded.Load());
            };
            Assert.Equal(addr.Contains('*') ? creds.Length : 1, i);

            foreach (var cred in creds)
                cred.Delete();
        }

        public static TheoryData<string, Credential[]> DataSet => new()
        {
            { "demo123", new Credential[] { new("demo123", "a", "b"), new("demo124", "a", "cc") } },
            { "demo1/*", new Credential[] { new("demo1/a", "a", "b"), new("demo1/b", "b", "") } },
            { "*@demo2", new Credential[] { new("a@demo2", "a", ""), new("b@demo2", "b", "cc") } },
        };

        [Theory]
        [InlineData("a*demo3")]
        [InlineData(" demo")]
        [InlineData("demo ")]
        [InlineData("")]
        public void InvalidNames(string adr)
        {
            _ = Assert.Throws<ArgumentException>(() => CredentialFactory.Load(adr).Any());
        }

    }
}
