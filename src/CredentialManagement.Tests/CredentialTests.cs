using System;
using Xunit;

namespace CredentialManagement.Tests
{
    public class CredentialTests
    {
        [Theory]
        [InlineData("demo.com", "user", "pASs", CredentialType.DomainPassword)]
        [InlineData("demo.com", "user", "pASs", CredentialType.Generic)]
        [InlineData("demo.com", "user", "pASs", CredentialType.None)]
        [InlineData("example", "user", "", CredentialType.DomainVisiblePassword)]
        [InlineData("ex.net", "", "", CredentialType.DomainPassword)]
        [InlineData("exa.net", "", "passw", CredentialType.DomainPassword)]
        public void StorageTest(string target, string user, string pass, CredentialType type)
        {

            var c = new Credential(target, user, pass, type);
            var cc = new Credential(target, type);

            //target != ""
            var hastarget = !string.IsNullOrEmpty(target);
            
            //type has to be != none and user has to be set (password may be empty)
            var saveable = type != CredentialType.None && !string.IsNullOrEmpty(user);

            //deleting, loading, checking, saveing without target shall produce exception
            if (hastarget)
            {
                Assert.Equal(saveable, c.Save());
                Assert.Equal(saveable, c.Exists());
                Assert.Equal(saveable, cc.Load());
                if (saveable)
                {
                    Assert.Equal(type, cc.Type);
                    Assert.Equal(target, cc.Domain);
                    Assert.Equal(user, cc.UserName);
                    //domain password shall return empty string.
                    Assert.Equal(type != CredentialType.DomainPassword ? pass : "", cc.Password);
                    Assert.True((cc.LastWriteTimeUtc - c.LastWriteTimeUtc).Seconds < 1);
                    Assert.True(cc.Delete());
                }
            }
            else
            {
                Assert.Throws<InvalidOperationException>(() => cc.Save());
                Assert.Throws<InvalidOperationException>(() => cc.Load());
                Assert.Throws<InvalidOperationException>(() => cc.Exists());
                Assert.Throws<InvalidOperationException>(() => cc.Delete());
            }
        }

        [Theory]
        [InlineData(" demo")]
        [InlineData("demo ")]
        [InlineData("")]
        public void InvalidDomains(string domain)
        {
            var c = new Credential();
            Assert.Throws<ArgumentException>(() => c = new Credential(domain));
            Assert.Throws<ArgumentException>(() => c.Domain = domain);
        }

        [Fact]
        public void Renaming()
        {
            var original = "demo";
            var renamed = "omed";
            var old = new Credential(original);
            old.Save();
            old.Domain = renamed;
            old.Save();

            old.Domain = original;
            Assert.False(old.Load());

            //original has to stay deleted:
            var nw = new Credential(renamed);
            Assert.True(nw.Load());
            nw.Domain = original;
            nw.Save();

            var nw2 = new Credential(renamed);
            Assert.False(nw2.Load());

            nw.Delete();
        }

    }
}