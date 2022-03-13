using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SoftwareApproach.TestingExtensions;

namespace CredentialManagement.Test
{
    [TestClass]
    public class CredentialTests
    {
        [TestMethod]
        public void Credential_Create_ShouldNotThrowNull()
        {
            new Credential().ShouldNotBeNull();
        }

        [TestMethod]
        public void Credential_Create_With_Username_ShouldNotThrowNull()
        {
            new Credential("username").ShouldNotBeNull();
        }

        [TestMethod]
        public void Credential_Create_With_Username_And_Password_ShouldNotThrowNull()
        {
            new Credential("username", "password").ShouldNotBeNull();
        }
        [TestMethod]
        public void Credential_Create_With_Username_Password_Target_ShouldNotThrowNull()
        {
            new Credential("username", "password","target").ShouldNotBeNull();
        }

        [TestMethod]
        public void Credential_ShouldBe_IDisposable()
        {
            Assert.IsTrue(new Credential() is IDisposable, "Credential should implement IDisposable Interface.");
        }
        
        [TestMethod]
        public void Credential_Dispose_ShouldNotThrowException()
        {
            new Credential().Dispose();
        }

        [TestMethod]
        public void Credential_Save()
        {
            Credential saved = new ("username", "password", "target", CredentialType.Generic);
            saved.PersistanceType = PersistanceType.LocalComputer;
            saved.Save().ShouldBeTrue();
        }
        
        [TestMethod]
        public void Credential_Delete()
        {
            new Credential("username", "password", "target").Save();
            new Credential("username", "password","target").Delete().ShouldBeTrue();
        }

        [TestMethod]
        public void Credential_Delete_NullTerminator()
        {
            Credential credential = new (null, null, "\0", CredentialType.None);
            credential.Description = null;
            credential.Delete().ShouldBeFalse();
        }
       
        [TestMethod]
        public void Credential_Load()
        {
            Credential setup = new ("username", "password", "target", CredentialType.Generic);
            setup.Save();

            Credential credential = new () {Target = "target", Type = CredentialType.Generic };
            credential.Load().ShouldBeTrue();

            credential.Username.ShouldNotBeEmpty();
            credential.Password.ShouldNotBeNull();
            credential.Username.ShouldEqual("username");
            credential.Password.ShouldEqual("password");
            credential.Target.ShouldEqual("target");
        }

        [TestMethod]
        public void Credential_Exists_Target_ShouldNotBeNull()
        {
            new Credential { Username = "username", Password = "password", Target = "target" }.Save();
            
            Credential existingCred = new () {Target = "target"};
            existingCred.Exists().ShouldBeTrue();
            
            existingCred.Delete();
        }
    }
}
