namespace Mjcheetham.SecureStorage
{
    /// <summary>
    /// Represents a simple credential; user name and password pair.
    /// </summary>
    public interface ICredential
    {
        string UserName { get; }
        string Password { get; }
    }

    public class Credential : ICredential
    {
        public Credential(string userName, string password)
        {
            UserName = userName;
            Password = password;
        }

        public string UserName { get; }

        public string Password { get; }
    }
}
