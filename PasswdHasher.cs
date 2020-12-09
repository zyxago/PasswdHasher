using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Web;

namespace WebAppTesting.Classes
{
    public static class PasswdHasher
    {
        private const int HASH_SIZE = 32;
        private const int SALT_SIZE = 32;
        private const int ITERATION = 20000;

        /*
        private static byte[] saltUsed;

        public static byte[] GetSaltUsed()
        {
            return saltUsed;
        }
        */

        /// <summary>
        /// Hashes password with custom salt
        /// </summary>
        /// <param name="passwd">Password to hash</param>
        /// <param name="salt">Salt used in hashing</param>
        /// <returns>Hashed version of password</returns>
        public static byte[] HashPasswd(string passwd, out byte[] salt)
        {
            Rfc2898DeriveBytes pbkdf2 = null;
            //Generate salt
            salt = new byte[SALT_SIZE];
            RNGCryptoServiceProvider provider = new RNGCryptoServiceProvider();
            provider.GetBytes(salt);

            //Generate Hash
            pbkdf2 = new Rfc2898DeriveBytes(passwd, salt, ITERATION);

            //saltUsed = salt;

            return pbkdf2.GetBytes(HASH_SIZE);
        }

        /// <summary>
        /// Compares password to hash and salt
        /// </summary>
        /// <param name="hash"></param>
        /// <param name="passwd"></param>
        /// <param name="salt"></param>
        /// <returns>Returns true if password matches hash and salt</returns>
        public static bool ComparePasswdToHash(string hash, string passwd, byte[] salt)
        {
            if (hash == HashPasswd(passwd, salt))
                return true;
            return false;
        }

        private static string HashPasswd(string passwd, byte[] salt)
        {
            Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(passwd, salt, ITERATION);
            return Convert.ToBase64String(pbkdf2.GetBytes(HASH_SIZE));
        }
    }
}