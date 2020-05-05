using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoEngine.Wpf
{
    public static class Engine
    {
        public static string ToEncrypt(this string password)
        {
            var EncryptionKey = "abc123";
            var clearBytes = Encoding.Unicode.GetBytes(password);
            using (var encryptor = Aes.Create())
            {
                var pdb = new Rfc2898DeriveBytes(EncryptionKey,
                    new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                if (encryptor != null)
                {
                    encryptor.Key = pdb.GetBytes(32);
                    encryptor.IV = pdb.GetBytes(16);
                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor.CreateEncryptor(),
                            CryptoStreamMode.Write))
                        {
                            cs.Write(clearBytes, 0, clearBytes.Length);
                            cs.Close();
                        }

                        password = Convert.ToBase64String(ms.ToArray());
                    }
                }
            }

            return password;
        }

        public static string ToDecrypt(this string password)
        {
            var EncryptionKey = "abc123";
            password = password.Replace(" ", "+");
            var cipherBytes = Convert.FromBase64String(password);
            using (var encryptor = Aes.Create())
            {
                var pdb = new Rfc2898DeriveBytes(EncryptionKey,
                    new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                if (encryptor != null)
                {
                    encryptor.Key = pdb.GetBytes(32);
                    encryptor.IV = pdb.GetBytes(16);
                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor.CreateDecryptor(),
                            CryptoStreamMode.Write))
                        {
                            cs.Write(cipherBytes, 0, cipherBytes.Length);
                            cs.Close();
                        }

                        password = Encoding.Unicode.GetString(ms.ToArray());
                    }
                }
            }

            return password;
        }
    }
}
