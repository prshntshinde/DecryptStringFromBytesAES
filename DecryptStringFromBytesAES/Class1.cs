using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Activities;
using System.ComponentModel;
using System.Security.Cryptography;
using System.IO;

namespace DecryptStringFromBytesAES
{
    public class DecryptText : CodeActivity
    {
        [Category("Input")]
        [RequiredArgument]
        public InArgument<string> CipherText { get; set; }

        [Category("Input")]
        [RequiredArgument]
        public InArgument<string> Key { get; set; }

        [Category("Input")]
        [RequiredArgument]
        public InArgument<string> IV { get; set; }

        [Category("Output")]
        public OutArgument<string> OriginalText { get; set; }

        protected override void Execute(CodeActivityContext context)
        {
            var cipherText = CipherText.Get(context);
            var key = Key.Get(context);
            var iv = IV.Get(context);

            // Convert string to byte array
            var byteCipherText = Convert.FromBase64String(cipherText);
            var byteKey = Encoding.ASCII.GetBytes(key);
            var byteIV = Encoding.ASCII.GetBytes(iv);


            string original = DecryptStringFromBytes_Aes(byteCipherText, byteKey, byteIV);
            OriginalText.Set(context, original);
        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }
    }

    
}
