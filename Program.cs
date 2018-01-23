using System;
using System.IO;
using System.Security.Cryptography;

namespace ClsKeyGen
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args[0] == "create") CreateKeyPairs();
            else if (args[0] == "encryptpub") EncryptWithKey(ReadKey("public.key"), args[1]);
            else if (args[0] == "decryptpri") DecryptWithKey(ReadKey("private.key"), args[1]);
            else if (args[0] == "sign") SignRoundTrip(args[1]);

            Console.WriteLine("All done!!");
        }

        private static void SignRoundTrip(string message)
        {
            byte[] signed;
            var data = System.Text.Encoding.UTF8.GetBytes(message);
            using (var rsa = ReadKey("private.key")) 
            {
                signed = rsa.SignData(data, new SHA1CryptoServiceProvider());
            }

            using (var rsa = ReadKey("public.key"))
            {
                bool verified = rsa.VerifyData(data, new SHA1CryptoServiceProvider(), signed);
                if (verified) Console.WriteLine("Round-trip verification works.");
            }
        }

        private static void DecryptWithKey(RSACryptoServiceProvider rsa, string base64)
        {
            var bytes = Convert.FromBase64String(base64);
            var plainBytes = rsa.Decrypt(bytes, false);
            var plainText = System.Text.Encoding.ASCII.GetString(plainBytes);
            Console.WriteLine("Decrypted as: " + plainText);
            rsa.Dispose();
        }

        private static RSACryptoServiceProvider ReadKey(string path)
        {
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportCspBlob(Convert.FromBase64String(File.ReadAllText(path)));
            return rsa;
        }

        private static void EncryptWithKey(RSACryptoServiceProvider rsa, string plain)
        {
            var bytes = rsa.Encrypt(System.Text.Encoding.ASCII.GetBytes(plain), false);
            Console.WriteLine("Encrypted as: " + Convert.ToBase64String(bytes));
            rsa.Dispose();
        }

        static void CreateKeyPairs() 
        {
            using (var rsa = new RSACryptoServiceProvider(2048)) 
            {
                var privateBytes = rsa.ExportCspBlob(true);
                var publicBytes = rsa.ExportCspBlob(false);
                File.WriteAllText("private.key", Convert.ToBase64String(privateBytes));
                File.WriteAllText("public.key", Convert.ToBase64String(publicBytes));
            }
            Console.WriteLine("Keys created!!");
        }
    }
}
