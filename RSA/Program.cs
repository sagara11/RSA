using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization; 

namespace RSA
{
    public class RsaEnc
    {
        //Initializes a new instance of the RSACryptoServiceProvider class with a random key pair of the specified key size.
        public static RSACryptoServiceProvider csp = new RSACryptoServiceProvider(2048);  
        RSAParameters _privateKey;
        RSAParameters _publicKey;

        public RsaEnc()
        {
            _privateKey = csp.ExportParameters(true);
            _publicKey = csp.ExportParameters(false);
        }
        // Hàm in ra public key
        public string PublicKeyString()
        {
            var sw = new StringWriter();
            var xs = new XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, _publicKey);
            return sw.ToString();
        }

        public string Encrypt(string plaintext)
        {
            csp = new RSACryptoServiceProvider();
            csp.ImportParameters(_publicKey);

            var data = Encoding.Unicode.GetBytes(plaintext);
            var cypher = csp.Encrypt(data, false);
            return Convert.ToBase64String(cypher);
        }
        public string Decrypt(string cypherText)
        {
            var dataBytes = Convert.FromBase64String(cypherText);
            csp.ImportParameters(_privateKey);
            var plaintext = csp.Decrypt(dataBytes, false);
            return Encoding.Unicode.GetString(plaintext);
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            RsaEnc rs = new RsaEnc();
            string cypher = String.Empty;
            Console.WriteLine($"PublicKey: \n {rs.PublicKeyString()}");

            Console.WriteLine("Enter your text to encrypt");
            var text = Console.ReadLine();
            if(text != String.Empty)
            {
                cypher = rs.Encrypt(text);
                Console.WriteLine($"Cypher Text: \n{cypher} \n");
            }

            Console.WriteLine("Press Enter to decrypt");
            Console.ReadLine();
            var plaintext = rs.Decrypt(cypher);
            Console.WriteLine("Decrypted Text: \n");
            Console.WriteLine(plaintext);
            Console.ReadLine();
        }
    }
}
