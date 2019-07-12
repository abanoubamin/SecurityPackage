using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public string Decrypt(string cipherText, List<string> key)
        {
            DES des = new DES();
            return des.Decrypt(des.Encrypt(des.Decrypt(cipherText, key[0]), key[1]), key[0]);
            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, List<string> key)
        {
            DES enc1 = new DES();
            string cipher1 = enc1.Encrypt(plainText, key[0]);
            DES dec = new DES();
            string plain = enc1.Decrypt(cipher1, key[1]);
            DES enc2 = new DES();
            string cipher2 = enc2.Encrypt(plain, key[0]);
            return cipher2;
            //throw new NotImplementedException();
        }

        public List<string> Analyse(string plainText,string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
