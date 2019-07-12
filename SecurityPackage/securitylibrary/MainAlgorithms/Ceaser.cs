using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
            int[] ptindex = new int[100];
            int[] ctindex = new int[100];
            char[] x = new char[100];


            for (int i = 0; i < plainText.Length; i++)
            {
                ptindex[i] = plainText[i] - 'a';
                ctindex[i] = ptindex[i] + key;
                if (ctindex[i] >= 26)
                {
                    ctindex[i] = ctindex[i] % 26;
                }
                x[i] = (Char)(ctindex[i] + 'a');
            }
            string ciefertext = new string(x);
            return ciefertext.ToUpper();
        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();
            int[] ptindex = new int[100];
            int[] ctindex = new int[100];
            char[] x = new char[100];


            for (int i = 0; i < cipherText.Length; i++)
            {
                ptindex[i] = cipherText[i] - 'A';
                ctindex[i] = ptindex[i] - key;
                if (ctindex[i] < 0)
                {
                    ctindex[i] = ctindex[i] + 26;
                }
                x[i] = (Char)(ctindex[i] + 'a');
            }
            string ciefertext = new string(x);
            return ciefertext.ToLower();
        }

        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            int y = cipherText[0] - plainText[0];
            if (y < 0)
            {
                y = y + 26;
            }
            return y;
        }
    }
}
