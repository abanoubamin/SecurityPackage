using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            string key = "";
            string alphabetic = "abcdefghijklmnopqrstuvwxyz";
            string notfound = "";
            int flag = 0;
            for (int i = 0; i < alphabetic.Length; i++)
            {
                flag = 0;
                for (int j = 0; j < plainText.Length; j++)
                {
                    if (plainText[j] == alphabetic[i])
                    {
                        key += cipherText[j];
                        flag = 1;
                        break;
                    }

                }
                if (flag == 0)
                {
                    key += '+';
                }
            }
            for (int i = 0; i < alphabetic.Length; i++)
            {
                flag = 0;
                for (int j = 0; j < cipherText.Length; j++)
                {

                    if (alphabetic[i] == cipherText[j])
                    {
                        flag = 1;
                        break;
                    }

                }
                if (flag == 0)
                {
                    notfound += alphabetic[i];
                }
            }
            StringBuilder Newkey = new StringBuilder(key);
            int count = 0;
            for (int i = 0; i < key.Length; i++)
            {
                if (key[i] == '+')
                {
                    Newkey[i] = notfound[count];
                    count++;
                }
            }
            return Newkey.ToString();
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            string plainText = "";
            string alphabetic = "abcdefghijklmnopqrstuvwxyz";
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < key.Length; j++)
                {
                    if (cipherText[i] == key[j])
                    {
                        plainText += alphabetic[j];
                        break;
                    }
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            string cipherText = "";
            string alphabetic = "abcdefghijklmnopqrstuvwxyz";
            int x;
            for (int i = 0; i < plainText.Length; i++)
            {
                x = alphabetic.IndexOf(plainText[i]);
                cipherText += key[x];
            }
            return cipherText;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            //throw new NotImplementedException();
            cipher = cipher.ToLower();
            string plain = "";
            char[] alphabetic = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            //string freqInfo = "etaoinsrhldcumfpgwybvkxjqz";
            string freqInfo = "zqjxkvbywgpfmucdlhrsnioate";
            int[] arr = new int[26];
            int cnt;
            for (int i = 0; i < 26; i++)
            {
                cnt = 0;
                for (int j = 0; j < cipher.Length; j++)
                {
                    if (alphabetic[i] == cipher[j])
                    {
                        cnt++;
                    }
                }
                arr[i] = cnt;
            }
            int temp = 0;
            char tmp;
            for (int k = 0; k < arr.Length; k++)
            {
                for (int l = 0; l < arr.Length - 1; l++)
                {
                    if (arr[l] > arr[l + 1])
                    {
                        temp = arr[l + 1];
                        arr[l + 1] = arr[l];
                        arr[l] = temp;

                        tmp = alphabetic[l + 1];
                        alphabetic[l + 1] = alphabetic[l];
                        alphabetic[l] = tmp;
                    }
                }
            }
            string key = "";
            for (int m = 0; m < 26; m++)
            {
                key += alphabetic[m];
            }
            int x;
            for (int n = 0; n < cipher.Length; n++)
            {
                x = key.IndexOf(cipher[n]);
                plain += freqInfo[x];
            }
            return plain;
        }
    }
}