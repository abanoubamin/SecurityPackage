using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            string key = "";
            string plaintext = "";
            int length = 0;
            string keySmallLength = "";
            string Key = "";
            int cnt = 0;
            int index = 0;
            int flag = 0;
            int row = 0;
            int column = 0;
            char[] ch = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            char[,] arr = new char[26, 26];
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (flag == 0)
                    {
                        index = j + cnt;
                    }
                    if (index == 26)
                    {
                        index = 0;
                        flag = 1;
                    }
                    arr[i, j] = ch[index];
                    if (flag == 1)
                        index++;
                }
                flag = 0;
                cnt++;
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (ch[j] == plainText[i])
                    {
                        row = j;
                        break;
                    }
                }
                for (int k = 0; k < 26; k++)
                {
                    if (arr[row, k] == cipherText[i])
                    {
                        column = k;
                        break;
                    }
                }
                Key += ch[column];
            }

            for (int v = 0; v < Key.Length; v++)
            {
                plaintext = "";
                key = keySmallLength;
                key += Key[v];
                keySmallLength = key;
                length = cipherText.Length - key.Length;
                for (int i = 0; i < length; i++)
                    key += plainText[i];
                for (int i = 0; i < cipherText.Length; i++)
                {
                    for (int j = 0; j < 26; j++)
                    {
                        if (ch[j] == key[i])
                        {
                            column = j;
                            break;
                        }

                    }
                    for (int k = 0; k < 26; k++)
                    {
                        if (arr[k, column] == cipherText[i])
                        {
                            row = k;
                            break;
                        }
                    }
                    plaintext += ch[row];
                }

                if (plaintext == plainText)
                    break;
            }
            return keySmallLength;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            string plainText = "";
            cipherText = cipherText.ToLower();
            int cnt = 0;
            int index = 0;
            int flag = 0;
            int row = 0;
            int column = 0;
            char[] ch = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            char[,] arr = new char[26, 26];
            int length = cipherText.Length - key.Length;

            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (flag == 0)
                    {
                        index = j + cnt;
                    }
                    if (index == 26)
                    {
                        index = 0;
                        flag = 1;
                    }
                    arr[i, j] = ch[index];
                    if (flag == 1)
                        index++;
                }
                flag = 0;
                cnt++;
            }
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (ch[j] == key[i])
                    {
                        column = j;
                        break;
                    }

                }
                for (int k = 0; k < 26; k++)
                {
                    if (arr[k, column] == cipherText[i])
                    {
                        row = k;
                        break;
                    }
                }

                plainText += ch[row];
                if (length > 0)
                {
                    key += plainText[i];
                    length--;
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            string cipher = "";
            int cnt = 0;
            int index = 0;
            int flag = 0;
            int row = 0;
            int column = 0;
            char[] ch = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            char[,] arr = new char[26, 26];
            int length = plainText.Length - key.Length;
            for (int i = 0; i < length; i++)
                key += plainText[i];
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (flag == 0)
                    {
                        index = j + cnt;
                    }
                    if (index == 26)
                    {
                        index = 0;
                        flag = 1;
                    }
                    arr[i, j] = ch[index];
                    if (flag == 1)
                        index++;
                }
                flag = 0;
                cnt++;
            }

            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (ch[j] == plainText[i])
                    {
                        row = j;
                        break;
                    }
                }
                for (int k = 0; k < 26; k++)
                {
                    if (ch[k] == key[i])
                    {
                        column = k;
                        break;
                    }
                }
                cipher += arr[row, column];
            }

            return cipher.ToUpper();
        }
    }
}
