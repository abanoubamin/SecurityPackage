using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            int key = 1;
            while (true)
            {

                string cipher = "";
                int col;
                if (plainText.Length % key == 0)
                {
                    col = plainText.Length / key;
                }
                else
                {
                    col = (plainText.Length / key) + 1;
                }
                char[] Plain = new char[key * col];
                for (int i = 0; i < plainText.Length; i++)
                    Plain[i] = plainText[i];
                char[,] arr = new char[key, col];
                int cnt = 0;
                for (int j = 0; j < col; j++)
                {
                    for (int i = 0; i < key; i++)
                    {
                        arr[i, j] = Plain[cnt];
                        cnt++;
                    }
                }
                for (int i = 0; i < key; i++)
                {
                    for (int j = 0; j < col; j++)
                    {
                        if (arr[i, j] != '\0')
                            cipher += arr[i, j];
                    }
                }

                if ((cipherText == cipher) || (key == cipherText.Length / 2))
                    break;
                else
                    key++;

            }
            return key;
        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();
            string plainText = "";
            int col;
            if (cipherText.Length % key == 0)
            {
                col = cipherText.Length / key;
            }
            else
            {
                col = (cipherText.Length / key) + 1;
            }
            char[] Cipher = new char[key * col];
            for (int i = 0; i < cipherText.Length; i++)
                Cipher[i] = cipherText[i];
            char[,] arr = new char[key, col];
            int cnt = 0;
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    arr[i, j] = Cipher[cnt];
                    cnt++;
                }
            }
            for (int j = 0; j < col; j++)
            {
                for (int i = 0; i < key; i++)
                {
                    if (arr[i, j] != '\0')
                        plainText += arr[i, j];
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
            string cipherText = "";
            int col;
            if (plainText.Length % key == 0)
            {
                col = plainText.Length / key;
            }
            else
            {
                col = (plainText.Length / key) + 1;
            }
            char[] Plain = new char[key * col];
            for (int i = 0; i < plainText.Length; i++)
                Plain[i] = plainText[i];
            char[,] arr = new char[key, col];
            int cnt = 0;
            for (int j = 0; j < col; j++)
            {
                for (int i = 0; i < key; i++)
                {
                    arr[i, j] = Plain[cnt];
                    cnt++;
                }
            }
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    if (arr[i, j] != '\0')
                        cipherText += arr[i, j];
                }
            }
            return cipherText;
        }
    }
}
