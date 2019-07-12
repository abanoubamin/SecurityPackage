using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        static List<int> StringToInt(string s)
        {
            List<int> L = new List<int>();
            foreach (var item in s)
            {
                L.Add(int.Parse(item.ToString()));
            }
            return L;
        }


        static List<string> GetPermute(string s)
        {
            if (s.Length == 1)
            {
                return new List<string> { s };
            }
            List<string> perms = new List<string>();
            for (int i = 0; i < s.Length; i++)
            {
                List<string> tempPerms = GetPermute(s.Remove(i, 1));
                for (int j = 0; j < tempPerms.Count; j++)
                    tempPerms[j] = tempPerms[j].Insert(0, s[i].ToString());
                perms.AddRange(tempPerms);
            }
            return perms;
        }
        public List<int> Analyse(string plainText, string cipherText)
        {
            int x = 2;
            char[] numstg = new char[20];
            List<int> result;
            string val = "";
            string cip = "";
            //  IEnumerable<IEnumerable<int>> result;
            do
            {

                for (int x1 = 0; x1 < x; x1++)
                {
                    val += x1 + 1;
                }

                List<string> valuess = GetPermute(val);

                //    result = GetPermutations(Enumerable.Range(1, x), x);
                for (int i = 0; i < valuess.Count(); i++)
                {
                    result = StringToInt(valuess[i]);
                    cip = Encrypt(plainText, result);
                    cip = cip.Replace("\0", string.Empty);

                    if (cip == cipherText.ToUpper())
                    {
                        return result;
                    }

                }

                x++;
                val = "";
            } while (x <= 9);
            List<int> xff = new List<int> { 1, 2, 3, 4, 5, 6, 7 };
            return xff;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            char[,] x = new char[100, 100];
            char[] y = new char[100];
            decimal nrow = key.Count;
            decimal ncol = cipherText.Length / nrow;
            ncol = Math.Ceiling(ncol);
            int k = 0;
            for (int i = 0; i < nrow; i++)
            {
                for (int j = 0; j < ncol; j++)
                {
                    int z = key[i] - 1;
                    k = (int)ncol * z;
                    if (k + j >= cipherText.Length)
                    {
                        break;
                    }
                    x[j, i] = cipherText[k + j];

                }
            }

            k = 0;
            for (int i = 0; i < ncol; i++)
            {
                for (int j = 0; j < nrow; j++)
                {
                    y[k] = x[i, j];
                    k++;

                }
            }
            string ptext = new string(y);
            return ptext.ToLower();


        }

        public string Encrypt(string plainText, List<int> key)
        {
            char[,] x = new char[100, 100];
            char[] y = new char[100];
            decimal nrow = key.Count;
            decimal ncol = plainText.Length / nrow;
            int b = plainText.Length;
            int l = b % (int)nrow;
            for (int i = 1; i < l; i++)
            {

                plainText += "x";
            }
            if (l == 1)
            {
                plainText += "x";
            }

            ncol = Math.Ceiling(ncol);
            int k = 0;
            for (int i = 0; i < ncol; i++)
            {
                for (int j = 0; j < nrow; j++)
                {
                    if (k > plainText.Length - 1)
                    {
                        break;
                    }

                    x[i, j] = plainText[k];


                    k++;

                }
            }
            k = 0;
            for (int i = 0; i < nrow; i++)
            {
                for (int j = 0; j < ncol; j++)
                {
                    int z = key[i] - 1;
                    k = (int)ncol * z;
                    y[k + j] = x[j, i];
                }
            }
            string ctext = new string(y);
            return ctext.ToUpper();

        }
    }
}
