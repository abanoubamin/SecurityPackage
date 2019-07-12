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
    public class DES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            string Hex = "0123456789ABCDEF";
            string[] dec = { "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15" };
            string[] Binary = { "0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111", "1000", "1001", "1010", "1011", "1100", "1101", "1110", "1111" };
            string binaryKey = "";
            string binaryPlain = "";
            int x;
            int counter = 1;
            string ipPlain = "";
            string[] L = new string[17];
            string[] R = new string[17];
            string[] ER = new string[17];
            int[] ip = {
                        58, 50, 42, 34, 26, 18, 10,  2,
                        60, 52, 44, 36, 28, 20, 12,  4,
                        62, 54, 46, 38, 30, 22, 14,  6,
                        64, 56, 48, 40, 32, 24, 16,  8,
                        57, 49, 41, 33, 25, 17,  9,  1,
                        59, 51, 43, 35, 27, 19, 11,  3,
                        61, 53, 45, 37, 29, 21, 13,  5,
                        63, 55, 47, 39, 31, 23, 15,  7
                    };
            int[] E = {
                        32,  1,  2,  3,  4,  5,
                         4,  5,  6,  7,  8,  9,
                         8,  9, 10, 11, 12, 13,
                        12, 13, 14, 15, 16, 17,
                        16, 17, 18, 19, 20, 21,
                        20, 21, 22, 23, 24, 25,
                        24, 25, 26, 27, 28, 29,
                        28, 29, 30, 31, 32,  1
                    };
            int[,] s1Box = {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
                     {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
                     {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
                     {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}};

            int[,] s2Box = {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
                       {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
                       {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
                       {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}};

            int[,] s3Box = {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
                       {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
                       {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
                       {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}};

            int[,] s4Box = {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
                       {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
                       {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
                       {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}};

            int[,] s5Box = {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
                      {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
                      {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
                      {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}};

            int[,] s6Box = {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
                      {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
                      {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
                      {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}};

            int[,] s7Box = {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
                       {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
                       {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
                       {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}};

            int[,] s8Box = {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
                       {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
                       {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
                       {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}};
            int[] p = {
                        16,  7, 20, 21,
                        29, 12, 28, 17,
                         1, 15, 23, 26,
                         5, 18, 31, 10,
                         2,  8, 24, 14,
                        32, 27,  3,  9,
                        19, 13, 30,  6,
                        22, 11,  4, 25
                    };
            int[] ipInverse = {
                        40,  8, 48, 16, 56, 24, 64, 32,
                        39,  7, 47, 15, 55, 23, 63, 31,
                        38,  6, 46, 14, 54, 22, 62, 30,
                        37,  5, 45, 13, 53, 21, 61, 29,
                        36,  4, 44, 12, 52, 20, 60, 28,
                        35,  3, 43, 11, 51, 19, 59, 27,
                        34,  2, 42, 10, 50, 18, 58, 26,
                        33,  1, 41,  9, 49, 17, 57, 25
                        };
            for (int i = 2; i < key.Length; i++)
            {
                x = Hex.IndexOf(key[i]);
                binaryKey += Binary[x];
            }
            int[] PC1 = { 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4 };
            string permKey1 = "";
            for (int j = 0; j < PC1.Count(); j++)
            {
                permKey1 += binaryKey[PC1[j] - 1];
            }
            string temp;
            string[] C = new string[17];
            string[] D = new string[17];
            string[] CD = new string[17];
            C[0] = permKey1.Substring(0, 28);
            D[0] = permKey1.Substring(28);
            CD[0] = C[0] + D[0];
            for (int k = 1; k <= 16; k++)
            {
                C[k] = C[k - 1].Substring(1) + C[k - 1][0];
                D[k] = D[k - 1].Substring(1) + D[k - 1][0];
                if (k != 1 && k != 2 && k != 9 && k != 16)
                {
                    temp = C[k];
                    C[k] = temp.Substring(1) + temp[0];
                    temp = D[k];
                    D[k] = temp.Substring(1) + temp[0];
                }
                CD[k] = C[k] + D[k];
            }
            int[] PC2 = { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };
            string[] KK = new string[16];
            for (int l = 0; l < 16; l++)
            {
                for (int m = 0; m < PC2.Count(); m++)
                {
                    KK[l] += CD[l + 1][PC2[m] - 1];
                }
            }
            string[] K = new string[16];
            int jj = 15;
            for (int i = 0; i < 16; i++)
            {
                K[i] = KK[jj];
                jj--;
            }
            for (int i = 2; i < cipherText.Length; i++)
            {
                x = Hex.IndexOf(cipherText[i]);
                binaryPlain += Binary[x];

            }
            for (int i = 0; i < ip.Length; i++)
            {
                ipPlain += binaryPlain[ip[i] - 1];
            }
            L[0] = ipPlain.Substring(0, 32);
            R[0] = ipPlain.Substring(32);
            for (int i = 1; i <= 16; i++)
            {
                L[i] = R[i - 1];
                string t = R[i - 1];
                for (int j = 0; j < 48; j++)
                {
                    ER[i - 1] += t[E[j] - 1];
                }
                string keey = K[i - 1];
                string keyXorR = "";
                int sbox = 0;
                string fsbox = "";
                string fsbox2 = "";
                t = ER[i - 1];
                for (int j = 0; j < 48; j++)
                {
                    if ((keey[j] == '0' && t[j] == '0') || (keey[j] == '1' && t[j] == '1'))
                    {
                        keyXorR += '0';
                    }
                    else
                    {
                        keyXorR += '1';
                    }
                }

                counter = 1;
                for (int j = 0; j < 48; j += 6)
                {
                    string row = "";
                    string column = "";
                    int r = 0;
                    int c = 0;
                    row += keyXorR[j];
                    row += keyXorR[j + 5];
                    column = keyXorR.Substring(j + 1, 4);
                    if (row == "00")
                        r = 0;
                    else if (row == "11")
                        r = 3;
                    else if (row == "01")
                        r = 1;
                    else if (row == "10")
                        r = 2;
                    for (int m = 0; m < dec.Length; m++)
                    {
                        if (Binary[m] == column)
                        {
                            c = Convert.ToInt32(dec[m]);
                            break;
                        }
                    }

                    if (counter == 1)
                        sbox = s1Box[r, c];
                    else if (counter == 2)
                        sbox = s2Box[r, c];
                    else if (counter == 3)
                        sbox = s3Box[r, c];
                    else if (counter == 4)
                        sbox = s4Box[r, c];
                    if (counter == 5)
                        sbox = s5Box[r, c];
                    if (counter == 6)
                        sbox = s6Box[r, c];
                    if (counter == 7)
                        sbox = s7Box[r, c];
                    if (counter == 8)
                        sbox = s8Box[r, c];
                    counter++;

                    fsbox += Binary[sbox];
                }

                for (int j = 0; j < 32; j++)
                {
                    fsbox2 += fsbox[p[j] - 1];
                }

                for (int j = 0; j < 32; j++)
                {
                    if ((L[i - 1][j] == '0' && fsbox2[j] == '0') || (L[i - 1][j] == '1' && fsbox2[j] == '1'))
                        R[i] += "0";
                    else
                        R[i] += "1";
                }

            }
            string cipher = "";
            string finalCipher = "0x";
            string reservedOrder = R[16];

            reservedOrder += L[16];
            for (int i = 0; i < 64; i++)
            {
                cipher += reservedOrder[ipInverse[i] - 1];

            }
            for (int i = 0; i < 64; i += 4)
            {
                string s = cipher.Substring(i, 4);
                for (int j = 0; j < Binary.Length; j++)
                {
                    if (Binary[j] == s)
                    {
                        finalCipher += Hex[j];
                        break;
                    }
                }
            }

            return finalCipher;
        }

        public override string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            string Hex = "0123456789ABCDEF";
            string[] dec = { "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15" };
            string[] Binary = { "0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111", "1000", "1001", "1010", "1011", "1100", "1101", "1110", "1111" };
            string binaryKey = "";
            string binaryPlain = "";
            int x;
            int counter = 1;
            string ipPlain = "";
            string[] L = new string[17];
            string[] R = new string[17];
            string[] ER = new string[17];
            int[] ip = {
                        58, 50, 42, 34, 26, 18, 10,  2,
                        60, 52, 44, 36, 28, 20, 12,  4,
                        62, 54, 46, 38, 30, 22, 14,  6,
                        64, 56, 48, 40, 32, 24, 16,  8,
                        57, 49, 41, 33, 25, 17,  9,  1,
                        59, 51, 43, 35, 27, 19, 11,  3,
                        61, 53, 45, 37, 29, 21, 13,  5,
                        63, 55, 47, 39, 31, 23, 15,  7
                    };
            int[] E = {
                        32,  1,  2,  3,  4,  5,
                         4,  5,  6,  7,  8,  9,
                         8,  9, 10, 11, 12, 13,
                        12, 13, 14, 15, 16, 17,
                        16, 17, 18, 19, 20, 21,
                        20, 21, 22, 23, 24, 25,
                        24, 25, 26, 27, 28, 29,
                        28, 29, 30, 31, 32,  1
                    };
            int[,] s1Box = {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
                     {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
                     {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
                     {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}};

            int[,] s2Box = {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
                       {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
                       {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
                       {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}};

            int[,] s3Box = {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
                       {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
                       {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
                       {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}};

            int[,] s4Box = {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
                       {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
                       {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
                       {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}};

            int[,] s5Box = {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
                      {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
                      {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
                      {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}};

            int[,] s6Box = {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
                      {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
                      {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
                      {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}};

            int[,] s7Box = {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
                       {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
                       {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
                       {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}};

            int[,] s8Box = {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
                       {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
                       {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
                       {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}};
            int[] p = {
                        16,  7, 20, 21,
                        29, 12, 28, 17,
                         1, 15, 23, 26,
                         5, 18, 31, 10,
                         2,  8, 24, 14,
                        32, 27,  3,  9,
                        19, 13, 30,  6,
                        22, 11,  4, 25
                    };
            int[] ipInverse = {
                        40,  8, 48, 16, 56, 24, 64, 32,
                        39,  7, 47, 15, 55, 23, 63, 31,
                        38,  6, 46, 14, 54, 22, 62, 30,
                        37,  5, 45, 13, 53, 21, 61, 29,
                        36,  4, 44, 12, 52, 20, 60, 28,
                        35,  3, 43, 11, 51, 19, 59, 27,
                        34,  2, 42, 10, 50, 18, 58, 26,
                        33,  1, 41,  9, 49, 17, 57, 25
                        };
            for (int i = 2; i < key.Length; i++)
            {
                x = Hex.IndexOf(key[i]);
                binaryKey += Binary[x];
            }
            int[] PC1 = { 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4 };
            string permKey1 = "";
            for (int j = 0; j < PC1.Count(); j++)
            {
                permKey1 += binaryKey[PC1[j] - 1];
            }
            string temp;
            string[] C = new string[17];
            string[] D = new string[17];
            string[] CD = new string[17];
            C[0] = permKey1.Substring(0, 28);
            D[0] = permKey1.Substring(28);
            CD[0] = C[0] + D[0];
            for (int k = 1; k <= 16; k++)
            {
                C[k] = C[k - 1].Substring(1) + C[k - 1][0];
                D[k] = D[k - 1].Substring(1) + D[k - 1][0];
                if (k != 1 && k != 2 && k != 9 && k != 16)
                {
                    temp = C[k];
                    C[k] = temp.Substring(1) + temp[0];
                    temp = D[k];
                    D[k] = temp.Substring(1) + temp[0];
                }
                CD[k] = C[k] + D[k];
            }
            int[] PC2 = { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };
            string[] K = new string[16];
            for (int l = 0; l < 16; l++)
            {
                for (int m = 0; m < PC2.Count(); m++)
                {
                    K[l] += CD[l + 1][PC2[m] - 1];
                }
            }
            for (int i = 2; i < plainText.Length; i++)
            {
                x = Hex.IndexOf(plainText[i]);
                binaryPlain += Binary[x];

            }
            for (int i = 0; i < ip.Length; i++)
            {
                ipPlain += binaryPlain[ip[i] - 1];
            }
            L[0] = ipPlain.Substring(0, 32);
            R[0] = ipPlain.Substring(32);
            for (int i = 1; i <= 16; i++)
            {
                L[i] = R[i - 1];
                string t = R[i - 1];
                for (int j = 0; j < 48; j++)
                {
                    ER[i - 1] += t[E[j] - 1];
                }
                string keey = K[i - 1];
                string keyXorR = "";
                int sbox = 0;
                string fsbox = "";
                string fsbox2 = "";
                t = ER[i - 1];
                for (int j = 0; j < 48; j++)
                {
                    if ((keey[j] == '0' && t[j] == '0') || (keey[j] == '1' && t[j] == '1'))
                    {
                        keyXorR += '0';
                    }
                    else
                    {
                        keyXorR += '1';
                    }
                }

                counter = 1;
                for (int j = 0; j < 48; j += 6)
                {
                    string row = "";
                    string column = "";
                    int r = 0;
                    int c = 0;
                    row += keyXorR[j];
                    row += keyXorR[j + 5];
                    column = keyXorR.Substring(j + 1, 4);
                    if (row == "00")
                        r = 0;
                    else if (row == "11")
                        r = 3;
                    else if (row == "01")
                        r = 1;
                    else if (row == "10")
                        r = 2;
                    for (int m = 0; m < dec.Length; m++)
                    {
                        if (Binary[m] == column)
                        {
                            c = Convert.ToInt32(dec[m]);
                            break;
                        }
                    }

                    if (counter == 1)
                        sbox = s1Box[r, c];
                    else if (counter == 2)
                        sbox = s2Box[r, c];
                    else if (counter == 3)
                        sbox = s3Box[r, c];
                    else if (counter == 4)
                        sbox = s4Box[r, c];
                    if (counter == 5)
                        sbox = s5Box[r, c];
                    if (counter == 6)
                        sbox = s6Box[r, c];
                    if (counter == 7)
                        sbox = s7Box[r, c];
                    if (counter == 8)
                        sbox = s8Box[r, c];
                    counter++;

                    fsbox += Binary[sbox];
                }

                for (int j = 0; j < 32; j++)
                {
                    fsbox2 += fsbox[p[j] - 1];
                }

                for (int j = 0; j < 32; j++)
                {
                    if ((L[i - 1][j] == '0' && fsbox2[j] == '0') || (L[i - 1][j] == '1' && fsbox2[j] == '1'))
                        R[i] += "0";
                    else
                        R[i] += "1";
                }

            }
            string cipher = "";
            string finalCipher = "0x";
            string reservedOrder = R[16];

            reservedOrder += L[16];
            for (int i = 0; i < 64; i++)
            {
                cipher += reservedOrder[ipInverse[i] - 1];

            }
            for (int i = 0; i < 64; i += 4)
            {
                string s = cipher.Substring(i, 4);
                for (int j = 0; j < Binary.Length; j++)
                {
                    if (Binary[j] == s)
                    {
                        finalCipher += Hex[j];
                        break;
                    }
                }
            }

            return finalCipher;
        }
    }
}
