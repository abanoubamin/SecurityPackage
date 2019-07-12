using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        static string removeRepeated(string key)
        {
            string R = "";

            foreach (char v in key)
            {
                if (R.IndexOf(v) == -1)
                {
                    R += v;
                }
            }
            return R;
        }
        public string Decrypt(string cipherText, string key)
        {
            string KeyUpper = key.ToUpper();
            string keyNotDuplicated = removeRepeated(KeyUpper);


            char[,] array = new char[5, 5];
            int indexI = 0;
            int indexJ = 0;
            bool check = false;

            for (int i = 0; i < keyNotDuplicated.Length; i++)
            {
                if (keyNotDuplicated[i] == 'I')
                {
                    check = true;
                }
                if (keyNotDuplicated[i] == 'J' && check == true)
                {
                    continue;
                }
                array[indexI, indexJ] = keyNotDuplicated[i];
                indexJ++;
                if (indexJ == 5)
                {
                    indexJ = 0;
                    indexI++;
                }



            }
            check = false;
            for (char i = 'A'; i <= 'Z'; i++)
            {
                if (i == 'J' && keyNotDuplicated.Contains('I'))
                {
                    continue;
                }
                if (!keyNotDuplicated.Contains(i))
                {
                    if (indexJ == 5 || indexI == 5)
                    {
                        break;
                    }

                    if (i == 'I')
                    {
                        check = true;
                    }
                    if (i == 'J' && check == true)
                    {
                        continue;
                    }
                    array[indexI, indexJ] = i;
                    indexJ++;
                    if (indexJ == 5)
                    {
                        indexJ = 0;
                        indexI++;
                    }



                }
            }
            //string cipherTextLower = cipherText.ToLower();
            string cipherTextTowork = cipherText;
            StringBuilder PlainText = new StringBuilder("");


            int indexofIFisrChar = 0;
            int indexofJFisrChar = 0;

            int indexofISecondChar = 0;
            int indexofJSecondChar = 0;
            //StringBuilder cipher = new StringBuilder("");


            for (int i = 0; i < (cipherTextTowork.Length); i = i + 2)
            {
                for (int j = 0; j < 5; j++)
                {
                    for (int k = 0; k < 5; k++)
                    {
                        if (array[j, k] == cipherTextTowork[i])
                        {
                            indexofIFisrChar = j;
                            indexofJFisrChar = k;
                        }
                    }
                }

                for (int L = 0; L < 5; L++)
                {
                    for (int M = 0; M < 5; M++)
                    {
                        if (array[L, M] == cipherTextTowork[i + 1])
                        {
                            indexofISecondChar = L;
                            indexofJSecondChar = M;
                        }
                    }
                }
                if (indexofIFisrChar == indexofISecondChar)
                {
                    if ((indexofJFisrChar) != 0)
                    {
                        PlainText.Insert(i, array[indexofIFisrChar, indexofJFisrChar - 1]);
                    }
                    else
                    {
                        PlainText.Insert(i, array[indexofIFisrChar, 4]);
                    }
                    if ((indexofJSecondChar) != 0)
                    {
                        PlainText.Insert(i + 1, array[indexofISecondChar, indexofJSecondChar - 1]);
                    }
                    else
                    {
                        PlainText.Insert(i + 1, array[indexofISecondChar, 4]);
                    }
                }

                else if (indexofJFisrChar == indexofJSecondChar)
                {
                    if ((indexofIFisrChar ) != 0)
                    {
                        PlainText.Insert(i, array[indexofIFisrChar - 1, indexofJFisrChar]);
                    }
                    else
                    {
                        PlainText.Insert(i, array[4, indexofJFisrChar]);
                    }
                    if ((indexofISecondChar ) != 0)
                    {
                        PlainText.Insert(i + 1, array[indexofISecondChar - 1, indexofJSecondChar]);
                    }
                    else
                    {
                        PlainText.Insert(i + 1, array[4, indexofJSecondChar]);
                    }
                }
                else
                {
                    PlainText.Insert(i, array[indexofIFisrChar, indexofJSecondChar]);
                    PlainText.Insert(i + 1, array[indexofISecondChar, indexofJFisrChar]);
                }
                indexofIFisrChar = 0;
                indexofJFisrChar = 0;

                indexofISecondChar = 0;
                indexofJSecondChar = 0;
            }
            string plainTextString = ((PlainText).ToString()).ToLower();       
            int c = 0;
            
            for (int i = 0; i < plainTextString.Length; i++)
            {
                if((i+2)< PlainText.Length)
                {
                    if ((plainTextString[i] == plainTextString[i + 2]) && (plainTextString[i+1] == 'x') &&( (i+1) % 2 != 0))
                    {
                        PlainText.Remove(i+1-c, 1);
                        c++;
                    }

                }
            }
            plainTextString = ((PlainText).ToString()).ToLower();
            if (plainTextString[PlainText.Length-1] == 'x')
            {
                PlainText.Remove(PlainText.Length - 1, 1);
                
            }
            return ((PlainText).ToString()).ToLower();
        }

        public string Encrypt(string plainText, string key)
        {
            
            string KeyUpper = key.ToUpper();
            string keyNotDuplicated = removeRepeated(KeyUpper);


            char[,] array = new char[5, 5];
            int indexI = 0;
            int indexJ = 0;
            bool check = false;
            
            for (int i = 0; i < keyNotDuplicated.Length; i++)
            {
                if (keyNotDuplicated[i] == 'I')
                {
                    check = true;
                }
                if (keyNotDuplicated[i] == 'J' && check == true)
                {
                    continue;
                }
                array[indexI, indexJ] = keyNotDuplicated[i];
                    indexJ++;
                    if (indexJ == 5)
                    {
                        indexJ = 0;
                        indexI++;
                    }     
            }
            check = false;
            for (char i = 'A'; i <= 'Z'; i++)
            {
                if(i=='J' && keyNotDuplicated.Contains('I'))
                {
                    continue;
                }
                if (!keyNotDuplicated.Contains(i))
                {
                    if (indexJ == 5 || indexI == 5)
                    {
                        break;
                    }

                    if (i == 'I')
                    {
                        check = true;
                    }
                    if (i == 'J' && check == true)
                    {
                        continue;
                    }
                    array[indexI, indexJ] = i;
                    indexJ++;
                    if (indexJ == 5)
                    {
                        indexJ = 0;
                        indexI++;
                    }
                    
                    
                    
                }
            }
            string plainTextUpper = plainText.ToUpper();
            StringBuilder UpdatedPlainText = new StringBuilder("");
            UpdatedPlainText.Insert(0 ,plainTextUpper[0]);
            int UpdatedPlainTextIdex = 1;
            int counter = 0;
            for (int i = 1; i< plainTextUpper.Length; i++)
            {
                if((plainTextUpper[i]== plainTextUpper[i - 1]) && ((i+ counter) %2!=0))
                {
                    UpdatedPlainText.Insert(UpdatedPlainTextIdex, 'X');
                    UpdatedPlainTextIdex++;
                    UpdatedPlainText.Insert(UpdatedPlainTextIdex, plainTextUpper[i]);
                    UpdatedPlainTextIdex++;
                    counter++;


                }
                else
                {
                    UpdatedPlainText.Insert(UpdatedPlainTextIdex, plainTextUpper[i]);
                    UpdatedPlainTextIdex++;
                }
            }
            if (UpdatedPlainText.Length % 2 != 0)
            {
                UpdatedPlainText.Insert(UpdatedPlainText.Length, 'X');
            }
            int indexofIFisrChar = 0;
            int indexofJFisrChar = 0;

            int indexofISecondChar = 0;
            int indexofJSecondChar = 0;
            StringBuilder cipher = new StringBuilder("");


            for(int i = 0; i< (UpdatedPlainText.Length); i = i+2)
            {
                for(int j = 0; j<5; j++)
                {
                    for (int k = 0; k < 5; k++)
                    {
                        if(array[j,k] == UpdatedPlainText[i])
                        {
                            indexofIFisrChar = j;
                            indexofJFisrChar = k;
                        }
                    }
                }

                for (int L = 0; L < 5; L++)
                {
                    for (int M = 0; M < 5; M++)
                    {
                        if (array[L, M] == UpdatedPlainText[i+1])
                        {
                            indexofISecondChar = L;
                            indexofJSecondChar = M;
                        }
                    }
                }
                if(indexofIFisrChar == indexofISecondChar)
                {
                    if((indexofJFisrChar + 1) != 5)
                    {
                        cipher.Insert(i , array[indexofIFisrChar, indexofJFisrChar + 1]);
                    }
                    else
                    {
                        cipher.Insert(i, array[indexofIFisrChar, 0]);
                    }
                    if ((indexofJSecondChar + 1) != 5)
                    {
                        cipher.Insert(i + 1, array[indexofISecondChar, indexofJSecondChar + 1]);
                    }
                    else
                    {
                        cipher.Insert(i + 1, array[indexofISecondChar, 0]);
                    }
                }

                else if (indexofJFisrChar == indexofJSecondChar)
                {
                    if ((indexofIFisrChar + 1) != 5)
                    {
                        cipher.Insert(i,  array[indexofIFisrChar +1 , indexofJFisrChar]);
                    }
                    else
                    {
                        cipher.Insert(i, array[0, indexofJFisrChar]);
                    }
                    if ((indexofISecondChar + 1) != 5)
                    {
                        cipher.Insert(i + 1, array[indexofISecondChar +1, indexofJSecondChar]);
                    }
                    else
                    {
                        cipher.Insert(i + 1, array[0, indexofJSecondChar]);
                    }
                }
                else
                {
                    cipher.Insert(i , array[indexofIFisrChar, indexofJSecondChar]);
                    cipher.Insert(i + 1, array[indexofISecondChar, indexofJFisrChar]);
                }
                indexofIFisrChar = 0;
                indexofJFisrChar = 0;

                indexofISecondChar = 0;
                indexofJSecondChar = 0;
            }
            
            return (cipher).ToString();
        }
    }
}
