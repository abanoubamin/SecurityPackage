using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<List<int>> plainTextcols = new List<List<int>>();
            List<List<int>> cipherTextcols = new List<List<int>>();

            for (int i = 0; i < plainText.Count ; i+=2)
            {
                List<int> colP = new List<int>();
                colP.Add(plainText[i]);
                colP.Add(plainText[i + 1]);
                plainTextcols.Add(colP);

                List<int> colC = new List<int>();
                colC.Add(cipherText[i]);
                colC.Add(cipherText[i + 1]);
                cipherTextcols.Add(colC);
            }
            int sum = 0;
            for (int i = 1; i <= (plainText.Count / 2)-1; i ++)
            {
                sum += i;
            }
            List<List<int>> plainTextCom = new List<List<int>>();
            List<List<int>> cipherTextCom = new List<List<int>>();

            for (int i = 0; i < (plainText.Count / 2) - 1; i ++)
            {
                for (int j = i+1; j < (plainText.Count / 2); j++)
                {
                    List<int> colP = new List<int>();
                    colP.Add(plainTextcols[i].ElementAt(0));
                    colP.Add(plainTextcols[i].ElementAt(1));
                    colP.Add(plainTextcols[j].ElementAt(0));
                    colP.Add(plainTextcols[j].ElementAt(1));
                    plainTextCom.Add(colP);

                    List<int> colC = new List<int>();
                    colC.Add(cipherTextcols[i].ElementAt(0));
                    colC.Add(cipherTextcols[i].ElementAt(1));
                    colC.Add(cipherTextcols[j].ElementAt(0));
                    colC.Add(cipherTextcols[j].ElementAt(1));
                    cipherTextCom.Add(colC);
                }
            }
            for(int i = 0;i < plainTextCom.Count; i++)
            {
                int det = (plainTextCom[i].ElementAt(0) * plainTextCom[i].ElementAt(3)) - (plainTextCom[i].ElementAt(1) * plainTextCom[i].ElementAt(2));
                
                    
                List<int> modidfied = new List<int>();
                for (int j = 0; j <4; j++)
                {
                    if (plainTextCom[i].ElementAt(j) < 0)
                    {
                        modidfied.Insert(j, (plainTextCom[i].ElementAt(j) % 26) + 26);
                    }
                    else if (plainTextCom[i].ElementAt(j) >= 26)
                    {
                        modidfied.Insert(j, (plainTextCom[i].ElementAt(j) % 26));
                    }
                    else
                        modidfied.Insert(j, plainTextCom[i].ElementAt(j));
                }
                int dOfDeter = ((modidfied[0] * modidfied[3]) - (modidfied[1] * modidfied[2]));
                int constOfDeter = 0;
                if (dOfDeter != 1 && dOfDeter != -1)
                {
                    int a = dOfDeter;
                    int b = 26;

                    int x0 = 1, xn = 1;
                    int y0 = 0, yn = 0;
                    int x1 = 0;
                    int y1 = 1;
                    int q;
                    int r = a % b;

                    while (r > 0)
                    {
                        q = a / b;
                        xn = x0 - q * x1;
                        yn = y0 - q * y1;

                        x0 = x1;
                        y0 = y1;
                        x1 = xn;
                        y1 = yn;
                        a = b;
                        b = r;
                        r = a % b;
                    }
                    constOfDeter = xn;
                    if (constOfDeter < 0)
                    {
                        constOfDeter = constOfDeter + 26;
                    }
                }
                else
                {
                    constOfDeter = dOfDeter;
                }
                List<int> inverseOfPlain = new List<int>();

                inverseOfPlain.Insert(0, modidfied[3] * constOfDeter);
                inverseOfPlain.Insert(1, modidfied[1] * constOfDeter * -1);
                inverseOfPlain.Insert(2, modidfied[2] * constOfDeter * -1);
                inverseOfPlain.Insert(3, modidfied[0] * constOfDeter);

                List<int> Key = new List<int>();
                Key.Insert(0, (cipherTextCom[i].ElementAt(0) * inverseOfPlain[0]) + (cipherTextCom[i].ElementAt(2) * inverseOfPlain[1]));
                Key.Insert(1, (cipherTextCom[i].ElementAt(0) * inverseOfPlain[2]) + (cipherTextCom[i].ElementAt(2) * inverseOfPlain[3]));
                Key.Insert(2, (cipherTextCom[i].ElementAt(1) * inverseOfPlain[0]) + (cipherTextCom[i].ElementAt(3) * inverseOfPlain[1]));
                Key.Insert(3, (cipherTextCom[i].ElementAt(1) * inverseOfPlain[2]) + (cipherTextCom[i].ElementAt(3) * inverseOfPlain[3]));

                List<int> modifiedKey = new List<int>();
                for (int j = 0; j < 4; j++)
                {
                    if (Key[j] < 0)
                    {
                        modifiedKey.Insert(j, (Key[j] % 26) + 26);
                    }
                    else if (Key[j] >= 26)
                    {
                        modifiedKey.Insert(j, (Key[j] % 26));
                    }
                    else
                        modifiedKey.Insert(j, Key[j]);
                }
                List<int> ciphMessage = new List<int>();
                ciphMessage = Encrypt(plainText, modifiedKey);
                if (ciphMessage.SequenceEqual(cipherText))
                {

                    return modifiedKey;
                }
                
            }
            throw new InvalidAnlysisException();
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<int> inverseOfKey = new List<int>();
            int deter = 0;
            List<int> modidfied = new List<int>();
            for (int i = 0; i < key.Count; i++)
            {
                if (key[i] < 0)
                {
                    modidfied.Insert(i, (key[i] % 26) + 26);
                }
                else if (key[i] >= 26)
                {
                    modidfied.Insert(i, (key[i] % 26));
                }
                else
                    modidfied.Insert(i, key[i]);
            }
            if (modidfied.Count == 4)
            {
                int det = (key[0] * key[3]) - (key[1] * key[2]);
                if (det == 0 || (det % 2) == 0 || (det % 13) == 0)
                    throw new InvalidAnlysisException();
                int dOfDeter = ((modidfied[0] * modidfied[3]) - (modidfied[1] * modidfied[2]));
                int constOfDeter = 0;
                if (dOfDeter != 1 && dOfDeter != -1)
                {
                    int a = dOfDeter;
                    int b = 26;

                    int x0 = 1, xn = 1;
                    int y0 = 0, yn = 0;
                    int x1 = 0;
                    int y1 = 1;
                    int q;
                    int r = a % b;

                    while (r > 0)
                    {
                        q = a / b;
                        xn = x0 - q * x1;
                        yn = y0 - q * y1;

                        x0 = x1;
                        y0 = y1;
                        x1 = xn;
                        y1 = yn;
                        a = b;
                        b = r;
                        r = a % b;
                    }
                    constOfDeter = xn;
                    if (constOfDeter < 0)
                    {
                        constOfDeter = constOfDeter + 26;
                    }
                }
                else
                {
                    constOfDeter = dOfDeter;
                }
                inverseOfKey.Insert(0, modidfied[3] * constOfDeter);
                inverseOfKey.Insert(1, modidfied[1] * constOfDeter * -1);
                inverseOfKey.Insert(2, modidfied[2] * constOfDeter * -1);
                inverseOfKey.Insert(3, modidfied[0] * constOfDeter);
            }
            else if (key.Count > 4)
            {
                deter = (modidfied[0] * (modidfied[4] * modidfied[8] - modidfied[5] * modidfied[7])) - (modidfied[1] * (modidfied[3] * modidfied[8] - modidfied[5] * modidfied[6])) + (modidfied[2] * (modidfied[3] * modidfied[7] - modidfied[4] * modidfied[6]));
                if (deter == 0 || (deter % 2) == 0 || (deter % 13) == 0)
                    throw new InvalidAnlysisException();
                int startCondition = 0;
                if (deter < 26)
                {
                    startCondition = deter;
                }
                else
                {
                    startCondition = 26;
                }
                //bool GCD = false;
                for (int k = startCondition; k >= 2; k--)
                {
                    if (deter % k == 0 && 26 % k == 0)
                    {
                        //GCD = true;
                        throw new InvalidAnlysisException();
                    }
                }
                int newDeter = deter % 26;
                if (newDeter < 0)
                {
                    newDeter += 26;
                }
                int i = 26 - newDeter;
                int x = 0;
                int c = 0;
                while (true)
                {
                    double dd = ((double)((double)(x * 26) + 1) / (double)i);
                    bool is_integer = unchecked(dd == (int)dd);
                    if (is_integer)
                    {
                        c = (int)dd;
                        break;
                    }
                    else
                    {
                        x++;
                    }
                }
                int b = 26 - c;
                List<int> inverseOfKeyNotTranspose = new List<int>();
                inverseOfKeyNotTranspose.Insert(0, b * (modidfied[4] * modidfied[8] - modidfied[5] * modidfied[7]));
                inverseOfKeyNotTranspose.Insert(1, -1 * b * (modidfied[3] * modidfied[8] - modidfied[5] * modidfied[6]));
                inverseOfKeyNotTranspose.Insert(2, b * (modidfied[3] * modidfied[7] - modidfied[4] * modidfied[6]));
                inverseOfKeyNotTranspose.Insert(3, -1 * b * (modidfied[1] * modidfied[8] - modidfied[2] * modidfied[7]));
                inverseOfKeyNotTranspose.Insert(4, b * (modidfied[0] * modidfied[8] - modidfied[2] * modidfied[6]));
                inverseOfKeyNotTranspose.Insert(5, -1 * b * (modidfied[0] * modidfied[7] - modidfied[1] * modidfied[6]));
                inverseOfKeyNotTranspose.Insert(6, b * (modidfied[1] * modidfied[5] - modidfied[2] * modidfied[4]));
                inverseOfKeyNotTranspose.Insert(7, -1 * b * (modidfied[0] * modidfied[5] - modidfied[2] * modidfied[3]));
                inverseOfKeyNotTranspose.Insert(8, b * (modidfied[0] * modidfied[4] - modidfied[1] * modidfied[3]));
                inverseOfKey.Insert(0, inverseOfKeyNotTranspose[0]);
                inverseOfKey.Insert(1, inverseOfKeyNotTranspose[3]);
                inverseOfKey.Insert(2, inverseOfKeyNotTranspose[6]);
                inverseOfKey.Insert(3, inverseOfKeyNotTranspose[1]);
                inverseOfKey.Insert(4, inverseOfKeyNotTranspose[4]);
                inverseOfKey.Insert(5, inverseOfKeyNotTranspose[7]);
                inverseOfKey.Insert(6, inverseOfKeyNotTranspose[2]);
                inverseOfKey.Insert(7, inverseOfKeyNotTranspose[5]);
                inverseOfKey.Insert(8, inverseOfKeyNotTranspose[8]);
            }
            List<int> DecMessage = new List<int>();
            int keyCount = key.Count;
            int dim = (int)(Math.Sqrt(keyCount));
            int indexofeachrow = 0;
            for (int i = 0; i < cipherText.Count; i++)
            {
                DecMessage.Insert(i, 0);
            }
            int vectorIndex = 0;
            for (int i = 0; i < cipherText.Count; i++)
            {

                for (int j = 0; j < dim; j++)
                {

                    if ((i % (dim)) == 0)
                    {
                        vectorIndex = i;
                    }
                    else
                    {
                        for (int z = i; z >= 0; z--)
                        {
                            if ((z % (dim)) == 0)
                            {
                                vectorIndex = z;
                                break;
                            }
                        }

                    }
                    DecMessage[i] += inverseOfKey[j + (indexofeachrow * dim)] * cipherText[vectorIndex + j];
                }

                DecMessage[i] = DecMessage[i] % 26;
                if (indexofeachrow == (dim - 1))
                {
                    indexofeachrow = 0;
                }
                else
                {
                    indexofeachrow++;
                }
            }
            //int u = 0;
            for (int i = 0; i < DecMessage.Count; i++)
            {
                if (DecMessage[i] < 0)
                {
                    DecMessage[i] = DecMessage[i] % 26;
                    DecMessage[i] += 26;
                }
                else if (DecMessage[i] >= 26)
                {
                    DecMessage[i] = DecMessage[i] % 26;

                }
            }
            return DecMessage;
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> EncMessage = new List<int>();
            int keyCount = key.Count;
            int dim = (int)(Math.Sqrt(keyCount));
            int indexofeachrow = 0;
            for (int i = 0; i < plainText.Count; i++)
            {
                EncMessage.Insert(i, 0);
            }
            int vectorIndex = 0;
            for (int i = 0; i < plainText.Count; i++)
            {

                for (int j = 0; j < dim; j++)
                {

                    if ((i % (dim)) == 0)
                    {
                        vectorIndex = i;
                    }
                    else
                    {
                        for (int z = i; z >= 0; z--)
                        {
                            if ((z % (dim)) == 0)
                            {
                                vectorIndex = z;
                                break;
                            }
                        }

                    }
                    EncMessage[i] += key[j + (indexofeachrow * dim)] * plainText[vectorIndex + j];
                }

                EncMessage[i] = EncMessage[i] % 26;
                if (indexofeachrow == (dim - 1))
                {
                    indexofeachrow = 0;
                }
                else
                {
                    indexofeachrow++;
                }
            }
            return EncMessage;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            List<List<int>> plainTextcols = new List<List<int>>();
            List<List<int>> cipherTextcols = new List<List<int>>();

            for (int i = 0; i < plainText.Count; i += 3)
            {
                List<int> colP = new List<int>();
                colP.Add(plainText[i]);
                colP.Add(plainText[i + 1]);
                colP.Add(plainText[i + 2]);
                plainTextcols.Add(colP);

                List<int> colC = new List<int>();
                colC.Add(cipherText[i]);
                colC.Add(cipherText[i + 1]);
                colC.Add(cipherText[i + 2]);
                cipherTextcols.Add(colC);
            }
            int sum = 0;
            for (int i = 1; i <= (plainText.Count / 3) - 1; i++)
            {
                sum += i;
            }
            List<List<int>> plainTextCom = new List<List<int>>();
            List<List<int>> cipherTextCom = new List<List<int>>();

            
            
            for (int i = 0; i < (plainText.Count / 3) - 1; i++)
            {
                for (int j = i + 1; j < (plainText.Count / 3); j++)
                {
                    for (int w = j + 1; w < (plainText.Count / 3); w++)
                    {
                        List<int> colP = new List<int>();
                        colP.Add(plainTextcols[i].ElementAt(0));
                        colP.Add(plainTextcols[i].ElementAt(1));
                        colP.Add(plainTextcols[i].ElementAt(2));
                        colP.Add(plainTextcols[j].ElementAt(0));
                        colP.Add(plainTextcols[j].ElementAt(1));
                        colP.Add(plainTextcols[j].ElementAt(2));
                        colP.Add(plainTextcols[w].ElementAt(0));
                        colP.Add(plainTextcols[w].ElementAt(1));
                        colP.Add(plainTextcols[w].ElementAt(2));
                        plainTextCom.Add(colP);

                        List<int> colC = new List<int>();
                        colC.Add(cipherTextcols[i].ElementAt(0));
                        colC.Add(cipherTextcols[i].ElementAt(1));
                        colC.Add(cipherTextcols[i].ElementAt(2));
                        colC.Add(cipherTextcols[j].ElementAt(0));
                        colC.Add(cipherTextcols[j].ElementAt(1));
                        colC.Add(cipherTextcols[j].ElementAt(2));
                        colC.Add(cipherTextcols[w].ElementAt(0));
                        colC.Add(cipherTextcols[w].ElementAt(1));
                        colC.Add(cipherTextcols[w].ElementAt(2));
                        cipherTextCom.Add(colC);
                    }
                    
                }
            }
            for (int i = 0; i < plainTextCom.Count; i++)
            {
                List<int> inverseOfplainText = new List<int>();
                int deter = 0;
                List<int> modidfied = new List<int>();
                for (int j = 0; j < plainTextCom[i].Count; j++)
                {
                    if (plainTextCom[i].ElementAt(j) < 0)
                    {
                        modidfied.Insert(j, (plainTextCom[i].ElementAt(j) % 26) + 26);
                    }
                    else if (plainTextCom[i].ElementAt(j) >= 26)
                    {
                        modidfied.Insert(j, (plainTextCom[i].ElementAt(j) % 26));
                    }
                    else
                        modidfied.Insert(j, plainTextCom[i].ElementAt(j));
                }
                deter = (modidfied[0] * (modidfied[4] * modidfied[8] - modidfied[5] * modidfied[7])) - (modidfied[1] * (modidfied[3] * modidfied[8] - modidfied[5] * modidfied[6])) + (modidfied[2] * (modidfied[3] * modidfied[7] - modidfied[4] * modidfied[6]));
                if (deter == 0)
                {
                    throw new InvalidAnlysisException();
                }
                int startCondition = 0;
                if (deter < 26)
                {
                    startCondition = deter;
                }
                else
                {
                    startCondition = 26;
                }
                //bool GCD = false;
                for (int k = startCondition; k >= 2; k--)
                {
                    if (deter % k == 0 && 26 % k == 0)
                    {
                        //GCD = true;
                        throw new InvalidAnlysisException();
                    }
                }
                int newDeter = deter % 26;
                if (newDeter < 0)
                {
                    newDeter += 26;
                }

                int ii = 26 - newDeter;
                int x = 0;
                int c = 0;
                while (true)
                {
                    double dd = ((double)((double)(x * 26) + 1) / (double)ii);
                    bool is_integer = unchecked(dd == (int)dd);
                    if (is_integer)
                    {
                        c = (int)dd;
                        break;
                    }
                    else
                    {
                        x++;
                    }
                }
                int b = 26 - c;
                List<int> inverseOfKeyNotTranspose = new List<int>();
                inverseOfKeyNotTranspose.Insert(0, b * (modidfied[4] * modidfied[8] - modidfied[5] * modidfied[7]));
                inverseOfKeyNotTranspose.Insert(1, -1 * b * (modidfied[3] * modidfied[8] - modidfied[5] * modidfied[6]));
                inverseOfKeyNotTranspose.Insert(2, b * (modidfied[3] * modidfied[7] - modidfied[4] * modidfied[6]));
                inverseOfKeyNotTranspose.Insert(3, -1 * b * (modidfied[1] * modidfied[8] - modidfied[2] * modidfied[7]));
                inverseOfKeyNotTranspose.Insert(4, b * (modidfied[0] * modidfied[8] - modidfied[2] * modidfied[6]));
                inverseOfKeyNotTranspose.Insert(5, -1 * b * (modidfied[0] * modidfied[7] - modidfied[1] * modidfied[6]));
                inverseOfKeyNotTranspose.Insert(6, b * (modidfied[1] * modidfied[5] - modidfied[2] * modidfied[4]));
                inverseOfKeyNotTranspose.Insert(7, -1 * b * (modidfied[0] * modidfied[5] - modidfied[2] * modidfied[3]));
                inverseOfKeyNotTranspose.Insert(8, b * (modidfied[0] * modidfied[4] - modidfied[1] * modidfied[3]));
                inverseOfplainText.Insert(0, inverseOfKeyNotTranspose[0]);
                inverseOfplainText.Insert(1, inverseOfKeyNotTranspose[3]);
                inverseOfplainText.Insert(2, inverseOfKeyNotTranspose[6]);
                inverseOfplainText.Insert(3, inverseOfKeyNotTranspose[1]);
                inverseOfplainText.Insert(4, inverseOfKeyNotTranspose[4]);
                inverseOfplainText.Insert(5, inverseOfKeyNotTranspose[7]);
                inverseOfplainText.Insert(6, inverseOfKeyNotTranspose[2]);
                inverseOfplainText.Insert(7, inverseOfKeyNotTranspose[5]);
                inverseOfplainText.Insert(8, inverseOfKeyNotTranspose[8]);
                for (int a = 0; a < inverseOfplainText.Count; a++)
                {
                    if (inverseOfplainText[a] < 0)
                    {
                        inverseOfplainText[a] = inverseOfplainText[a] % 26;
                        inverseOfplainText[a] += 26;
                    }
                    else if (inverseOfplainText[a] >= 26)
                    {
                        inverseOfplainText[a] = inverseOfplainText[a] % 26;

                    }
                }
                List<int> cipherTrans = new List<int>();
                cipherTrans.Insert(0, cipherTextCom[i].ElementAt(0));
                cipherTrans.Insert(1, cipherTextCom[i].ElementAt(3));
                cipherTrans.Insert(2, cipherTextCom[i].ElementAt(6));
                cipherTrans.Insert(3, cipherTextCom[i].ElementAt(1));
                cipherTrans.Insert(4, cipherTextCom[i].ElementAt(4));
                cipherTrans.Insert(5, cipherTextCom[i].ElementAt(7));
                cipherTrans.Insert(6, cipherTextCom[i].ElementAt(2));
                cipherTrans.Insert(7, cipherTextCom[i].ElementAt(5));
                cipherTrans.Insert(8, cipherTextCom[i].ElementAt(8));
                List<int> cipherTrans2 = new List<int>();


                List<int> DecMessage = new List<int>();
                //int keyCount = 9;
                int dim = 3;

                int indexofeachrow = 0;
                for (int j = 0; j < 9; j++)
                {
                    DecMessage.Insert(j, 0);
                }
                int vectorIndex = 0;
                for (int r = 0; r < 9; r++)
                {

                    for (int j = 0; j < dim; j++)
                    {

                        if ((r % (dim)) == 0)
                        {
                            vectorIndex = r;
                        }
                        else
                        {
                            for (int z = r; z >= 0; z--)
                            {
                                if ((z % (dim)) == 0)
                                {
                                    vectorIndex = z;
                                    break;
                                }
                            }

                        }
                        DecMessage[r] += cipherTrans[j + (indexofeachrow * dim)] * inverseOfplainText[vectorIndex + j];
                    }

                    DecMessage[r] = DecMessage[r] % 26;
                    if (indexofeachrow == (dim - 1))
                    {
                        indexofeachrow = 0;
                    }
                    else
                    {
                        indexofeachrow++;
                    }
                    //indexofeachrow += dim;
                }
                List<int> Keys = new List<int>();
                Keys.Insert(0, DecMessage[0]);
                Keys.Insert(1, DecMessage[3]);
                Keys.Insert(2, DecMessage[6]);
                Keys.Insert(3, DecMessage[1]);
                Keys.Insert(4, DecMessage[4]);
                Keys.Insert(5, DecMessage[7]);
                Keys.Insert(6, DecMessage[2]);
                Keys.Insert(7, DecMessage[5]);
                Keys.Insert(8, DecMessage[8]);
                List<int> ciphMessage = new List<int>();
                ciphMessage = Encrypt(plainText, Keys);
                if (ciphMessage.SequenceEqual(cipherText))
                {

                    return Keys;
                }
            }
            throw new InvalidAnlysisException();


        }

    }
}
