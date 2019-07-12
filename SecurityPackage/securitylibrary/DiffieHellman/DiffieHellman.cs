using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            int YA = 1;
            for (int i = 0; i < xa; i++)
            {
                YA = YA % q;
                YA *= (alpha % q);
            }
            YA = (YA % q);

            int YB = 1;
            for (int i = 0; i < xb; i++)
            {
                YB = YB % q;
                YB *= (alpha % q);
            }
            YB = (YB % q);

            int K1 = 1;
            for (int i = 0; i < xa; i++)
            {
                K1 = K1 % q;
                K1 *= (YB % q);
            }
            K1 = (K1 % q);

            int K2 = 1;
            for (int i = 0; i < xb; i++)
            {
                K2 = K2 % q;
                K2 *= (YA % q);
            }
            K2 = (K2 % q);
            List<int> keys = new List<int>();
            keys.Add(K1);
            keys.Add(K2);
            return keys;
        }
    }
}
