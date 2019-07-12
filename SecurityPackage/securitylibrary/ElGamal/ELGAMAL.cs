using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            long c1 = 1;
            for (int i = 0; i < k; i++)
            {
                c1 = c1 % q;
                c1 *= (alpha % q);
            }
            c1 = (c1 % q);

            long kk = 1;
            for (int i = 0; i < k; i++)
            {
                kk = kk % q;
                kk *= (y % q);
            }
            kk = (kk % q);
            long c2 = kk * m % q;
            List<long> ciphers = new List<long>();
            ciphers.Add(c1);
            ciphers.Add(c2);
            return ciphers;
        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            int K = 1;
            for (int i = 0; i < x; i++)
            {
                K = K % q;
                K *= (c1 % q);
            }
            K = (K % q);

            int kInv;
            //Ectended Eclud to calc K inverse
            int a = K;
            int b = q;

            int x0 = 1, xn = 1;
            int y0 = 0, yn = 0;
            int x1 = 0;
            int y1 = 1;
            int qq;
            int r = a % b;

            while (r > 0)
            {
                qq = a / b;
                xn = x0 - qq * x1;
                yn = y0 - qq * y1;

                x0 = x1;
                y0 = y1;
                x1 = xn;
                y1 = yn;
                a = b;
                b = r;
                r = a % b;
            }
            kInv = xn;
            if (kInv < 0)
            {
                kInv = (xn % q);
                kInv += q;
            }
            int M = c2 * kInv % q;
            return M;
        }
    }
}
