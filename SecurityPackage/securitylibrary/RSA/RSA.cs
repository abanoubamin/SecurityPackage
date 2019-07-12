using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            
            int c = 1;
            for (int i = 0; i < e; i++)
            {
                c = c % n;
                c *= (M % n);
            }
            return (c % n);
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int Qn = (p - 1) * (q - 1);
            int d;


            //Extended Eclud to calc d
            int a = e;
            int b = Qn;

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
            d = xn;
            if (d < 0)
            {
                d = (xn % Qn);
                d += Qn;
            }
            
            int m = 1;
            for (int i = 0; i < d; i++)
            {
                m = m % n;
                m *= (C % n);
            }
            return (m % n);
        }
    }
}
