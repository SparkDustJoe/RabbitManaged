using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using RabbitManaged;

namespace RabbitManaged.Tester
{
    class Program
    {
        static void Main(string[] args)
        {

            byte[] s1 = new byte[] { 0x83, 0x95, 0x74, 0x15, 0x87, 0xE0, 0xC7, 0x33, 0xE9, 0xE9, 0xAB, 0x01, 0xC0, 0x9B, 0x00, 0x43 };
            Array.Reverse(s1);
            Console.WriteLine(BitConverter.ToString(s1).Replace("-", ", 0x"));
           

            




            int TESTCASE;
            TestCases tc = new TestCases();
            for (int i = 0; i < tc.Tests.Length; i++)
            {
                TESTCASE = i;
                Rabbit r = new Rabbit(tc.Tests[TESTCASE].Key, tc.Tests[TESTCASE].IV);
                byte[] output = r.KeyStreamBytes(tc.Tests[TESTCASE].ExpectedResult.Length);
                int firstDiff = -1;
                if (CompareArrays(tc.Tests[TESTCASE].ExpectedResult, output, out firstDiff))
                {
                    Console.WriteLine("Tests compare as true. " + i);
                }
                else
                {
                    Console.WriteLine("Test " + i + ", results compare as FALSE! First diff = " + firstDiff);
                    Console.WriteLine("Expexted:");
                    Console.WriteLine(BitConverter.ToString(tc.Tests[TESTCASE].ExpectedResult).Replace("-", ""));
                    Console.WriteLine("Obtained:");
                    Console.WriteLine(BitConverter.ToString(output).Replace("-", ""));
                    
                }
                Console.WriteLine("----");
            }
            Console.WriteLine("Press any key to end...");
            Console.ReadKey(true);
        }

        static bool CompareArrays(byte[] target1, byte[] target2, out int firstDiff)
        {
            if (target1 == null || target2 == null)
            {
                firstDiff = -1;
                return false;
            }
            firstDiff = Math.Min(target1.Length, target2.Length);
            for (int i = 0; i < Math.Min(target1.Length, target2.Length); i++)
            {
                if (target1[i] != target2[i])
                {
                    firstDiff = i;
                    return false;
                }
            }
            return true;
        }
    }
}
