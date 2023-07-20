/// PrimeGen
///
/// This file is meant to support Messenger in creating prime numbers.
/// 
///@author Zak Rutherford Email:zjr6302@rit.edu
///Created Oct 2022
///Edited Nov 2022
///
using System;
using System.IO;
using System.Threading;
using System.Collections;
using System.Security.Cryptography;
using System.Numerics;

namespace Prime
{
    /// <summary>
    /// Class used to implement extension methods for BigIntegers.
    /// </summary>
    static class BigIntExtension
    {
        /// <summary>
        /// Extension method for BigIntegers. Assumes BigInteger is positive and odd. Determines if the BigInteger is prime or not
        /// by using the Miller-Rabin Primality Test. The higher k is, the higher the rate of acccuracy.
        /// </summary>
        /// <param name="value"> The BigInteger being tested as prime.</param>
        /// <param name="k"> Default is 10. The number of iterations the algorithm will use, the higher the more accurate, but it takes more time.</param>
        /// <returns>True if probably prime, false if composite.</returns>
        public static Boolean isProbablyPrime(this BigInteger value, int k = 10)
        {
            //find d
            var d = value - 1;
            var s = 0;
            while (d % 2 == 0)
            {
                s++;
                d = d / 2;
            }

            //create RandomNumberGenerator instance
            RandomNumberGenerator rng = RandomNumberGenerator.Create();

            //do loop k times
            for (int i = 0; i < k; i++)
            {
                //get a
                BigInteger a = 0;
                while (a < 2 || a > value - 2)
                {
                    var byteArray = new byte[value.ToByteArray().Length];
                    rng.GetBytes(byteArray);
                    a = new BigInteger(byteArray);
                }
                //get x
                var x = BigInteger.ModPow(a, d, value);
                if (x == 1 || x == value - 1)
                {
                    continue;
                }
                //repeat s - 1 times
                for (int j = 0; j < s - 1; j++)
                {
                    x = BigInteger.ModPow(x, 2, value);
                    if (x == value - 1)
                    {
                        continue;
                    }
                }
                //composite
                return false;
            }
            //is probably prime
            return true;
        }
    }

    /// <summary>
    /// Class used to find large prime numbers.
    /// </summary>
    public class PrimeGen
    {

        /// <summary>
        /// Finds a prime
        /// </summary>
        /// <param name="bits"> The desired size in bits of the prime number(s). </param>
        /// <returns>A BigInteger prime number of bit size.</returns>
        public static BigInteger parallelPrime(int bits)
        {
            List<Thread> threads = new List<Thread>();
            List<int> primeList = new List<int>();
            int[] param = new int[3];
            param[0] = bits;
            param[1] = 0;
            BigInteger[] result = new BigInteger[1];

            //get number of proccessors to optimise number of threads.
            var threadCount = Environment.ProcessorCount;

            //create list of first (bit) primes
            primeList.Add(2);
            var primeCount = (bits * 2);
            var current = 3;
            primeList.Add(2);
            var prime = false;
            while (primeCount > 0)
            {
                prime = true;
                Parallel.ForEach(primeList, num =>
                {
                    if (current % num == 0)
                    {
                        prime = false;
                    }
                });
                if (prime)
                {
                    primeList.Add(current);
                    primeCount--;
                }
                current += 2;
            }

            //create threads
            for (int i = 0; i < threadCount; i++)
            {
                var newThread = new Thread(() => findPrime(param, primeList, result));
                newThread.Start();
                threads.Add(newThread);
            }

            //wait for threads to join
            foreach (Thread thread in threads)
            {
                thread.Join();
            }

            //return the found prime
            return result[0];
        }

        /// <summary>
        /// Randomly creates BigIntegers of specified size until the desired number of primes is reached. 
        /// </summary>
        /// <param name="param"> The array used to pass parameters that all threads can access and modify. param[0] should be bit size of number,
        /// param[1] should be 1 if a prime is found, and 0 if it has not (0 initially). </param>
        /// <param name="primeList"> The list of small prime numbers to mod the random numbers by, should be bigger depending on bit size. </param>
        /// <param name="result"> The array used to pass results back. </param>
        /// 
        public static void findPrime(int[] param, List<int> primeList, BigInteger[] result)
        {
            //create RandomNumberGenerator instance
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            var byteArray = new byte[param[0] / 8];
            BigInteger rand = 0;
            while (param[1] < 1)
            {
                var notReady = true;
                //create random number
                while (notReady)
                {
                    notReady = false;
                    rng.GetBytes(byteArray);
                    rand = new BigInteger(byteArray);

                    //turn positive
                    if (rand < 0)
                    {
                        rand = rand * -1;
                    }
                    foreach (int prime in primeList)
                    {
                        if (rand % prime == 0)
                        {
                            notReady = true;
                            break;
                        }
                    }
                }

                //if prime print and update param[1]
                if (rand.isProbablyPrime())
                {
                    lock (param)
                    {
                        if (param[1] < 1)
                        {
                            //increment param[1] and store result.
                            param[1]++;
                            result[0] = rand;
                        }
                    }
                }
            }
        }
    }
}