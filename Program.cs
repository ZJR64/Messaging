///CSCI 251 Project 3
///
/// This program is used to send and recieve encrypted messages over a server. The keyGen option creates a
/// new public and private key then tores them on the computer. The sendKey option sends the generated public key to the
/// server. The getKey option gets public keys from the server by email address. The sendMsg option sends an
/// encrypted message to the server. The getMsge option recieves an enrypted message and decrypts it. ALl of this
/// is done with the standard RSA algorithms.
/// 
///@author Zak Rutherford Email: zjr6302@rit.edu
///Created Nov 2022
///
using System;
using System.IO;
using System.Threading;
using System.Collections;
using System.Security.Cryptography;
using System.Numerics;
using Prime;
using System.Net.Sockets;
using Newtonsoft.Json;
using System.Text;

namespace CSCI251Project3
{
    /// <summary>
    /// Class used to store and manipulate messages. Can both encrypt and decrypt it's content based on the
    /// parameters given.
    /// </summary>
    public class Message
    {
        public String email { get; set; }
        public String content { get; set; }

        /// <summary>
        /// Constructor used when generating new messages.
        /// </summary>
        /// <param name="email"> The email associated with the message.</param>
        /// <param name="message"> The plaintext message.</param>
        public Message(String email, String message)
        {
            this.email = email;
            this.content = message;
        }

        /// <summary>
        /// A blank constructor with no parameters, used mostly for Json deserialize.
        /// </summary>
        public Message() { }


        /// <summary>
        /// Encrypts the plaintext message.
        /// </summary>
        /// <param name="N"> N is used as the modulo for the operation</param>
        /// <param name="E"> E is used as the power for the function</param>
        public void encrypt(BigInteger E, BigInteger N)
        {
            //encode message to byte array for encryption
            var plainBytes = Encoding.ASCII.GetBytes(this.content);
            var bigPlain = new BigInteger(plainBytes);
            var bigCipher = BigInteger.ModPow(bigPlain, E, N);
            var cipherBytes = bigCipher.ToByteArray();
            this.content = Convert.ToBase64String(cipherBytes);

        }

        /// <summary>
        /// Decrypts the cipher message.
        /// </summary>
        /// <param name="N"> N is used as the modulo for the operation</param>
        /// <param name="D"> D is used as the power for the function</param>
        public void decrypt(BigInteger D, BigInteger N)
        {
            //encode message to byte array for decryption
            var cipherBytes = Convert.FromBase64String(this.content);
            var bigCipher = new BigInteger(cipherBytes);
            var bigPlain = BigInteger.ModPow(bigCipher, D, N);
            var plainBytes = bigPlain.ToByteArray();
            this.content = Encoding.ASCII.GetString(plainBytes);

        }

    }


    /// <summary>
    /// Class used to store and manipulate Public Keys, contains constructors, the ability to write
    /// files with the keys data, and the ability to extract E and N from the keys.
    /// </summary>
    public class Key
    {
        public String email { get; set; }
        public String key { get; set; }

        /// <summary>
        /// Constructor used when generating new keys.
        /// </summary>
        /// <param name="key"> The key to be stored in this object.</param>
        public Key(String key)
        {
            this.email = "temp";
            this.key = key;
        }

        /// <summary>
        /// A blank constructor with no parameters, used mostly for Json deserialize.
        /// </summary>
        public Key() { }

        /// <summary>
        /// Converts the key object to a json format then saves it as a file.
        /// </summary>
        /// <param name="path"> The command line arguments</param>
        public void writeFile(String path)
        {
            File.WriteAllText(path, JsonConvert.SerializeObject(this));
        }

        /// <summary>
        /// Parses through the key and extracts N and E from the key.
        /// </summary>
        /// <returns> BigInteger[] results. results[0] = E and results[1] = N.</returns>
        public BigInteger[] getEN()
        {
            var keyArray = Convert.FromBase64String(this.key);
            var sizeNArray = new byte[4];
            var sizeEArray = new byte[4];
            var index = 0;

            //extract E
            for (int i = 0; i < 4; i++)
            {
                sizeEArray[i] = keyArray[index];
                index++;
            }
            //size of E
            var size = (int)new BigInteger(sizeEArray);
            var EArray = new byte[size];
            for (int i = 0; i < size; i++)
            {
                EArray[i] = keyArray[index];
                index++;
            }

            //extract N
            for (int i = 0; i < 4; i++)
            {
                sizeNArray[i] = keyArray[index];
                index++;
            }
            //size of N
            size = (int)new BigInteger(sizeNArray);
            var NArray = new byte[size];
            for (int i = 0; i < size; i++)
            {
                NArray[i] = keyArray[index];
                index++;
            }

            BigInteger[] results = new BigInteger[2];
            results[0] = new BigInteger(EArray);
            results[1] = new BigInteger(NArray);
            return results;
        }
    }

    /// <summary>
    /// Class used to store and manipulate the Private Key, mostly similar to the Key class but includes an email
    /// array and a method of adding emails to said array. getEN is also replaced with getDN
    /// </summary>
    public class PrivateKey
    {
        public String[] email { get; set; }
        public String key { get; set; }

        /// <summary>
        /// Constructor used when generating new keys.
        /// </summary>
        /// <param name="key"> The key to be stored in this object.</param>
        public PrivateKey(String key)
        {
            this.email = new String[1];
            email[0] = "temp";
            this.key = key;
        }

        /// <summary>
        /// A blank constructor with no parameters, used mostly for Json deserialize.
        /// </summary>
        public PrivateKey() { }

        /// <summary>
        /// Adds an email to the array of emails. Overwrites the temp value if it is the first email.
        /// </summary>
        /// <param name="email"> The email to add to the array.</param>
        public void addEmail(String email)
        {
            if (this.email[0].Equals("temp"))
            {
                //replace if there was no email here before
                this.email[0] = email;
            }
            else
            {
                //append an email
                String[] temp = new string[this.email.Length + 1];
                var count = 0;
                foreach (String em in this.email)
                {
                    //exit if email already exists
                    if (em.Equals(email))
                    {
                        return;
                    }
                    temp[count] = em;
                    count++;
                }
                temp[count] = email;
                this.email = temp;
            }
        }

        /// <summary>
        /// Parses through the key and extracts D and N from the key.
        /// </summary>
        /// <returns> BigInteger[] results. results[0] = D and results[1] = N.</returns>
        public BigInteger[] getDN()
        {
            var keyArray = Convert.FromBase64String(this.key);
            var sizeNArray = new byte[4];
            var sizeDArray = new byte[4];
            var index = 0;

            //extract D
            for (int i = 0; i < 4; i++)
            {
                sizeDArray[i] = keyArray[index];
                index++;
            }
            //size of E
            var size = (int)new BigInteger(sizeDArray);
            var DArray = new byte[size];
            for (int i = 0; i < size; i++)
            {
                DArray[i] = keyArray[index];
                index++;
            }
            //extract N
            for (int i = 0; i < 4; i++)
            {
                sizeNArray[i] = keyArray[index];
                index++;
            }
            //size of N
            size = (int)new BigInteger(sizeNArray);
            var NArray = new byte[size];
            for (int i = 0; i < size; i++)
            {
                NArray[i] = keyArray[index];
                index++;
            }


            BigInteger[] results = new BigInteger[2];
            results[0] = new BigInteger(DArray);
            results[1] = new BigInteger(NArray);
            return results;
        }



        /// <summary>
        /// Converts the key object to a json format then saves it as a file.
        /// </summary>
        /// <param name="path"> The command line arguments</param>
        public void writeFile(String path)
        {
            File.WriteAllText(path, JsonConvert.SerializeObject(this));
        }
    }

    /// <summary>
    /// Class used as a secure messenger. Can generate RSA keys, as well as send and recieve both keys and messages from a server.
    /// </summary>
    public class Messenger
    {
        static readonly HttpClient client = new HttpClient();

        /// <summary>
        /// The Main Function. Gets the command line arguments and vets them, then carries out the corresponding commands.
        /// </summary>
        /// <param name="args"> The command line arguments</param>
        public static void Main(string[] args)
        {
            //locations of keys
            var privatePath = "private.key";
            var publicPath = "public.key";
            //help message for user
            var helpMessage = "Usage:  dotnet run <option> <other arguments>\n" +
                              "Connect and send messages over a secure network.\n\n" +
                              "\t- option - the task that you wish the program to carry out.\n" +
                              "\t- other arguments - the other parameter for the program used by the task.\n\n" +
                              "All options and other arguments:\n" +
                              "\t- keyGen <keysize> - generates a keypair of size keysize bits, must be a multiple of 8.\n" +
                              "\t- sendKey <email> - sends the public key with the email to the server, server then stores both.\n" +
                              "\t- getKey <email> - gets the public key for the email given, needed for sending encoded messages.\n" +
                              "\t- sendMsg <email> <plaintext> - encrypts and sends the plaintext message to the email provided.\n" +
                              "\t- getMsg <email> - get the message for email, will not work if you do not have corresponding private key.\n";

            //check each command line argument
            //check keyGen
            if (args[0].Equals("keyGen"))
            {
                int keySize;
                //check command line arguments
                if (args.Length != 2)
                {
                    Console.WriteLine("Error: keyGen option has wrong number of arguments.");
                    Console.WriteLine(helpMessage);
                    return;
                }
                //check if keysize is an int
                if (!int.TryParse(args[1], out keySize))
                {
                    Console.WriteLine("Error: <keysize> must be an integer.");
                    Console.WriteLine(helpMessage);
                    return;
                }
                //ckeck if keysize is multiple of 8
                if (!(keySize % 8 == 0))
                {
                    Console.WriteLine("Error: <keysize> must be a multiple of 8.");
                    Console.WriteLine(helpMessage);
                    return;
                }

                //create a key
                createKey(keySize, publicPath, privatePath);
            }
            //check sendKey
            else if (args[0].Equals("sendKey"))
            {
                //check command line arguments
                if (args.Length != 2)
                {
                    Console.WriteLine("Error: sendKey option has wrong number of arguments.");
                    Console.WriteLine(helpMessage);
                    return;
                }

                //check that a public key has been generated
                if (!System.IO.File.Exists(publicPath))
                {
                    Console.WriteLine("Error: You have not generated a key yet, please use keyGen first.");
                    Console.WriteLine(helpMessage);
                    return;
                }
                var complete = updateKey(args[1]);
                //wait for async method to finish
                complete.Wait();
                Console.WriteLine("Key saved");
            }
            //check getKey
            else if (args[0].Equals("getKey"))
            {
                //check command line arguments
                if (args.Length != 2)
                {
                    Console.WriteLine("Error: getKey option has wrong number of arguments.");
                    Console.WriteLine(helpMessage);
                    return;
                }

                //ask for key from server
                var complete = askForKey(args[1]);
                //wait for async method to finish
                complete.Wait();

            }
            //check sendMsg
            else if (args[0].Equals("sendMsg"))
            {
                //check command line arguments
                if (args.Length != 3)
                {
                    Console.WriteLine("Error: sendMsg option has wrong number of arguments.");
                    Console.WriteLine(helpMessage);
                    return;
                }
                var email = args[1];
                //check that the key exists for the corresponding email.
                if (!System.IO.File.Exists(email + ".key"))
                {
                    Console.WriteLine("Key does not exist for " + email);
                    return;
                }

                //retrieve private key to check is we can decrypt messages from this email
                var pubString = File.ReadAllText(publicPath);
                var key = JsonConvert.DeserializeObject<Key>(pubString);

                //send message to server
                var complete = sendMessage(email, args[2]);
                //wait for async method to finish
                complete.Wait();
                Console.WriteLine("Message Written");
            }
            //check getMsg
            else if (args[0].Equals("getMsg"))
            {
                //check command line arguments
                if (args.Length != 2)
                {
                    Console.WriteLine("Error: getMsg option has wrong number of arguments.");
                    Console.WriteLine(helpMessage);
                    return;
                }
                var email = args[1];
                //check that the key exists for the corresponding email.
                if (!System.IO.File.Exists("private.key"))
                {
                    Console.WriteLine("Error: You do not have a private key, use keyGen first.");
                    Console.WriteLine(helpMessage);
                    return;
                }
                //retrieve private key to check is we can decrypt messages from this email
                var priString = File.ReadAllText(privatePath);
                var key = JsonConvert.DeserializeObject<PrivateKey>(priString);

                String[] emails = key.email;
                if (!emails.Contains(email))
                {
                    Console.WriteLine("Error: You do not have a key for this email.");
                    Console.WriteLine(helpMessage);
                    return;
                }
                
                //send message to server
                var complete = askForMessage(email);
                //wait for async method to finish
                complete.Wait();
            }
            //must be incorrect option
            else
            {
                Console.WriteLine("Error: option not recognised or not provided.");
                Console.WriteLine(helpMessage);
                return;
            }
        }


        /// <summary>
        /// Retrieves the encrypted message from the server with the corresponding email
        /// </summary>
        /// <param name="email"> The email you want the public key for.</param>
        static async Task askForMessage(String email)
        {
            try
            {
                //request the message
                using HttpResponseMessage response = await Messenger.client.GetAsync("http://kayrun.cs.rit.edu:5000/Message/" + email);
                response.EnsureSuccessStatusCode();
                string responseBody = await response.Content.ReadAsStringAsync();

                if (responseBody != null)
                {
                    //get private key
                    var priString = File.ReadAllText("private.key");
                    var key = JsonConvert.DeserializeObject<PrivateKey>(priString);

                    //get D and N
                    var nums = key.getDN();

                    //deserialize the json
                    Message message = JsonConvert.DeserializeObject<Message>(responseBody);
                    message.decrypt(nums[0], nums[1]);
                    Console.WriteLine(message.content);

                }
            }
            catch (ArgumentNullException e)
            {
                Console.WriteLine("the email (" + email + ") does not have any messages currently.");
            }

            return;
        }


        /// <summary>
        /// Sends the an encoded message to the server.
        /// </summary>
        /// <param name="email"> The email you are sending the message to.</param>
        /// <param name="message"> The message you want to send.</param>
        static async Task sendMessage(String email, String message)
        {
            try
            {
                //get public key for the email
                var pubString = File.ReadAllText(email + ".key");
                var key = JsonConvert.DeserializeObject<Key>(pubString);

                //get E and N
                var nums = key.getEN();

                //create message object
                var mess = new Message(email, message);

                //encrypt message
                mess.encrypt(nums[0], nums[1]);

                //request to send message
                var content = new StringContent(JsonConvert.SerializeObject(mess), Encoding.UTF8, "application/json");
                using HttpResponseMessage response = await Messenger.client.PutAsync("http://kayrun.cs.rit.edu:5000/Message/" + email, content);
                response.EnsureSuccessStatusCode();
                string responseBody = await response.Content.ReadAsStringAsync();

            }
            catch (Exception e)
            {
                //TODO
                Console.WriteLine("\nException Caught!");
                Console.WriteLine(e);
            }

            return;
        }


        /// <summary>
        /// Sends the public key stored on this computer to the server for other users to use and retrieve.
        /// </summary>
        /// <param name="email"> The email you are sending a key for.</param>
        static async Task updateKey(String email)
        {
            try
            {
                //update public key with email
                var pubString = File.ReadAllText("public.key");
                Key publicKey = JsonConvert.DeserializeObject<Key>(pubString);
                publicKey.email = email;
                publicKey.writeFile("public.key");

                //update private key
                var priString = File.ReadAllText("private.key");
                PrivateKey privateKey = JsonConvert.DeserializeObject<PrivateKey>(priString);
                privateKey.addEmail(email);
                privateKey.writeFile("private.key");


                //request to send key
                var content = new StringContent(JsonConvert.SerializeObject(publicKey), Encoding.UTF8, "application/json") ;
                using HttpResponseMessage response = await Messenger.client.PutAsync("http://kayrun.cs.rit.edu:5000/Key/" + email, content);
                response.EnsureSuccessStatusCode();
                string responseBody = await response.Content.ReadAsStringAsync();

            }
            catch (Exception e)
            {
                //TODO
                Console.WriteLine("\nException Caught!");
                Console.WriteLine("Message :{0} ", e.Message);
            }

            return;
        }



        /// <summary>
        /// Retrieves the public key of the email provided. When the key has been confirmed to have been retrieved
        /// a new file is created to store the key along with the email for future use.
        /// </summary>
        /// <param name="email"> The email you want the public key for.</param>
        static async Task askForKey(String email)
        {
            try
            {
                //request the key
                using HttpResponseMessage response = await Messenger.client.GetAsync("http://kayrun.cs.rit.edu:5000/Key/" + email);
                response.EnsureSuccessStatusCode();
                string responseBody = await response.Content.ReadAsStringAsync();

                if (responseBody != null)
                {
                    //deserialize the json
                    Key newKey = JsonConvert.DeserializeObject<Key>(responseBody);
                    //store public key
                    if(newKey == null)
                    {
                        Console.WriteLine("the email (" + email + ") does not seem to exist on the server\n" +
                                        "it could be a spelling mistake, or the email could just not exist.");
                        return;
                    }
                    newKey.writeFile(newKey.email + ".key");

                }
                else
                {
                    Console.WriteLine("the email (" + email + ") does not seem to exist on the server\n" +
                                        "it could be a spelling mistake, or the email could just not exist.");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("\nException Caught!");
                Console.WriteLine("Message :{0} ", e.Message);
            }

            return;
        }


        /// <summary>
        /// Creates both a public and private key used for encryption from the keySize recieved from the user. Uses the RSA algorithm to
        /// calculate all necassary components, then stores both the public and private keys in a storage folder for later use.
        /// </summary>
        /// <param name="keySize"> The length in bits of p and q combined.</param>
        /// <param name="publicPath"> The location to store the public key.</param>
        /// <param name="privatePath"> The location to store the private key.</param>
        static void createKey(int keySize, String publicPath, String privatePath)
        {
            var rand = new Random();
            
            // get + or -
            var modifier = rand.Next(0, 2);
            if (modifier == 0)
            {
                modifier--;
            }

            //find size of p
            var bits = keySize / 2 + (modifier) * (int)(rand.Next(20, 31) * keySize / 100);
            bits = bits - (bits % 8);
            //get p
            var p = PrimeGen.parallelPrime(bits);
            //get q
            var q = PrimeGen.parallelPrime(keySize - bits);
            //get N
            var N = p * q;
            //get r
            var r = (p - 1) * (q - 1);
            //get E
            var E = PrimeGen.parallelPrime(16);
            //get D
            var D = modInverse(E, r);

            //create variables
            var NSize = N.GetByteCount();
            var ESize = E.GetByteCount();
            var DSize = D.GetByteCount();
            byte[] NBytes = N.ToByteArray();
            byte[] EBytes = E.ToByteArray();
            byte[] DBytes = D.ToByteArray();
            

            //create byte arrays
            byte[] publicKey = new byte[8 + NSize + ESize];
            byte[] privateKey = new byte[8 + DSize + NSize];

            //make sizes into byte arrays
            byte[] NArray = BitConverter.GetBytes(NSize);
            byte[] EArray = BitConverter.GetBytes(ESize);
            byte[] DArray = BitConverter.GetBytes(DSize);

            var index = 0;
            //fill public key
            for (int i = 0; i < 4 - EArray.Length; i++)
            {
                publicKey[index] = 0;
                index++;
            }
            foreach (byte b in EArray)
            {
                publicKey[index] = b;
                index++;
            }
            //put E into array
            foreach (byte b in EBytes)
            {
                publicKey[index] = b;
                index++;
            }
            for (int i = 0; i < 4 - NArray.Length; i++)
            {
                publicKey[index] = 0;
                index++;
            }
            foreach (byte b in NArray)
            {
                publicKey[index] = b;
                index++;
            }
            //put N into array
            foreach (byte b in NBytes)
            {
                publicKey[index] = b;
                index++;
            }


            index = 0;
            //fill private key
            for (int i = 0; i < 4 - DArray.Length; i++)
            {
                privateKey[index] = 0;
                index++;
            }
            foreach (byte b in DArray)
            {
                privateKey[index] = b;
                index++;
            }
            //put D into array
            foreach (byte b in DBytes)
            {
                privateKey[index] = b;
                index++;
            }
            for (int i = 0; i < 4 - NArray.Length; i++)
            {
                privateKey[index] = 0;
                index++;
            }
            foreach (byte b in NArray)
            {
                privateKey[index] = b;
                index++;
            }
            //put N into array
            foreach (byte b in NBytes)
            {
                privateKey[index] = b;
                index++;
            }

            //Base64 Encoding
            var privateString = Convert.ToBase64String(privateKey);
            var publicString = Convert.ToBase64String(publicKey);

            //create key objects
            var pubKey = new Key(publicString);
            var priKey = new PrivateKey(privateString);


            //store keys in a file
            pubKey.writeFile("public.key");
            priKey.writeFile("private.key");
        }

        /// <summary>
        /// A mod inverse function to help in the creation of RSA keys.
        /// </summary>
        /// <param name="a"> A small prime number.</param>
        /// <param name="n"> (p-1) * (q-1), or r.</param>
        /// <returns> The modinverse of a.</returns>
        static BigInteger modInverse(BigInteger a, BigInteger n)
        {
            BigInteger i = n;
            BigInteger v = 0;
            BigInteger d = 1;
            while (a>0)
            {
                BigInteger t = i / a;
                BigInteger x = a;
                a = i % x;
                i = x;
                x = d;
                d = v - t * x;
                v = x;
            }
            v %= n;
            if (v < 0)
            {
                v = (v + n) % n;
            }
            return v;
        }
    }


}