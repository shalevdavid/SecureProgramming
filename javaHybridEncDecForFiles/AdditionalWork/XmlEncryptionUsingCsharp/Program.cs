﻿using System;
using System.Xml;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;


namespace CSCrypto
{
    class Program
    {
        static void Main(string[] args)
        {
            RijndaelManaged key = null;

            try
            {
                // Create a new Rijndael key.
                key = new RijndaelManaged();
                // Load an XML document.
                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Load(@"D:\shalev\Projects\Workspace\SecureProgrammingTrainingCsharp\test.xml");

                // Encrypt the "creditcard" element.
                EncryptContent(xmlDoc, "creditcard", key);

                Console.WriteLine("The element was encrypted");

                Console.WriteLine(xmlDoc.InnerXml);

                xmlDoc.Save(@"D:\shalev\Projects\Workspace\SecureProgrammingTrainingCsharp\testEncryptedContent.xml");

                //////////////////////////////////////////

                XmlDocument xmlDoc2 = new XmlDocument();
                xmlDoc2.PreserveWhitespace = true;
                xmlDoc2.Load(@"D:\shalev\Projects\Workspace\SecureProgrammingTrainingCsharp\testEncrypted.xml");

                Decrypt(xmlDoc2, key);

                Console.WriteLine("The element was decrypted");

                Console.WriteLine(xmlDoc2.InnerXml);

            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            finally
            {
                // Clear the key. 
                if (key != null)
                {
                    key.Clear();
                }
            }

        }

        public static void Encrypt(XmlDocument Doc, string ElementName, SymmetricAlgorithm Key)
        {
            // Check the arguments.   
            if (Doc == null)
                throw new ArgumentNullException("Doc");
            if (ElementName == null)
                throw new ArgumentNullException("ElementToEncrypt");
            if (Key == null)
                throw new ArgumentNullException("Alg");

            //////////////////////////////////////////////// 
            // Find the specified element in the XmlDocument 
            // object and create a new XmlElemnt object. 
            ////////////////////////////////////////////////
            XmlElement elementToEncrypt = Doc.GetElementsByTagName(ElementName)[0] as XmlElement;
            // Throw an XmlException if the element was not found. 
            if (elementToEncrypt == null)
            {
                throw new XmlException("The specified element was not found");
            }

            ////////////////////////////////////////////////// 
            // Create a new instance of the EncryptedXml class  
            // and use it to encrypt the XmlElement with the  
            // symmetric key. 
            //////////////////////////////////////////////////

            EncryptedXml eXml = new EncryptedXml();

            byte[] encryptedElement = eXml.EncryptData(elementToEncrypt, Key, false);
            //////////////////////////////////////////////// 
            // Construct an EncryptedData object and populate 
            // it with the desired encryption information. 
            ////////////////////////////////////////////////

            EncryptedData edElement = new EncryptedData();
            edElement.Type = EncryptedXml.XmlEncElementUrl;

            // Create an EncryptionMethod element so that the  
            // receiver knows which algorithm to use for decryption. 
            // Determine what kind of algorithm is being used and 
            // supply the appropriate URL to the EncryptionMethod element. 

            string encryptionMethod = null;

            if (Key is TripleDES)
            {
                encryptionMethod = EncryptedXml.XmlEncTripleDESUrl;
            }
            else if (Key is DES)
            {
                encryptionMethod = EncryptedXml.XmlEncDESUrl;
            }
            if (Key is Rijndael)
            {
                switch (Key.KeySize)
                {
                    case 128:
                        encryptionMethod = EncryptedXml.XmlEncAES128Url;
                        break;
                    case 192:
                        encryptionMethod = EncryptedXml.XmlEncAES192Url;
                        break;
                    case 256:
                        encryptionMethod = EncryptedXml.XmlEncAES256Url;
                        break;
                }
            }
            else
            {
                // Throw an exception if the transform is not in the previous categories 
                throw new CryptographicException("The specified algorithm is not supported for XML Encryption.");
            }

            edElement.EncryptionMethod = new EncryptionMethod(encryptionMethod);

            // Add the encrypted element data to the  
            // EncryptedData object.
            edElement.CipherData.CipherValue = encryptedElement;

            //////////////////////////////////////////////////// 
            // Replace the element from the original XmlDocument 
            // object with the EncryptedData element. 
            ////////////////////////////////////////////////////
            EncryptedXml.ReplaceElement(elementToEncrypt, edElement, false);
        }

        public static void Decrypt(XmlDocument Doc, SymmetricAlgorithm Alg)
        {
            // Check the arguments.   
            if (Doc == null)
                throw new ArgumentNullException("Doc");
            if (Alg == null)
                throw new ArgumentNullException("Alg");

            // Find the EncryptedData element in the XmlDocument.
            XmlElement encryptedElement = Doc.GetElementsByTagName("EncryptedData")[0] as XmlElement;

            // If the EncryptedData element was not found, throw an exception. 
            if (encryptedElement == null)
            {
                throw new XmlException("The EncryptedData element was not found.");
            }

            // Create an EncryptedData object and populate it.
            EncryptedData edElement = new EncryptedData();
            edElement.LoadXml(encryptedElement);

            // Create a new EncryptedXml object.
            EncryptedXml exml = new EncryptedXml();

            // Decrypt the element using the symmetric key. 
            byte[] rgbOutput = exml.DecryptData(edElement, Alg);

            // Replace the encryptedData element with the plaintext XML element.
            exml.ReplaceData(encryptedElement, rgbOutput);

        }

        public static void EncryptContent(XmlDocument Doc, string ElementName, SymmetricAlgorithm Key)
        {
            // Check the arguments.   
            if (Doc == null)
                throw new ArgumentNullException("Doc");
            if (ElementName == null)
                throw new ArgumentNullException("ElementToEncrypt");
            if (Key == null)
                throw new ArgumentNullException("Alg");

            //////////////////////////////////////////////// 
            // Find the specified element in the XmlDocument 
            // object and create a new XmlElemnt object. 
            ////////////////////////////////////////////////
            XmlElement elementToEncrypt = Doc.GetElementsByTagName(ElementName)[0] as XmlElement;
            // Throw an XmlException if the element was not found. 
            if (elementToEncrypt == null)
            {
                throw new XmlException("The specified element was not found");
            }

            ////////////////////////////////////////////////// 
            // Create a new instance of the EncryptedXml class  
            // and use it to encrypt the XmlElement with the  
            // symmetric key. 
            //////////////////////////////////////////////////

            EncryptedXml eXml = new EncryptedXml();

            byte[] encryptedElement = eXml.EncryptData(elementToEncrypt, Key, false);
            //////////////////////////////////////////////// 
            // Construct an EncryptedData object and populate 
            // it with the desired encryption information. 
            ////////////////////////////////////////////////

            EncryptedData edElement = new EncryptedData();
            edElement.Type = EncryptedXml.XmlEncElementUrl;

            // Create an EncryptionMethod element so that the  
            // receiver knows which algorithm to use for decryption. 
            // Determine what kind of algorithm is being used and 
            // supply the appropriate URL to the EncryptionMethod element. 

            string encryptionMethod = null;

            if (Key is TripleDES)
            {
                encryptionMethod = EncryptedXml.XmlEncTripleDESUrl;
            }
            else if (Key is DES)
            {
                encryptionMethod = EncryptedXml.XmlEncDESUrl;
            }
            if (Key is Rijndael)
            {
                switch (Key.KeySize)
                {
                    case 128:
                        encryptionMethod = EncryptedXml.XmlEncAES128Url;
                        break;
                    case 192:
                        encryptionMethod = EncryptedXml.XmlEncAES192Url;
                        break;
                    case 256:
                        encryptionMethod = EncryptedXml.XmlEncAES256Url;
                        break;
                }
            }
            else
            {
                // Throw an exception if the transform is not in the previous categories 
                throw new CryptographicException("The specified algorithm is not supported for XML Encryption.");
            }

            edElement.EncryptionMethod = new EncryptionMethod(encryptionMethod);

            // Add the encrypted element data to the  
            // EncryptedData object.
            edElement.CipherData.CipherValue = encryptedElement;

            //////////////////////////////////////////////////// 
            // Replace the element from the original XmlDocument 
            // object with the EncryptedData element. 
            ////////////////////////////////////////////////////
            EncryptedXml.ReplaceElement(elementToEncrypt, edElement, true);
        }

    }

}

