package ProgramDecrypt;

import javax.crypto.*;
import java.security.AlgorithmParameters;
import java.security.PrivateKey;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.*;
import javax.crypto.spec.*;

public class ProgramDecrypt {
	
	static class Decrypt {
			
		  // Input - Symmetric key for Encryption. 
		  // Output - Symmetric Key for Decryption.
		  static public void AssymetricDecrypt( PrivateKey receiverAssymetricPrivateKey, byte[] keyExploited, int keySizeInbytes) throws Exception {
			  			  
			  byte[] keyEncrypted = new byte[128];
			  
			  FileInputStream keyfis = new FileInputStream("D:/shalev/MSC Computer Science - IDC/Courses/3536 - Building Secure Applications - Winter 2014-2015/Assignments-HomeWork/Hw5 - Programming Assignment/Answers/Inputs&Outputs/config_encryptedSymetricSharedKey.txt");
			  int i = keyfis.read(keyEncrypted);
			  keyfis.close();
			  
			  Cipher cipher = Cipher.getInstance("RSA", "SunJCE");
			  cipher.init(Cipher.DECRYPT_MODE, receiverAssymetricPrivateKey);
			  
			  byte[] keyExploitedTmp = cipher.doFinal(keyEncrypted);
			  
			  //System.arraycopy(source, 0, target, 0, source.length);
			  System.arraycopy(keyExploitedTmp, 0, keyExploited, 0, keySizeInbytes);
		  }
		  
		  // Output - plainText
		  static public void SymetricDecrypt( byte[] aesKeyData, AlgorithmParameters params) throws Exception {
			  			  
			  Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
			  SecretKeySpec key = new SecretKeySpec(aesKeyData, "AES");
			  cipher.init(Cipher.DECRYPT_MODE, key, params);
			  
			  String ciphertextFile = "D:/shalev/MSC Computer Science - IDC/Courses/3536 - Building Secure Applications - Winter 2014-2015/Assignments-HomeWork/Hw5 - Programming Assignment/Answers/Inputs&Outputs/ciphertextSymm.txt";
			  String plaintextFile = "D:/shalev/MSC Computer Science - IDC/Courses/3536 - Building Secure Applications - Winter 2014-2015/Assignments-HomeWork/Hw5 - Programming Assignment/Answers/Inputs&Outputs/plaintext_afterEncryptionAndDecryption.txt";
			   
			  FileInputStream fis = new FileInputStream(ciphertextFile);
			  CipherInputStream cis = new CipherInputStream(fis, cipher);
			  
			  FileOutputStream fos = new FileOutputStream(plaintextFile);
			  
			  byte[] block = new byte[8];
			  int i;
			  
			  while ((i = cis.read(block)) != -1) {
			  fos.write(block, 0, i);
			  }
			  
			  cis.close();
			  fis.close();
			  fos.close();
		  }
		  
		  static public boolean VerifyDigitalSignature( PublicKey pubKey ) throws Exception {
		
			  // Extract the signature to be verified from the configuration file
			  File digSigfile = new File("D:/shalev/MSC Computer Science - IDC/Courses/3536 - Building Secure Applications - Winter 2014-2015/Assignments-HomeWork/Hw5 - Programming Assignment/Answers/Inputs&Outputs/config_sig.txt");
			  FileInputStream digSigFis = new FileInputStream("D:/shalev/MSC Computer Science - IDC/Courses/3536 - Building Secure Applications - Winter 2014-2015/Assignments-HomeWork/Hw5 - Programming Assignment/Answers/Inputs&Outputs/config_sig.txt");
			  
			  byte sigToVerify[] = new byte[(int)digSigfile.length()];
			  int i = digSigFis.read(sigToVerify);
			  
			  digSigFis.close();
			  	  
			  // Prepare signature to be compared using pubKey
			  Signature sig = Signature.getInstance("SHA1withRSA");
			  sig.initVerify(pubKey);
			  
			  FileInputStream datafis = new FileInputStream("D:/shalev/MSC Computer Science - IDC/Courses/3536 - Building Secure Applications - Winter 2014-2015/Assignments-HomeWork/Hw5 - Programming Assignment/Answers/Inputs&Outputs/plaintext_afterEncryptionAndDecryption.txt");
			  BufferedInputStream bufin = new BufferedInputStream(datafis);

			  byte[] buffer = new byte[1024];
			  int len;
			  while (bufin.available() != 0) {
			      len = bufin.read(buffer);
			      sig.update(buffer, 0, len);
			  };

			  bufin.close();

			  // Verify Signature.
			  boolean verifies = sig.verify(sigToVerify);
			  
			  return verifies;

		  }
		  
		  static public byte[] ReadIVSpecBytesFromFile() throws Exception {
			  byte[] ivSpecBytes = new byte[16];
			  FileInputStream sigfos = new FileInputStream("D:/shalev/MSC Computer Science - IDC/Courses/3536 - Building Secure Applications - Winter 2014-2015/Assignments-HomeWork/Hw5 - Programming Assignment/Answers/Inputs&Outputs/config_IVparams.txt");
			  sigfos.read(ivSpecBytes);
			  sigfos.close();
			  
			  return ivSpecBytes;
		  }
		
	}
	
	  public static void main(String[] args) throws Exception 
	  {  
		  
		  System.out.println("Starting Decrypt App");
		  
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////						Receiver Side - Decryption Side                           //////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////

		  
		/************* Extract receiver private key and sender public key from the key store ***************/  
		  
		  // Initialization of first key store.
		  String secondkeyStoreFilename = "C:/Program Files (x86)/Java/jre7/bin/SecondSideStore.jks";
		  FileInputStream finSecond = new FileInputStream(secondkeyStoreFilename);
		  KeyStore secondSidekeyStore = KeyStore.getInstance("JKS");
		  	  
		  // Extracting Second Side Public Key (pub1) from the trusted certificate.
		  String alias_trustedcrtSecond = "firstsidetrustedcrt";
		  secondSidekeyStore.load(finSecond, args[0].toCharArray());
		  Certificate trustedCertificateSecond = secondSidekeyStore.getCertificate(alias_trustedcrtSecond);		  
		  PublicKey pub1 = trustedCertificateSecond.getPublicKey(); //pub1
		  
		  // Extracting First Side Private Key (priv2) from the trusted certificate.
		  String alias_privKeySecond = "secondside";  
		  PrivateKey priv2 = (PrivateKey) secondSidekeyStore.getKey(alias_privKeySecond, args[0].toCharArray()); // priv2

		  
		/************* Decrypt config_encryptedSymetricSharedKey.txt using Asymmetric Crypto - with own Private key (which is now publicKey1) ***************/ 
		  
		  byte[] aeskeyDataExtracted = new byte[16];  // 16 bytes for 128bit AesKeySize
		  Decrypt.AssymetricDecrypt(priv2, aeskeyDataExtracted, aeskeyDataExtracted.length);
		  
		  
		/************* Decrypt ciphet Text using the Symmetric key (output is the plainText). ***************/ 
		  
		  // Extract params from file
		  byte[] ivSpecBytes2 = Decrypt.ReadIVSpecBytesFromFile();
		  AlgorithmParameters  params2 = AlgorithmParameters.getInstance("AES");
		  IvParameterSpec ivSpec2 = new IvParameterSpec(ivSpecBytes2); 		  
		  params2.init(ivSpec2);
		  // Decrypt cipherTestSymm using SymmetricKey aeskeyDataExtracted and IV.
		  Decrypt.SymetricDecrypt(aeskeyDataExtracted, params2);
		  
		  
		/*************  Verifying Digital Signature ***************/
		  
		  if (Decrypt.VerifyDigitalSignature(pub1) == true)
		  {
			  System.out.println("Digital Signature match!");
		  }
		  else
		  {
			  System.out.println("Digital Signature does not match");
		  }
		   
	  }  
}
