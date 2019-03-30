package ProgramEncrypt;

import javax.crypto.*;
import java.security.AlgorithmParameters;
import java.security.PrivateKey;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.*;
import javax.crypto.spec.*;

public class ProgramEncrypt {
	
	static class Encrypt {

		  static public byte[] CreateRandomKeyData() throws Exception {
			  
			  SecureRandom random1 = SecureRandom.getInstance("SHA1PRNG");
			  byte[] aesKeyData = random1.generateSeed(16);
			  
			  return aesKeyData;
		  }
		
		  // Output - receiverAssymetricPublicKey encrypted and saved to file.
		  static public void AssymetricEncrypt( PublicKey receiverAssymetricPublicKey, byte[] aesKeyData) throws Exception {
			  
			  Cipher cipher = Cipher.getInstance("RSA", "SunJCE");
			  cipher.init(Cipher.ENCRYPT_MODE, receiverAssymetricPublicKey);
			  
			  byte[] encryptedKey = cipher.doFinal(aesKeyData);
			  
			  FileOutputStream keyfos = new FileOutputStream("D:/shalev/MSC Computer Science - IDC/Courses/3536 - Building Secure Applications - Winter 2014-2015/Assignments-HomeWork/Hw5 - Programming Assignment/Answers/Inputs&Outputs/config_encryptedSymetricSharedKey.txt");
			  keyfos.write(encryptedKey);
			  keyfos.close();
			    
			  return;
		  }
		
		  // Output - cipherText
		  static public void SymetricEncrypt( byte[] aesKeyData, AlgorithmParameters params ) throws Exception {
			 
			  Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
			  SecretKeySpec key = new SecretKeySpec(aesKeyData, "AES");
			  cipher.init(Cipher.ENCRYPT_MODE, key, params);
			  
			  String plaintextFile = "D:/shalev/MSC Computer Science - IDC/Courses/3536 - Building Secure Applications - Winter 2014-2015/Assignments-HomeWork/Hw5 - Programming Assignment/Answers/Inputs&Outputs/plaintext.txt";
			  String ciphertextFile = "D:/shalev/MSC Computer Science - IDC/Courses/3536 - Building Secure Applications - Winter 2014-2015/Assignments-HomeWork/Hw5 - Programming Assignment/Answers/Inputs&Outputs/ciphertextSymm.txt";
			   
			  FileInputStream fis = new FileInputStream(plaintextFile);
			  FileOutputStream fos = new FileOutputStream(ciphertextFile);
			  CipherOutputStream cos = new CipherOutputStream(fos, cipher);
			  
			  byte[] block = new byte[8];
			  int i;
			  
			  while ((i = fis.read(block)) != -1) {
			  cos.write(block, 0, i);
			  }
			  
			  cos.close();
			  fis.close();
			  fos.close();
			  
		  }
		  
		  static public void DigitalSignature(PrivateKey priv) throws Exception {
			  
			  Signature rsa = Signature.getInstance("SHA1withRSA");
			  rsa.initSign(priv);
			  
			  FileInputStream fis = new FileInputStream("D:/shalev/MSC Computer Science - IDC/Courses/3536 - Building Secure Applications - Winter 2014-2015/Assignments-HomeWork/Hw5 - Programming Assignment/Answers/Inputs&Outputs/plaintext.txt");
			  BufferedInputStream bufin = new BufferedInputStream(fis);
			  byte[] buffer = new byte[1024];
			  int len;
			  while ((len = bufin.read(buffer)) >= 0) {
			      rsa.update(buffer, 0, len);
			  };
			  bufin.close();
			  			  
			  byte[] realSig = rsa.sign();
			  
			  /* save the signature to a file */
			  FileOutputStream sigfos = new FileOutputStream("D:/shalev/MSC Computer Science - IDC/Courses/3536 - Building Secure Applications - Winter 2014-2015/Assignments-HomeWork/Hw5 - Programming Assignment/Answers/Inputs&Outputs/config_sig.txt");
			  sigfos.write(realSig);
			  sigfos.close();

		  }
		  
		  // Saving the IV specification to File for later construction at Decryption.
		  static public void SaveIVSpecBytesToFile(byte[] ivSpecBytes) throws Exception {
			  FileOutputStream sigfos = new FileOutputStream("D:/shalev/MSC Computer Science - IDC/Courses/3536 - Building Secure Applications - Winter 2014-2015/Assignments-HomeWork/Hw5 - Programming Assignment/Answers/Inputs&Outputs/config_IVparams.txt");
			  sigfos.write(ivSpecBytes);
			  sigfos.close();
		  }
		  
	}
	
	  public static void main(String[] args) throws Exception 
	  {  
		  
		  System.out.println("Starting Encrypt App");
		

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////						Sender Side - Encryption Side                           //////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////

		/************* Extract sender private key and receiver public key from the key store ***************/
		  
		  // Initialization of first key store.
		  String keyStoreFilename = "C:/Program Files (x86)/Java/jre7/bin/FirstSideStore.jks";
		  FileInputStream fin = new FileInputStream(keyStoreFilename);
		  KeyStore firstSidekeyStore = KeyStore.getInstance("JKS");
		  		  
		  // Extracting Second Side Public Key (pub2) from the trusted certificate.
		  String alias_trustedcrt = "secondsidetrustedcrt";
		  firstSidekeyStore.load(fin, args[0].toCharArray());
		  Certificate trustedCertificate = firstSidekeyStore.getCertificate(alias_trustedcrt);		  
		  PublicKey pub2 = trustedCertificate.getPublicKey(); //pub2
		  
		  // Extracting First Side Private Key (priv1) from the trusted certificate.
		  String alias_privKey = "firstside";  
		  PrivateKey priv1 = (PrivateKey) firstSidekeyStore.getKey(alias_privKey, args[0].toCharArray()); // priv1		 
		  
		  
		/************* Create symmetric key data (Secret Key data). *************/
		  
		  byte[] aesKeyData =  Encrypt.CreateRandomKeyData(); // For Data File Encryption.
		
		  
		/************* Encrypt plain Text using Symmetric Key cryptography. **************/
		  
		  // Create Algorithm Parameters for AES Encryption. 
		  AlgorithmParameters  params = AlgorithmParameters.getInstance("AES");
		  SecureRandom random1 = SecureRandom.getInstance("SHA1PRNG");
		  IvParameterSpec ivSpec = new IvParameterSpec(random1.generateSeed(16)); 		  
		  params.init(ivSpec);
		  byte[] ivSpecBytes = ivSpec.getIV();
		  
		  // Save Parameters(IV) to configuration file.
		  Encrypt.SaveIVSpecBytesToFile(ivSpecBytes);
		  				  
		  // Encrypt plain Text using Symmetric Key cryptography.		  
		  Encrypt.SymetricEncrypt(aesKeyData, params);
		  
		  
		/************* Sign plainText - signing is with own Asymmetric key. **************/
		  
		  Encrypt.DigitalSignature(priv1);
		  
		  
		/************* Encrypt Symmetric Key using Asymmetric Encryption. **************/
		  
		  Encrypt.AssymetricEncrypt(pub2, aesKeyData);

		  System.out.println("Encryption was successful");
		   
	  }  
}
