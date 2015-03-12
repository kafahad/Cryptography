import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;


public class Asymmetric 
{
	private PublicKey rsaPublicKey = null;
	private PrivateKey	rsaPrivateKey = null;
	private String cryptType = "RSA/ECB/PKCS1PADDING";


	/**
	 * Will initiate Asymmetric class for RSA communication purpose
	 * @param generateKey whether generate public & private key
	 */
	public  Asymmetric(boolean generateKey) 
	{
		try
		{			
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(512); // 512 is the keysize.
			if(generateKey)
			{				
				KeyPair kp = kpg.generateKeyPair();
				rsaPublicKey = kp.getPublic();
				rsaPrivateKey = kp.getPrivate();				
				System.out.println("RSA Private Key: "+rsaPrivateKey.toString());
			}
		} 
		catch(Exception ex)
		{
			System.out.println("Exception: "+ex.toString());
		}		
	}



	// Private operation
	/**
	 * @param inpBytes msg in byte array for encryption purpose
	 * @param pubkey public key to encrypt a msg
	 * @return encrypted msg in byte array
	 * @throws Exception
	 */
	private byte[] encrypt(byte[] inpBytes, PublicKey pubkey) throws Exception 
	{
		System.out.println("~~ Encrypt RSA ~~");
		Cipher cipher = Cipher.getInstance(cryptType);
		cipher.init(Cipher.ENCRYPT_MODE, pubkey);
		return cipher.doFinal(inpBytes);
	}


	/**
	 * @param inpBytes Encrypted msg in byte array format
	 * @param pvtkey RSA private key for decryption
	 * @return Decrypted msg in byte array format
	 * @throws Exception
	 */
	private byte[] decrypt(byte[] inpBytes, PrivateKey pvtkey) throws Exception
	{
		System.out.println("~~ Decrypt RSA ~~");
		Cipher cipher = Cipher.getInstance(cryptType);
		cipher.init(Cipher.DECRYPT_MODE, pvtkey);
		return cipher.doFinal(inpBytes);
	}	

	// Public operation
	/**
	 * @return publish public key for RSA asymmetric communication purpose
	 */
	public PublicKey getRSApublickey()
	{
		return rsaPublicKey;
	} 

	/**
	 * @param msg in byte array for RSA asymmetric encryption purpose
	 * @param pubKey public key for encrypting msg
	 * @return encrypted msg in byte array
	 * @throws Exception
	 */
	public byte[] encryptMSG(byte[] dataBytes, PublicKey pubKey) throws Exception
	{		
		byte[] encBytes = encrypt(dataBytes, pubKey);	 	   
		return encBytes;
	}

	/**
	 * @param encBytes Encrypted msg in byte array format for RSA asymmetric decryption 
	 * @return decrypted msg by RSA
	 * @throws Exception
	 */
	public byte[] decryptMSG(byte[] encBytes) throws Exception
	{
		System.out.println("~~ RSA Decrypting ~~");
		System.out.println("RSA Private Key: "+rsaPrivateKey.toString());
		byte[] decryptedBytes = decrypt(encBytes, rsaPrivateKey);	    
		return decryptedBytes;

	}	

}
