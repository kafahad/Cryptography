import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;


public class Symmetric {

	private static byte[] iv =   { 0x0a, 0x01, 0x02, 0x03, 0x04, 0x0b, 0x0c, 0x0d };
	private static SecretKey secKey;
	public static String cryptType = "DES/CBC/PKCS5Padding";

	/**
	 * @param generateKey
	 */
	public Symmetric(boolean generateKey)
	{
		try
		{
			KeyGenerator kg = KeyGenerator.getInstance("DES");
			kg.init(56); // 56 is the keysize. Fixed for DES
			if(generateKey)
			{
				secKey = kg.generateKey();
				System.out.println("DES private key: "+secKey.toString());
			}
		} 
		catch(Exception ex)
		{

		}
	}


	/**
	 * @param inpBytes
	 * @param key
	 * @param xform
	 * @return
	 * @throws Exception
	 */
	private static byte[] encrypt(byte[] inpBytes, SecretKey key, String xform) throws Exception {
		System.out.println("@@ DES Encrypting @@");
		Cipher cipher = Cipher.getInstance(xform);
		IvParameterSpec ips = new IvParameterSpec(iv);
		cipher.init(Cipher.ENCRYPT_MODE, key, ips);		
		return cipher.doFinal(inpBytes);
	}


	/**
	 * @param inpBytes
	 * @param key
	 * @param xform
	 * @return
	 * @throws Exception
	 */
	private static byte[] decrypt(byte[] inpBytes,  SecretKey key, String xform) throws Exception {
		System.out.println("@@ DES Decrypting @@");
		System.out.println("Des sec key: "+key.toString());
		Cipher cipher = Cipher.getInstance(xform);
		IvParameterSpec ips = new IvParameterSpec(iv);
		cipher.init(Cipher.DECRYPT_MODE, key, ips);
		return cipher.doFinal(inpBytes);
	}

	/**
	 * @param msg
	 * @param clientSecKey
	 * @return
	 * @throws Exception
	 */
	public byte[] encryptMSG (byte[] msg, SecretKey clientSecKey) throws Exception
	{
		byte[] encBytes = null;
		if(clientSecKey == null)
		{
			encBytes = encrypt(msg, secKey, cryptType);
		}
		else
		{
			encBytes = encrypt(msg, clientSecKey, cryptType);
		}
		return encBytes;
	}


	/**
	 * @param encodedByte
	 * @param clientSecKey
	 * @return
	 * @throws Exception
	 */
	public byte[] decryptMSG(byte[] encodedByte, SecretKey clientSecKey) throws Exception
	{
		byte[] decBytes; 		
		if(clientSecKey == null)
		{
			decBytes = decrypt(encodedByte, secKey, cryptType);
		}
		else
		{
			decBytes = decrypt(encodedByte, clientSecKey, cryptType);
		}
		return decBytes;
	}

	/**
	 * @return
	 */
	public SecretKey getSecretKey()
	{
		return secKey;
	}


}
