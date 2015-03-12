import java.security.PublicKey;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class CommunicationEngine {

	private SecretKey desSecretKey = null ;
	private Asymmetric rsaEngine;
	private Symmetric desEngine;

	/**
	 * @param enableAsymetricComm Initiate communication engine by enabeling Asymmetric/Symmetric mode
	 */
	public CommunicationEngine(boolean enableAsymetricComm)
	{
		if(enableAsymetricComm)
		{
			rsaEngine = new Asymmetric(true);
			desEngine = new Symmetric(false);
		}
		else
		{
			rsaEngine = new Asymmetric(false);
			desEngine = new Symmetric(true);
		}
	}

	
	/**
	 * @param msg message data in byte format
	 * @param isSymetric allow Symetric operation or not
	 * @param pubKey public key for asymetric communication purpose cant be NULL
	 * @return return encrypted msg in byte array form
	 */
	public byte[] sendMSG(byte[] msg, boolean isSymetric, PublicKey pubKey) 
	{
		byte[] encrptedMsgByte  = null;
		try
		{
			if(isSymetric)
			{
				encrptedMsgByte = desEngine.encryptMSG(msg, desSecretKey);
			}
			else
			{
				encrptedMsgByte = rsaEngine.encryptMSG(msg, pubKey);
			}

		} catch(Exception ex)
		{
			System.out.println(ex.toString());
		}
		return encrptedMsgByte;
	}


	/**
	 * @param encrptedMsgByte encrypted message in byte form
	 * @param iskey whether cncrypted message contain in key information or not
	 * @param isAsymetric decryption mode (Asymetric/symetric)	 
	 */
	public void receiveMSG(byte[] encrptedMsgByte,boolean iskey, boolean isAsymetric)
	{
		try
		{
			if(iskey)
			{
				System.out.println("< Receive MSG with Key>");
				byte[] encryptedMsg = rsaEngine.decryptMSG(encrptedMsgByte);
				desSecretKey = new SecretKeySpec(encryptedMsg,0,encryptedMsg.length,"DES");
				System.out.println("Received DES PV key: "+desSecretKey.toString());
			}
			else if(isAsymetric)
			{
				byte[] deCryptedMsg = rsaEngine.decryptMSG(encrptedMsgByte);
				System.out.println("After Asymetric decryption: "+new String(deCryptedMsg));
			}
			else //Symetric communication
			{
				byte[] deCryptedMsg = desEngine.decryptMSG(encrptedMsgByte,desSecretKey);
				System.out.println("After symetric decryption: "+new String(deCryptedMsg));
			}
		}catch(Exception ex)
		{
			System.out.println(ex.toString());
		}
	}


	/**
	 * @return secret key while communicating in symmetric mode (DES)
	 */
	public byte[] getSecretKey()
	{
		return desEngine.getSecretKey().getEncoded();
	}

	/**
	 * @return public key while communicating in asymmetric mode (RSA)
	 */
	public PublicKey getPublicKey()
	{
		return rsaEngine.getRSApublickey();
	}
}
