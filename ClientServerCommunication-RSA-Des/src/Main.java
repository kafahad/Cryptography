


public class Main {

	public static void main(String[] args)throws Exception 
	{
		
		String clientMSG = "Client MSG -> In the development of DES, NSA convinced IBM that a reduced key size was sufficient; "
				+ "indirectly assisted in the development of the S-box structures; and certified that the final DES algorithm was, "
				+ "to the best of their knowledge, free from any statistical or mathematical weakness.";
		
		String serverMSG = "Server MSG -> NSA worked closely with IBM to strengthen the algorithm against all except brute force attacks and "
				+ "to strengthen substitution tables, called S-boxes. Conversely, "
				+ "NSA tried to convince IBM to reduce the length of the key from 64 to 48 bits. Ultimately they compromised on a 56-bit key.";
		
		CommunicationEngine svrOne = new CommunicationEngine(true);
		CommunicationEngine clientOne = new CommunicationEngine(false);
		
		// Sharing clients DES secret code in RSA mode with server
		byte[] temMsg = clientOne.sendMSG(clientOne.getSecretKey(), false,svrOne.getPublicKey());
		System.out.println("\n **DES-SEC-KEY decrypted in SVR (sent from client ) **");
		svrOne.receiveMSG(temMsg, true, false);
		
		//After share the clients secret key, now send msg Client -> Server using DES
		byte[] symClMSG = clientOne.sendMSG(clientMSG.getBytes(), true, null);
		System.out.println("\n **MSG decrypted in SVR (sent from client) **");
		svrOne.receiveMSG(symClMSG, false, false);
		
		//Server send MSG -> Client using DES/Secret key cryptography
		byte[] symSvMSG = svrOne.sendMSG(serverMSG.getBytes(), true, null);
		System.out.println("\n **MSG decrypted in client (sent from server) **");
		clientOne.receiveMSG(symSvMSG, false, false);
	}
	
	
	  

}
