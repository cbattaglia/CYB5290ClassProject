
/*
 * Important!
 * For sake of simplicity in the Server-Client aspect of this program,
 * the port number is hard coded into both the Client and Server.
 * As the essence of this project is to demonstrate our knowledge of PKI.
 */
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class Server implements Runnable {
	private static String Spriv = "Spriv";
	public static String Spub = "Spub";
	static PKI pkiServ = new PKI(Spub, Spriv);
	private static Map<Integer, Integer> accounts = new HashMap<Integer, Integer>();
	private ServerSocket server = null;
	private Thread thread = null;
	private ServerThread client = null;
	private int clientCount = 0;
	private ServerThread clients[] = new ServerThread[50];
	private String accountNo = "";
	private int clibalance = 0;
	private PublicKey Cpub;
	public static int port = 9000;
	
	public Server(int port) {
		try {
			System.out.println("Binding port "+port+", please wait...");
			server = new ServerSocket(port);
			System.out.println("Server start: "+server);
			start();
		} catch(IOException e) {
			System.out.println(e);
		}
	}
	
	public Server() {
	}
	

	public void run() {
		while(thread != null) {
			try {
				System.out.println("Waiting for a client...");
				addThread(server.accept());
			} catch(IOException e) {
				System.out.println("Acceptance Error: "+e);
			}
		}
	}
	
	private int findClient(int ID) {
		for(int i = 0; i < clientCount; i++) {
			if(clients[i].getID() == ID) {
				return i;
			}
		}
		return -1;
	}
	private int request(int accountNo) {
		int balance = 0;
		if(accounts.get(accountNo) != null) {
			balance = accounts.get(accountNo);
		} else {
			return -1;
		}
		return balance;
	}
	public synchronized void handle(int ID, String input) {
		String keylength, M1, M2, key, signature, HashedMsg = "", decryptSig = "";
		String[] byteValues, byteValuesSig;
		byte[] CpubBytes, SigBytes, M3 = null;
		boolean result = false;
		
		if(input.equals(".bye")) {
			clients[findClient(ID)].send(".bye");
			remove(ID);
		} else {
			/*
			 * Once the server sees that the sent message starts with REQUEST_BALANCE 
			 * we assume a few things.
			 * First: The message sent, as specified in the client application is REQUEST_BALANCE, (accountNo)[lengthOfClientKey]
			 * with this knowledge, we divide up the string based on the length of the Client Key to get all other information needed
			 */
			if(input.startsWith("REQUEST_BALANCE")) { 
				accountNo = input.substring(17,18);
				clibalance = request(Integer.parseInt(accountNo));
				if(clibalance == -1) {
					clients[findClient(ID)].send("Server: "+accountNo+" is not a valid account No.");
				}
				keylength = input.substring(18,22);
				M1 = input.substring(0, 21+Integer.parseInt(keylength)+1);
				key = input.substring(22, 22+Integer.parseInt(keylength));
				signature = input.substring(22+Integer.parseInt(keylength));
				
				//Display receveid msg to Server Console
				System.out.println("Server: Received from Client, plaintext message -> "+input.substring(0, 18));
				System.out.println("Server: Received from Client, keylength of encoded key -> "+input.substring(18,22));
				System.out.println("Server: Received from Client, encoded Client Public Key -> "+input.substring(22, 22+Integer.parseInt(keylength)));
				System.out.println("Server: Received from Client, signature -> "+input.substring(22+Integer.parseInt(keylength)));
				//Get Client Pub key
				/*
				 * As the client key is first encoded to be sent, these steps
				 * bring back the data to its original sent byte array so that it may be newly generated
				 * using the X509EncodedKeySpec to recreate it.
				 */
				byteValues = key.substring(0, key.length()-1).split(",");
				CpubBytes = new byte[byteValues.length];
				for(int i = 0; i < CpubBytes.length; i++) {
					CpubBytes[i] = Byte.valueOf(byteValues[i].trim());
				}
				KeyFactory kf = null;
				try {
					kf = KeyFactory.getInstance("RSA");
				} catch (NoSuchAlgorithmException e) {
					e.printStackTrace();
				}
				EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(CpubBytes);
				try {
					Cpub = kf.generatePublic(pubKeySpec);
				} catch (InvalidKeySpecException e) {
					e.printStackTrace();
				}
				
				//Verfiy it came from the Client
				/*
				 * As the encoded hash message from the client is encrypted
				 * it is a byte[] array. We need to get it back to its original byte array
				 * before we can compare.
				 */
				byteValuesSig = signature.substring(0, signature.length()-1).split(",");
				SigBytes = new byte[byteValuesSig.length];
				for(int i = 0; i < SigBytes.length; i++) {
					SigBytes[i] = Byte.valueOf(byteValuesSig[i].trim());
				}
				
				try {
					HashedMsg = pkiServ.sha1(M1);
				} catch (NoSuchAlgorithmException e1) {
					e1.printStackTrace();
				}
				try {
					decryptSig = pkiServ.decrpytwithPub(SigBytes, Cpub);
				} catch (IOException e1) {
					e1.printStackTrace();
				}
				String[] decryptSigValues = decryptSig.substring(0, decryptSig.length()-1).split(",");
				String finaldecrypt = "";
				byte[] decrypted = new byte[decryptSigValues.length];
				for(int i = 0; i < decrypted.length; i++) {
					decrypted[i] = Byte.valueOf(decryptSigValues[i].trim());
					finaldecrypt += Character.valueOf((char)decrypted[i]);
				}
				// Once the comparison is done, compare hashes
				try {
					result = pkiServ.verifyChecksum(HashedMsg, finaldecrypt);
				} catch (NoSuchAlgorithmException e) {
					e.printStackTrace();
				}
				if(result == true) {
					//if true send information requested and encrypt it
					M2 = "Server: Balance for Client["+ID+"] with Account No."+accountNo+" has a balance = $"+clibalance+"";
					try {
						M3 = pkiServ.encryptwithPriv(M2, pkiServ.readPrivateKeyFromFile(Spriv));
					} catch (IOException e) {
						e.printStackTrace();
					}
					System.out.println("Server: Sending Encrypted message to Client -> "+M3);
					//This message is sent as a byte array due to the nature of the encrypting 
					//functions. What you see in the output is a String representation of that
					//byte array.
					clients[findClient(ID)].sendByte(M3);
				} else {
					clients[findClient(ID)].send(".checkfail");
				}
			} else {
				clients[findClient(ID)].send("Server: Invalid request sent.");
			}
		}
	}
	
	public synchronized void remove(int ID) {
		int pos = findClient(ID);
		if(pos >= 0) {
			ServerThread toTerminate = clients[pos];
			System.out.println("Removing client thread "+ID+" at "+pos);
			if(pos < clientCount-1) {
				for(int i = pos+1; i < clientCount; i++) {
					clients[i-1] = clients[i];
				}
			}
			clientCount--;
			try {
				toTerminate.close();
			} catch(IOException e) {
				System.out.println("Error closing thread: "+e);
			}
			toTerminate.stop();
		}
	}
	public void addThread(Socket socket) {
		if(clientCount < clients.length) {
			System.out.println("Client Accepted: " +socket);
			clients[clientCount] = new ServerThread(this, socket);
			try {
				clients[clientCount].open();
				clients[clientCount].start();
				clientCount++;
			} catch(IOException e) {
				System.out.println("Error opening thread: "+e);
			}
		} else {
			System.out.println("Client refused. Maximum clients ["+clients.length+"] reached.");
		}
	}
	
	public void start() {
		if(thread == null) {
			thread = new Thread(this);
			thread.start();
		}
	}
	
	public void stop() {
		if(thread != null) {
			thread.stop();
			thread = null;
		}
	}
	/*
	 * Creates a small table of accounts for the use
	 * of the project. The accounts are a HashMap with keyvalues of
	 * AccountNo, Amount
	 */
	public static void main(String args[]) {
		accounts.put(1, 1010);
		accounts.put(2, 2020);
		accounts.put(3, 3030);
		accounts.put(4, 4040);
		accounts.put(5, 5050);
		
		Server server = null;
		try {
			pkiServ.generatekeys(Spub, Spriv);
		} catch (IOException e) {
			e.printStackTrace();
		}
		server = new Server(port);
	}
}
