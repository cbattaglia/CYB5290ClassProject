

import java.net.*;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.io.*;
import java.applet.*;
import java.awt.*;

public class Client extends Applet {
	private Socket socket = null;
	private DataInputStream console = null;
	private DataOutputStream streamOut = null;
	private ClientThread client = null;
	private TextArea disp = new TextArea();
	private TextField input = new TextField();
	private Button send = new Button("Send"), connect = new Button("Connect"), quit = new Button("Quit");
	private String serverName;
	private int serverPort;
	public PublicKey ServerPub;
	private String sPub;
	private String Clientpub = "Cpub";
	private String Clientpriv = "Cpriv";
	private byte[] CpubEncoded;
	private String sCpubBytes = "";
	private int keylength;
	PKI pkiClient = new PKI(Clientpub, Clientpriv);
	
	public void init() {
		//Applet setup
		Panel keys = new Panel();
		keys.setLayout(new GridLayout(1,2));
		keys.add(quit);
		keys.add(connect);
		Panel south = new Panel();
		south.setLayout(new BorderLayout());
		south.add("West", keys);
		south.add("Center", input);
		south.add("East", send);
		Label title = new Label("Client Applet, Format: REQUEST_BALANCE, [accountNo]", Label.CENTER);
		title.setFont(new Font("Helvetica", Font.BOLD, 14));
		setLayout(new BorderLayout());
		add("North", title);
		add("Center", disp);
		add("South", south);
		quit.disable();
		send.disable();
		//generate Client keys
		try {
			/*
			 * Here we change the Client's public key into an encoded byte array so it can be sent to the server
			 * we also grab the length of the byte array so that the server may use it to 
			 * divide up the client message accordingly
			 */
			pkiClient.generatekeys(Clientpub, Clientpriv);
			CpubEncoded = pkiClient.readPublicKeyFromFile(Clientpub).getEncoded();
			sCpubBytes = "";
			for(int i = 0; i < CpubEncoded.length; i++) {
				sCpubBytes += CpubEncoded[i];
				sCpubBytes += ", ";
			}
			keylength = sCpubBytes.length();
		} catch (IOException e) {
			e.printStackTrace();
		}
		getParameters();
	}
	
	public boolean action(Event e, Object o) {
		if(e.target == quit) {
			input.setText(".bye");
			send();
			quit.disable();
			send.disable();
			connect.enable();
		} else if (e.target == connect) {
			connect(serverName, serverPort);
		} else if (e.target == send) {
			send();
			input.requestFocus();
		}
		return true;
	}
	
	public void connect(String serverName, int serverPort) {
		println("Establishing Connection....");
		try {
			socket = new Socket(serverName, serverPort);
			println("Connected: " + socket);
			open();
			send.enable();
			connect.disable();
			quit.enable();
		} catch (UnknownHostException e) {
			println("Unknown host exception: "+e.getMessage());
		} catch (IOException e) {
			println("Unexpected exception: "+e.getMessage());
		}
	}
	
	public void send() {
		/*
		 * Send M1 = (input from applet console + length of encoded Client Key + encoded Client Key) 
		 * + Encrypted with Client Private Key(Hash of M1)
		 * When we encrpyt, it creates a byte array. The byte array is broken down and put into a string 
		 * so that it may be easier converted back into its original byte array.
		 */
		if(input.getText().contains("REQUEST_BALANCE")) {
			String M1, HashedMsg, M2, sEncryptedHash = "";
			byte[] EncryptedHash;
			try {
				M1 = input.getText().concat(Integer.toString(keylength)).concat(sCpubBytes);
				HashedMsg = pkiClient.sha1(M1);
				EncryptedHash = pkiClient.encryptwithPriv(HashedMsg, pkiClient.readPrivateKeyFromFile(Clientpriv));
				for(int i = 0; i < EncryptedHash.length; i++) {
					sEncryptedHash += EncryptedHash[i];
					sEncryptedHash += ", ";
				}
				M2 = M1.concat(sEncryptedHash);
				//Display receveid msg to Client Console
				println("Client: Sent to Server, plaintext message -> "+M2.substring(0, (18)));
				println("Client: Sent to Server, keylength of encoded key -> "+M2.substring(18,22));
				println("Client: Sent to Server, encoded Client Public Key -> "+M2.substring(22, 22+keylength));
				println("Client: Sent to Server, signature -> "+M2.substring(22+keylength));
				streamOut.writeUTF(M2);
				streamOut.flush();
				input.setText("");
			} catch(IOException e) {
				println("Sending error: "+e.getMessage());
				close();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} else {
			try {
				streamOut.writeUTF(input.getText());
				streamOut.flush();
			} catch (IOException e) {
				e.printStackTrace();
			}
			input.setText("");
		}
	}

	public void handle(byte[] msg) {
		if(msg.equals(".bye")) {
			println("Good bye. Press enter to exit...");
			close();
		} else if(msg.equals(".checkfail")) {
			println("Message has been tampered with, closing connection.");
			close();
		} else {
			println("Client: Received message from server -> "+msg);
			//Decrypt message from server
			String decryptedMsg = "";
			try {
				//We Assume the Client already has the Server's Public Key.
				//The keys are saved into the main directory of the project folder
				//In this case, CYB5290ClassProject
				// "../Spub", for reference the .. goes up two directories.
				PublicKey ServerPub = pkiClient.readPublicKeyFromFile("../Spub");
				decryptedMsg = pkiClient.decrpytwithPub(msg, ServerPub);
			} catch (IOException e) {
				e.printStackTrace();
			}
			String[] decryptSigValues = decryptedMsg.substring(0, decryptedMsg.length()-1).split(",");
			String finaldecrypt = "";
			byte[] decrypted = new byte[decryptSigValues.length];
			for(int i = 0; i < decrypted.length; i++) {
				decrypted[i] = Byte.valueOf(decryptSigValues[i].trim());
				finaldecrypt += Character.valueOf((char)decrypted[i]);
			}
			println(finaldecrypt);
			println("Client: Terminating connection to server...");
			client.stop();
		}
	}
	
	public void open() throws IOException {
		console = new DataInputStream(System.in);
		streamOut = new DataOutputStream(socket.getOutputStream());
		client = new ClientThread(this, socket);
	}
	
	public void close() {
		try {
			if(streamOut != null) { streamOut.close(); }
			if(socket != null) { socket.close(); }
		} catch(IOException e) {
			println("Error closing...");
		}
		//client.close();
		client.stop();
	}
	
	private void println(String msg) {
		disp.appendText(msg + "\n");
	}
	
	public void getParameters() {
		serverName = "0.0.0.0";
		serverPort = 9000;
	}

}
