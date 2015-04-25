

import java.net.*;
import java.io.*;

public class ServerThread extends Thread {
	private Socket socket = null;
	private Server server = null;
	private int ID = -1;
	private DataInputStream streamIn = null;
	private DataOutputStream streamOut = null;
	
	public ServerThread(Server server, Socket socket) {
		this.server = server;
		this.socket = socket;
		ID = socket.getPort();
	}
	
	public void send(String msg) {
		try {
			streamOut.writeUTF(msg);
			streamOut.flush();
		} catch(IOException e) {
			System.out.println(ID+" Error sending: "+e.getMessage());
			server.remove(ID);
			stop();
		}
	}
	
	public void sendByte(byte[] msg) {
		try {
			streamOut.writeInt(msg.length);
			streamOut.write(msg, 0, msg.length);
			streamOut.flush();
		} catch(IOException e) {
			System.out.println(ID+"Error sending: "+e.getMessage());
			server.remove(ID);
			stop();
		}
	}
	
	public int getID() {
		return ID;
	}
	
	public void run() {
		System.out.println("Server Thread "+ID+" running.");
		while(true) {
			try {
				server.handle(ID, streamIn.readUTF());
			} catch(IOException e) {
				System.out.println(ID+" Error sending: "+e.getMessage());
				server.remove(ID);
				stop();
			}
		}
	}
	
	public void open() throws IOException {
		streamIn = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
		streamOut = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
	}
	
	public void close() throws IOException {
		if(socket != null) { socket.close(); }
		if(streamIn != null) { streamIn.close(); }
		if(streamOut != null) { streamOut.close(); }
	}
}
