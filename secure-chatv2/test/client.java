package paket;
import java.io.IOException;
import java.net.*;
import java.sql.Timestamp;
import java.util.Scanner;

public class client {
	
	
	public static void main(String args[]) throws Exception {
		// Socket Kýsmý
		String hedefIP = new String("127.0.0.1");
		InetAddress serverIPAddress = InetAddress.getByName(hedefIP);
		int serverPort = 3748;
		DatagramSocket clientSocket = new DatagramSocket();
		String sendText = new String();
		byte [] sendData = new byte[1024];
		byte [] receiveData = new byte[1024];
		DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
		Scanner myObj = new Scanner(System.in);
		
		// Thread Kýsmý
		producer p = new producer (clientSocket, receivePacket, serverIPAddress, serverPort);
		p.start();
		
		while (true) {
			// Send
			System.out.print("Client>> ");
			sendText = myObj.nextLine();
			if (sendText == "!exit") {
				clientSocket.close();
				return;
			}
			sendData = sendText.getBytes();
			DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, serverIPAddress, serverPort);
			clientSocket.send(sendPacket);
		}
		
		
	}
	
	// Thread
	static class producer extends Thread {
		DatagramSocket clientSocket;
		DatagramPacket receivePacket;
		InetAddress serverIPAddress;
		int serverPort;
		public producer (DatagramSocket clientSocket, DatagramPacket receivePacket, InetAddress serverIPAddress, int serverPort) {
			this.clientSocket = clientSocket;
			this.receivePacket = receivePacket;
			this.serverIPAddress = serverIPAddress;
			this.serverPort = serverPort;
		}
		public void run() {
			while (true)
			{
					try {
						clientSocket.receive(receivePacket);
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					Timestamp timestamp = new Timestamp(System.currentTimeMillis());
					System.out.println(timestamp.getHours() + ":" + timestamp.getMinutes() + " Client>> " + new String(receivePacket.getData(), 0, receivePacket.getLength()));
			}
			
		}
	}
}
