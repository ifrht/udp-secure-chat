package paket;
import java.io.IOException;
import java.net.*;
import java.sql.Timestamp;
import java.util.Scanner;

public class server {
	public static int serverPort = 3748;
	public static int clientPort = 0;
	public static InetAddress clientIPAddress = null;
	public static void main(String args[]) throws IOException {
		// Socket Kýsmý
		DatagramSocket serverSocket = new DatagramSocket(serverPort);
		byte[] receiveDataPacket = new byte[1024];
		byte[] sendDataPacket = new byte[1024];
		String sendText = new String();
		DatagramPacket receivePacket = new DatagramPacket(receiveDataPacket, receiveDataPacket.length);
		Scanner myObj = new Scanner(System.in);
		
		// Thread Kýsmý
		producer p = new producer (serverSocket, receivePacket, clientIPAddress, clientPort);
		p.start();
		

		
		while (true) {
			// Send
			System.out.print("Server>> ");
			sendText = myObj.nextLine();
			if (sendText == "!exit") {
				serverSocket.close();
				return;
			}
			sendDataPacket = sendText.getBytes();
			DatagramPacket sendPacket = new DatagramPacket(sendDataPacket, sendDataPacket.length, paket.producer.clientIPAddress, paket.producer.clientPort);
			serverSocket.send(sendPacket);
			
		}
	}
}

class producer extends Thread {
	DatagramSocket serverSocket;
	DatagramPacket receivePacket;
	public static InetAddress clientIPAddress;
	public static int clientPort;
	public producer (DatagramSocket serverSocket, DatagramPacket receivePacket, InetAddress clientIPAddress, int clientPort) {
		this.serverSocket = serverSocket;
		this.receivePacket = receivePacket;
		producer.clientIPAddress = clientIPAddress;
		producer.clientPort = clientPort;
	}
	public void run() {
		while (true)
		{
				try {
					serverSocket.receive(receivePacket);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				Timestamp timestamp = new Timestamp(System.currentTimeMillis());
				System.out.println(timestamp.getHours() + ":" + timestamp.getMinutes() + " Client>> " + new String(receivePacket.getData(), 0, receivePacket.getLength()));
				clientIPAddress = receivePacket.getAddress();
				clientPort = receivePacket.getPort();
		}
		
	}
}

class data {
	int deger;
}