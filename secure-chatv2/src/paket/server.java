package paket;
import java.io.IOException;
import java.net.*;
import java.util.Calendar;
import java.util.Scanner;
import javax.crypto.Cipher;
import java.io.InputStream;
import java.security.*;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import static java.nio.charset.StandardCharsets.UTF_8;

public class server {
	private static final String AESPass = null;
	// Secure Layer for RSA
	 public static KeyPair generateKeyPair() throws Exception {
	        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
	        generator.initialize(2048, new SecureRandom());
	        KeyPair pair = generator.generateKeyPair();

	        return pair;
	    }

	    public static KeyPair getKeyPairFromKeyStore() throws Exception {
	        //Generated with:
	        //  keytool -genkeypair -alias mykey -storepass s3cr3t -keypass s3cr3t -keyalg RSA -keystore keystore.jks

	        InputStream ins = server.class.getResourceAsStream("/keystore.jks");

	        KeyStore keyStore = KeyStore.getInstance("JCEKS");
	        keyStore.load(ins, "s3cr3t".toCharArray());   //Keystore password
	        KeyStore.PasswordProtection keyPassword =       //Key password
	                new KeyStore.PasswordProtection("s3cr3t".toCharArray());

	        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("mykey", keyPassword);

	        java.security.cert.Certificate cert = keyStore.getCertificate("mykey");
	        PublicKey publicKey = cert.getPublicKey();
	        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

	        return new KeyPair(publicKey, privateKey);
	    }

	    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
	        Cipher encryptCipher = Cipher.getInstance("RSA");
	        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

	        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

	        return Base64.getEncoder().encodeToString(cipherText);
	    }

	    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
	        byte[] bytes = Base64.getDecoder().decode(cipherText);

	        Cipher decriptCipher = Cipher.getInstance("RSA");
	        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

	        return new String(decriptCipher.doFinal(bytes), UTF_8);
	    }

	    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
	        Signature privateSignature = Signature.getInstance("SHA256withRSA");
	        privateSignature.initSign(privateKey);
	        privateSignature.update(plainText.getBytes(UTF_8));

	        byte[] signature = privateSignature.sign();

	        return Base64.getEncoder().encodeToString(signature);
	    }

	    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
	        Signature publicSignature = Signature.getInstance("SHA256withRSA");
	        publicSignature.initVerify(publicKey);
	        publicSignature.update(plainText.getBytes(UTF_8));

	        byte[] signatureBytes = Base64.getDecoder().decode(signature);

	        return publicSignature.verify(signatureBytes);
	    }
	    
	    
	    
	    
	    
	    
	    
	    // Secure Layer for AES
	    private static SecretKeySpec AESsecretKey;
	    private static byte[] AESkey;
	    public static void setAESKey(String myAESKey)
	    {
	        MessageDigest sha = null;
	        try {
	        	AESkey = myAESKey.getBytes("UTF-8");
	            sha = MessageDigest.getInstance("SHA-1");
	            AESkey = sha.digest(AESkey);
	            AESkey = Arrays.copyOf(AESkey, 16);
	            AESsecretKey = new SecretKeySpec(AESkey, "AES");
	        }
	        catch (NoSuchAlgorithmException e) {
	            e.printStackTrace();
	        }
	        catch (UnsupportedEncodingException e) {
	            e.printStackTrace();
	        }
	    }
	 
	    public static String encryptAES(String strToEncrypt, String secret)
	    {
	        try
	        {
	            setAESKey(secret);
	            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
	            cipher.init(Cipher.ENCRYPT_MODE, AESsecretKey);
	            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
	        }
	        catch (Exception e)
	        {
	            System.out.println("Error while encrypting: " + e.toString());
	        }
	        return null;
	    }
	 
	    public static String decryptAES(String strToDecrypt, String secret)
	    {
	        try
	        {
	            setAESKey(secret);
	            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
	            cipher.init(Cipher.DECRYPT_MODE, AESsecretKey);
	            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
	        }
	        catch (Exception e)
	        {
	            System.out.println("Error while decrypting: " + e.toString());
	        }
	        return null;
	    }
	
	
	
	public static int serverPort = 55000;
	public static int clientPort = 0;
	public static InetAddress clientIPAddress = null;
	
	public static void main(String args[]) throws Exception {
		Scanner scanner = new Scanner(System.in);
		
		//System.out.print("Port numarasý girin: ");
		//int num = scanner.nextInt();
		//serverPort = num;
		System.out.print("Server port numarasý: " + serverPort + " olarak ayarlandý.\n");
		// Secure Layer for RSA
		
		//First generate a public/private key pair
		System.out.print("RSA anahtarý oluþturuluyor...\n");
        KeyPair pair = generateKeyPair();
        System.out.print("RSA anahtarý oluþturuldu.\n");
        System.out.print("RSA Public Key: " + pair.getPublic() + "\n");
        //System.out.print("Private Key: " + pair.getPrivate().getEncoded() + "\n");
        
        //KeyPair pair = getKeyPairFromKeyStore();

        //Our secret message
        //String message = "Merhaba, ben Ferhat ÝNALKAÇ";

        //Encrypt the message
       // String cipherText = encrypt(message, pair.getPublic());
        //System.out.println("Þifreli Mesaj: " + cipherText);
        

        //Now decrypt it
        //String decipheredMessage = decrypt(cipherText, pair.getPrivate());

        //System.out.println(decipheredMessage);

        //Let's sign our message
        //String signature = sign("Ferhat", pair.getPrivate());

        //Let's check the signature
        //boolean isCorrect = verify("Ferhat", signature, pair.getPublic());
        //System.out.println("Signature correct: " + isCorrect);
		
		

		
		
		// Socket Kýsmý
		DatagramSocket serverSocket = new DatagramSocket(serverPort);
		byte[] receiveDataPacket = new byte[4096];
		byte[] sendDataPacket = new byte[4096];
		String sendText = new String();
		DatagramPacket receivePacket = new DatagramPacket(receiveDataPacket, receiveDataPacket.length);
		
		System.out.print("Socket oluþturuluyor...\n");
		
		
		String encryptedString = new String();
		String decryptedString = new String();
		byte[] publicKeyBytes = pair.getPublic().getEncoded();
		boolean ok = true;
		// Anahtar Paylaþýmý
		
		String AESPassword = new String();
		while (ok){
			System.out.print("Anahtar paylaþýmý için bekleniyor...\n");
			serverSocket.receive(receivePacket);
			System.out.print("Anahtar paylaþýmý baþladý.\n");
			sendDataPacket = publicKeyBytes;
			DatagramPacket sendPacket = new DatagramPacket(sendDataPacket, sendDataPacket.length, receivePacket.getAddress(), receivePacket.getPort());
			serverSocket.send(sendPacket);
			System.out.print("Karþý taraftan AES anahtarý bekleniyor...\n");
			serverSocket.receive(receivePacket);
			System.out.println("\nClient AES KEY (Cipher)>> " + new String(receivePacket.getData(), 0, receivePacket.getLength()));
			AESPassword = decrypt(new String(receivePacket.getData(), 0, receivePacket.getLength()), pair.getPrivate());
			System.out.println("\nClient AES KEY (Plain Text)>> " + AESPassword);
			clientIPAddress = receivePacket.getAddress();
			clientPort = receivePacket.getPort();
			ok = false;
			
		}
		System.out.print("Anahtar paylaþýmý tamamlandý.\n");
		// Thread Kýsmý
		producer p = new producer (serverSocket, receivePacket, clientIPAddress, clientPort, AESPassword);
		p.start();
		
		sendText = "";
		while (true) {
			
			// Send
			//System.out.print("Server>> ");
			sendText = scanner.nextLine();
			if (sendText == "!exit") {
				serverSocket.close();
				return;
			}
			encryptedString = server.encryptAES(sendText, AESPassword);
			sendDataPacket = encryptedString.getBytes();
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
	String AESPassword;
	public producer (DatagramSocket serverSocket, DatagramPacket receivePacket, InetAddress clientIPAddress, int clientPort, String AESPassword) {
		this.serverSocket = serverSocket;
		this.receivePacket = receivePacket;
		producer.clientIPAddress = clientIPAddress;
		producer.clientPort = clientPort;
		this.AESPassword = AESPassword;
	}
	public void run() {
		String decryptedString = new String();
		SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
		
		while (true)
		{
				try {
					serverSocket.receive(receivePacket);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				Calendar now = Calendar.getInstance();
				System.out.print("------------------------------\n" + sdf.format(now.getTime()) + " Client>>>\n");
				decryptedString = server.decryptAES(new String(receivePacket.getData(), 0, receivePacket.getLength()), AESPassword);
				System.out.println("Cipher Text>> " + new String(receivePacket.getData(), 0, receivePacket.getLength()) + "\n");
				System.out.println("Plain Text>> " + decryptedString + "\n------------------------------");
				
				//clientIPAddress = receivePacket.getAddress();
				//clientPort = receivePacket.getPort();
		}
		
	}
}