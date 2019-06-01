package paket;
import java.io.IOException;
import java.net.*;
import java.util.Calendar;
import java.util.Scanner;
import javax.crypto.Cipher;
import java.io.InputStream;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import static java.nio.charset.StandardCharsets.UTF_8;

public class client {
	
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
	
	
	

	
	
	
	
	
	
	public static void main(String args[]) throws Exception {
		int serverPort = 55000;
		Scanner scanner = new Scanner(System.in);
		//int num = scanner.nextInt();
		//System.out.print("Server port numarasý girin: ");
		
		//serverPort = System.in.read();
		System.out.print("Server port numarasý: " + serverPort + " olarak ayarlandý.\n");
		// Secure Layer for AES
		System.out.print("AES anahtarý oluþturuluyor...\n");
        String AESPassword = "ferhat_inalkac";
        System.out.print("Oluþturulan AES anahtarý: " + AESPassword + "\n");
        //String originalString = "Bu bir deneme mesajidir.";
        //String encryptedString = client.encryptAES(originalString, AESPass) ;
        //String decryptedString = client.decryptAES(encryptedString, AESPass) ;
         
        //System.out.println(originalString);
        //System.out.println(encryptedString);
        //System.out.println(decryptedString);
		
		

		
		// Socket Kýsmý
        System.out.print("Socket oluþturuluyor...\n");
		String hedefIP = new String("127.0.0.1");
		InetAddress serverIPAddress = InetAddress.getByName(hedefIP);
		
		DatagramSocket clientSocket = new DatagramSocket();
		String sendText = new String();
		byte[] receiveDataPacket = new byte[4096];
		byte[] sendDataPacket = new byte[4096];
		DatagramPacket receivePacket = new DatagramPacket(receiveDataPacket, receiveDataPacket.length);
		
		System.out.println("Baðlanmak için !connect yazýn.");
		
		String encryptedString = new String();
		
		
        boolean ok = true;
		// Anahtar Paylaþýmý
		while (ok){
			//System.out.print("\nClient>> ");
			sendText = scanner.nextLine();
			sendDataPacket = sendText.getBytes();
			DatagramPacket sendPacket = new DatagramPacket(sendDataPacket, sendDataPacket.length, serverIPAddress, serverPort);
			clientSocket.send(sendPacket);
			System.out.print("Anahtar paylaþýmý baþladý...\n");
			
			clientSocket.receive(receivePacket);
			PublicKey serverRSAPublicKey = 
				    KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(receivePacket.getData()));
			System.out.print("RSA Public Key alýndý.\n");
			System.out.print("RSA Public Key: " + serverRSAPublicKey + "\n");
			System.out.print("AES anahtarý RSA Public Key ile þifreleniyor...\n");
			String cipherText = encrypt(AESPassword, serverRSAPublicKey);
			System.out.print("RSA ile þifrelenmiþ AES anahtarý: " + cipherText +"\n");
			sendDataPacket = cipherText.getBytes();
			DatagramPacket sendPacket1 = new DatagramPacket(sendDataPacket, sendDataPacket.length, serverIPAddress, serverPort);
			clientSocket.send(sendPacket1);
			System.out.print("Public Key ile þifrelenmiþ AES anahtarý gönderildi.\n");
			
			ok = false;
		}
		System.out.print("Anahtar paylaþýmý tamamlandý.\n");
		
		
		
		
		// Thread Kýsmý
		producer p = new producer (clientSocket, receivePacket, serverIPAddress, serverPort, AESPassword);
		p.start();
		while (true) {
			// Send
			//System.out.print("\nClient>> ");
			sendText = scanner.nextLine();
			encryptedString = server.encryptAES(sendText, AESPassword);
			sendDataPacket = encryptedString.getBytes();
			DatagramPacket sendPacket = new DatagramPacket(sendDataPacket, sendDataPacket.length, serverIPAddress, serverPort);
			clientSocket.send(sendPacket);
		}
		
		
	}
	
	// Thread
	static class producer extends Thread {
		DatagramSocket clientSocket;
		DatagramPacket receivePacket;
		InetAddress serverIPAddress;
		int serverPort;
		String AESPassword;
		public producer (DatagramSocket clientSocket, DatagramPacket receivePacket, InetAddress serverIPAddress, int serverPort, String AESPassword) {
			this.clientSocket = clientSocket;
			this.receivePacket = receivePacket;
			this.serverIPAddress = serverIPAddress;
			this.serverPort = serverPort;
			this.AESPassword = AESPassword;
		}
		public void run() {
			String decryptedString = new String();
			SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
			
			while (true)
			{
					try {
						clientSocket.receive(receivePacket);
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					Calendar now = Calendar.getInstance();
					System.out.println("------------------------------\n" + sdf.format(now.getTime()) + " Server>>>\n");
					decryptedString = server.decryptAES(new String(receivePacket.getData(), 0, receivePacket.getLength()), AESPassword);
					System.out.println("Cipher Text>> " + new String(receivePacket.getData(), 0, receivePacket.getLength()));
					System.out.println("Plain Text>> " + decryptedString + "\n------------------------------");
			}
			
		}
	}
}
