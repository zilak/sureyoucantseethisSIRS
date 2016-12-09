package projeto;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;

public class RMIClient implements RMIClientIntf{ 
	private static RMIServerIntf objServer;
	private static PublicKey pubKey;
	private static PrivateKey privKey;
	private static PublicKey serverKey;
	private static SecretKey aesKey;
	private static int port;
	private static Scanner s = new Scanner(System.in);
	private static ArrayList<Integer> tokens = new ArrayList<Integer>();
	private static X509Certificate caCert;
	private static X509Certificate inemCert;
	
    public static void main(String args[]) throws Exception {
    	
    	// Ca certificate
    	FileInputStream input = new FileInputStream(args[0]);
    	BufferedInputStream bufinput = new BufferedInputStream(input);
    	CertificateFactory cf =  CertificateFactory.getInstance("X.509");    	
		caCert = (X509Certificate)cf.generateCertificate(bufinput);
		
		// INEM certificate
		FileInputStream input1 = new FileInputStream(args[1]);
    	BufferedInputStream bufinput1 = new BufferedInputStream(input1);
    	CertificateFactory cf1 =  CertificateFactory.getInstance("X.509");    	
		inemCert = (X509Certificate)cf1.generateCertificate(bufinput1);
    	
    	
    	System.out.println("Indique o seu numero de port:");
    	
    	port = s.nextInt();
    	
    	// Create keys;
        createKey();
    	
    	//Instantiate RmiServer
        RMIClient obj = new RMIClient();
        try { //special exception handler for registry creation
        	
            RMIClientIntf stub = (RMIClientIntf) UnicastRemoteObject.exportObject(obj,0);
            Registry reg;
            try {
            	reg = LocateRegistry.createRegistry(port);
                System.out.println("java RMI registry created.");

            } catch(Exception e) {
            	System.out.println("Using existing registry");
            	reg = LocateRegistry.getRegistry();
            }
        	reg.rebind("RMIClient", stub);

        } catch (RemoteException e) {
        	e.printStackTrace();
        }   
        System.out.println("Clique enter se o server estiver ativo");
        System.in.read();
        
    	// connect to server
    	Registry registry = LocateRegistry.getRegistry("localhost");
    	objServer = (RMIServerIntf) registry.lookup("RMIServer");
    	Random r = new Random();
    	int x = r.nextInt(999999999 - 100000000+1)+100000000;
        objServer.registarClient(port,x);
        
        // verify the cert of SERVER checks if it is INEM
        
        boolean notexpired=false;
        try{
        	inemCert.checkValidity();
        	inemCert.verify(caCert.getPublicKey());
        	caCert.checkValidity();
        	caCert.verify(caCert.getPublicKey());
        	
        	System.out.println("The certificate chain is valid");
        	notexpired =true;
        }catch(CertificateExpiredException cee){
        	System.out.println(" Certificate is expired");
        }
        
        if(notexpired){
        	serverKey = inemCert.getPublicKey();
        	byte[] cipherText = encrypt("registe "+port,serverKey);
        	objServer.sendCipherText(cipherText, port); 
        	sendChallenge();
        }else{
        	System.out.println("Certificate expired");
        	s.nextLine();
        	
        }
    }   
    
    public static void menu() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, RemoteException{
    	while(true){
	    	System.out.println("1- Type "+1+" to send a emergency request:");
	    	//System.out.println("2- Type "+2+" to send blabla....");
	    	switch(s.nextInt()){
	    	case 1:
	    		System.out.println("Give your location: ");
	    		String line = s.next();
	    		System.out.println("localizacao: "+line);
	    		
	    		byte[] cyphertext = aesencrypt("help "+port+" " + createToken()+" "+line,aesKey);
	    		objServer.sendAESCipherText(cyphertext,port);
	    		break;
	    	}
    	}
    	
    }
    public static int createToken(){
    	Random r = new Random();
		int token = r.nextInt(999999 - 100000 +1)+100000;
		while(tokens.contains(token)){
			token = r.nextInt(999999 - 100000 +1)+100000;
		}
		return token;
    }
    
    public static void createKey() throws NoSuchAlgorithmException{
    	KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    	keyGen.initialize(512);
    	KeyPair myPair= keyGen.generateKeyPair();
    	pubKey = myPair.getPublic();  	
    	privKey = myPair.getPrivate();
    	
    }
    
    public static byte[] encrypt(String text, PublicKey key){
    	byte[] cipherText = null;
    	
    	try{
    		Cipher cipher = Cipher.getInstance("RSA");
    		cipher.init(Cipher.ENCRYPT_MODE, key);
    		cipherText = cipher.doFinal(text.getBytes());
    	}catch(Exception e){
    		System.out.println("Erro ao cifrar: "+e.toString());
    	}   	
		return cipherText;    	
    }
    
    public static String decrypt(byte[] cipherText, PrivateKey key){
    	byte[] dectyptedText = null;
        try {
          // get an RSA cipher object and print the provider
          Cipher cipher = Cipher.getInstance("RSA");

          //  decrypt the text using the private key
          cipher.init(Cipher.DECRYPT_MODE, key);
          dectyptedText = cipher.doFinal(cipherText);
          
        } catch (Exception ex) {
          ex.printStackTrace();
        }
        return new String(dectyptedText);
    }
    public static byte[] aesencrypt(String plainText, SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
    	Cipher cipher = Cipher.getInstance("AES");
    	cipher.init(Cipher.ENCRYPT_MODE, key);
    	byte[] encrypted = cipher.doFinal(plainText.getBytes());
    	return encrypted;
    }
    public String aesdecrypt(byte[] cipherText ,SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
    	Cipher cipher = Cipher.getInstance("AES");
    	cipher.init(Cipher.DECRYPT_MODE, key);
    	String plaintext = new String(cipher.doFinal(cipherText));
    	return plaintext;
    }
	public static void sendChallenge() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		System.out.println("Type here the number you receive in your phone:");
        int msg = s.nextInt();
		byte[] cipherText = encrypt("response "+port+" "+msg+" "+pubKey,serverKey);
        try {
			objServer.sendCipherText(cipherText, port);
		} catch (Base64DecodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public void sendCipherText(byte[] ciphertext) throws RemoteException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		System.out.println("client receive cipher: " +decrypt(ciphertext,privKey));
		String[] msg = decrypt(ciphertext,privKey).split(("\\s+"));
		
		switch(msg[0]){
		case"sessao":
			// decode the base64 encoded string
			byte[] decodedKey = Base64.getDecoder().decode(msg[1]);
			// rebuild key using SecretKeySpec
			aesKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES"); 			
			break;
		}
		menu();
		
	}

	@Override
	public void sendSymCipherText(byte[] ciphertext) throws RemoteException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		String[] msg = aesdecrypt(ciphertext,aesKey).split("\\s+");
		
		switch(msg[0]){
		case "help":
			System.out.println("Help is incoming!");
			break;
		}
	}
}

