package projeto;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.Scanner;
import java.util.ArrayList;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;


import java.security.PublicKey;



public class RMIServer 
    implements RMIServerIntf {
	
	private static Map<Integer,RMIClientIntf> clients = new HashMap<Integer,RMIClientIntf>(); // conetao com os clientes
	private static Map<Integer,RMIClientIntf> penalizado = new HashMap<Integer,RMIClientIntf>(); // penalizados
	private static Map<Integer,Integer> challengeSend = new HashMap<Integer,Integer>();  // os challegens send
	private static Map<Integer,Integer> challengeReceive = new HashMap<Integer,Integer>(); // os challenges received
	private static Map<Integer,PublicKey> clientsPub = new HashMap<Integer,PublicKey>(); // Clients connected public
	private static Map<Integer,SecretKey> clientsAES = new HashMap<Integer,SecretKey>(); // Sessions key with clients
	private static ArrayList<Integer> tokenAES = new ArrayList <Integer>(); // Check if the message sent with that key is fresh(cant send duplicate token)
	private static Map<Integer,Integer> noCount = new HashMap<Integer,Integer>();
	
    public RMIServer() throws RemoteException {
    	
    }
    
    static PublicKey inemPublic;
    static PrivateKey inemPrivate;
    static X509Certificate myCert;
    
    public static void main(String args[]) throws Exception {
    	
    	FileInputStream input = new FileInputStream(args[0]);
    	BufferedInputStream bufinput = new BufferedInputStream(input);
    	CertificateFactory cf =  CertificateFactory.getInstance("X.509");    	
		myCert = (X509Certificate)cf.generateCertificate(bufinput);
		
		//Second argument is the file that has the private key
		inemPrivate = getPrivate(args[1]);
		
		System.out.println("Privateee: "+inemPrivate.toString());
		System.out.println("cert: " + myCert.getPublicKey());
		    	
        
		
        System.out.println("RMI server started");
        
        //Instantiate RmiServer
        RMIServer obj = new RMIServer();
 
        try { //special exception handler for registry creation
        	
            RMIServerIntf stub = (RMIServerIntf) UnicastRemoteObject.exportObject(obj,0);
            Registry reg;
            try {
            	reg = LocateRegistry.createRegistry(1099);
                System.out.println("java RMI registry created.");

            } catch(Exception e) {
            	System.out.println("Using existing registry");
            	reg = LocateRegistry.getRegistry();
            }
        	reg.rebind("RMIServer", stub);

        } catch (RemoteException e) {
        	e.printStackTrace();
        }
               
        System.out.println("Clique enter se o cliente estiver ativo");       
        System.in.read();
    }
    
    public static PrivateKey getPrivate(String filename) throws Exception {
		    byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());

		    PKCS8EncodedKeySpec spec =
		      new PKCS8EncodedKeySpec(keyBytes);
		    KeyFactory kf = KeyFactory.getInstance("RSA");
		    return kf.generatePrivate(spec);
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

          // decrypt the text using the private key
          cipher.init(Cipher.DECRYPT_MODE, key);
          dectyptedText = cipher.doFinal(cipherText);

        } catch (Exception ex) {
          ex.printStackTrace();
        }

        return new String(dectyptedText);
    }    
    
    // Create a symetrical key (AES)
    
    public  SecretKey createAESKey() throws NoSuchAlgorithmException{
    	KeyGenerator kgen = KeyGenerator.getInstance("AES");
    	kgen.init(128);
    	SecretKey secret = kgen.generateKey();
    	
    	return secret;
    }
    public byte[] aesencrypt(String plainText, SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
    	Cipher cipher = Cipher.getInstance("AES");
    	cipher.init(Cipher.ENCRYPT_MODE, key);
    	byte[] encrypted = cipher.doFinal(plainText.getBytes());
    	return encrypted;
    }
    public String aesdecrypt(byte[] cipherText ,SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{

    	System.out.println("chave aes decript: "+key + "formato: "+key.getFormat());
    	Cipher cipher = Cipher.getInstance("AES");
    	cipher.init(Cipher.DECRYPT_MODE, key);
    	byte[] text = cipher.doFinal(cipherText);
    	String plaintext = new String(text);
    	return plaintext;
    }
    
    public String registarClient(int port) throws RemoteException{   	
        try {
        	Registry registry = LocateRegistry.getRegistry("localhost",port);
			RMIClientIntf objClient = (RMIClientIntf) registry.lookup("RMIClient");			
			clients.put(port, objClient);
			
		} catch (NotBoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  	
        return "registou e numero de cliente: " + clients.size();
    }
    
	public void sendCipherText(byte[] ciphertext,int port) throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException  {
		if(penalizado.containsKey(port)){
			// dizer que esta penalizado
		}else{
			String[] receive =decrypt(ciphertext,inemPrivate).split("\\s+");
			System.out.println("receive: "+receive[0]);
			int portEnv = Integer.parseInt(receive[1]);
			if(portEnv == port){
				switch(receive[0]){
				case "registe":
					Random random = new Random();
					int response = random.nextInt(999999 - 100000 +1)+100000;
					RMIClientIntf desafiar  = clients.get(port);
					System.out.println("The Client must response the challenge witht the the next number: "+response);					
					challengeSend.put(port, response);
					desafiar.sendChallenge();
					break;
				case "response":
					// check it has already receive a response of that port
					if(!challengeReceive.containsKey(port)){
						System.out.println("reposta: " +receive[2] + " modulos: "+receive[10]+ " expoent: "+receive[13]);
						String modulos = receive[10];
						String expoent = receive[13];
						// compares the challenge send with the response, if it equals than its him. This challange is done by an sms
						
						// 9 string is the modulos
						BigInteger m = new BigInteger(modulos);
						
						//12 is the expoent
						BigInteger e = new BigInteger(expoent);
						RSAPublicKeySpec keySpec = new RSAPublicKeySpec (m,e);
						//Say what type of instance the key is
						KeyFactory keyFactory = KeyFactory.getInstance("RSA");
									
						PublicKey pubKey = keyFactory.generatePublic(keySpec);
						clientsPub.put(port, pubKey);
						
						SecretKey secretKey = createAESKey();
						
						String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
						System.out.println("secretKey: "+secretKey + " encoded: "+ encodedKey + " secretkey.encoded: "+secretKey.getEncoded());
						
						if(!clientsAES.containsValue(secretKey)){
							byte[] cipher = encrypt("sessao "+encodedKey,pubKey);
							clientsAES.put(port, secretKey);
							
							System.out.println("Colocou no clientsAES a seguinte chave:"+secretKey);
							
							System.out.println("Colocou no clientsAES a seguinte chave:"+secretKey + " e ao seu tipo: "+secretKey.getFormat());
							
							RMIClientIntf client = clients.get(port);
							client.sendCipherText(cipher);
						}else{
							/*// try to create new aes that are not in the hashmap
							while(!clientsAES.containsValue(secretKey)){
								secretKey =createAESKey();
								clientsAES.put(port, secretKey);
								System.out.println("Colocou no clientsAES a seguinte chave:"+secretKey + " e ao seu tipo: "+secretKey.getFormat());
								
								encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
								byte[] cipher = encrypt("sessao "+encodedKey,pubKey);
								RMIClientIntf client = clients.get(port);
								client.sendCipherText(cipher);
							}*/
							}
					}
					break;
				}				
			}			
		}		
	}
    
	@Override
	public X509Certificate getCertificate() {
		return myCert;
	}

	@Override
	public void sendAESCipherText(byte[] ciphertext, int port) throws RemoteException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		System.out.println("Entrou no AESCipher Server e size do clientsAES: " + clientsAES.size());
		SecretKey secretKey = clientsAES.get(port);
		System.out.println("Entrou no AESCipher Server e a chave AES e: "+secretKey);
		String[] msg = aesdecrypt(ciphertext,secretKey).split("\\s+");
		int portEnv = Integer.parseInt(msg[1]);
		int token = Integer.parseInt(msg[2]);
		Scanner s = new Scanner(System.in);
		if(portEnv == port && tokenAES.contains(token)){
			switch(msg[0]){
			case "help":
				System.out.println("Help request in: " + msg[3]);
				System.out.println("Type [Y] for help type [N] for discard");
				String resp = s.next().toUpperCase();
				
				while(!resp.equals("Y") || !resp.equals("N")){
					System.out.println("Type [Y] for help type [N] for discard");
					resp = s.next().toUpperCase();
				}
				if(resp.compareTo("Y")==0){
					
				}
				break;
			}
		}
	}
}

