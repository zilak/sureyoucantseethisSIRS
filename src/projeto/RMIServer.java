package projeto;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
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
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;


import java.security.PublicKey;



public class RMIServer 
    implements RMIServerIntf {
	
	private static Map<Integer,RMIClientIntf> clients = new HashMap<Integer,RMIClientIntf>();
	private static Map<Integer,RMIClientIntf> penalizado = new HashMap<Integer,RMIClientIntf>();
	private static Map<Integer,Integer> challengeSend = new HashMap<Integer,Integer>();
	private static Map<Integer,Integer> challengeReceive = new HashMap<Integer,Integer>();
	private static Map<Integer,PublicKey> clientsPub = new HashMap<Integer,PublicKey>();
	
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
    
    public static SecretKey createAESKey() throws NoSuchAlgorithmException{
    	KeyGenerator kgen = KeyGenerator.getInstance("AES");
    	kgen.init(128);
    	
    	return null;
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
    
	public void sendCipherText(byte[] ciphertext,int port) throws RemoteException  {
		if(penalizado.containsKey(port)){
			// dizer que esta penalizado
		}else{
			String[] receive =decrypt(ciphertext,inemPrivate).split("\\s+");
			switch(receive[0]){
			case "registe":
				Random random = new Random();
				int response = random.nextInt(999999 - 100000 +1)+100000;
				RMIClientIntf desafiar  = clients.get(port);
				challengeSend.put(port, response);
				//enviar o challange
				break;
			case "response":
				if(!challengeReceive.containsKey(port)){
					int challegeResponse= Integer.parseInt(receive[1]);
					if(challegeResponse == challengeSend.get(port)){
						byte[] data = Base64.getDecoder().decode(receive[2]);
					    X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
					    KeyFactory fact;
						try {
							fact = KeyFactory.getInstance("DSA");
							try {
								PublicKey clientPub = fact.generatePublic(spec);
								clientsPub.put(port, clientPub);
							} catch (InvalidKeySpecException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						} catch (NoSuchAlgorithmException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					    
					}
				}
				break;
			}
			
		}
	}
    
	@Override
	public X509Certificate getCertificate() {
		return myCert;
	}
}

