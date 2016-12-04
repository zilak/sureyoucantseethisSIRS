package projeto;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

import java.security.PublicKey;



public class RMIServer 
    implements RMIServerIntf {
	
	private static Map<Integer,RMIClientIntf> clients = new HashMap<Integer,RMIClientIntf>();
	private static Map<Integer,RMIClientIntf> penalizado = new HashMap<Integer,RMIClientIntf>();
	
    public RMIServer() throws RemoteException {
    	
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
	public void sendCipherText(byte[] ciphertext) throws RemoteException  {
		//abc
	}
    
    static PublicKey inemPublic;
    static PrivateKey inemPrivate;
    
    public static void main(String args[]) throws Exception {

    	FileInputStream input = new FileInputStream("C:/Users/joao-/Desktop/certificate.crt");
    	BufferedInputStream bufinput = new BufferedInputStream(input);
    	CertificateFactory cf =  CertificateFactory.getInstance("X.509");
    	

    	while(bufinput.available() >0){
    		X509Certificate cert = (X509Certificate)cf.generateCertificate(bufinput);
    		RSAPublicKey pkey =(RSAPublicKey)cert.getPublicKey(); 
    		String field = DatatypeConverter.printHexBinary(pkey.getEncoded());
    		pkey.getEncoded();
    		System.out.println("cert: "+ cert.toString()+" public key: " + field+ " issuer: "+cert.getIssuerDN());
    		
    	}
                    	
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
        broadcastSMS("msg");
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
    
    public static void broadcastSMS(String msg) throws RemoteException{
    	for (Map.Entry<Integer, RMIClientIntf> entry : clients.entrySet()) {
			RMIClientIntf theclient = entry.getValue();
			theclient.sendMessage(msg);
			System.out.println("enviou a msm para o: "+ entry.getKey());
		}
    }
}

