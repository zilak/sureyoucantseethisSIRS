package projeto;

import java.io.FileInputStream;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

public class RMIClient implements RMIClientIntf{ 
    public static void main(String args[]) throws Exception {
    	
    	System.out.println("Indique o seu numero de port:");
    	Scanner s = new Scanner(System.in);
    	int port = s.nextInt();
    	
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
        RMIServerIntf objServer = (RMIServerIntf) registry.lookup("RMIServer");
        System.out.println("saida do registar: " + objServer.registarClient(port));
        
        // verify the cert
        
        X509Certificate cert = objServer.getCertificate();
        
        if(cert.getSubjectDN().toString().contains("CN=INEM")&& cert.getIssuerDN().toString().contains("CN=CA")){
        	System.out.println("subject: "+cert.getSubjectDN());
    		System.out.println(cert.getIssuerDN().toString());
    		RSAPublicKey pkey =(RSAPublicKey)cert.getPublicKey(); 
    		String field = DatatypeConverter.printHexBinary(pkey.getEncoded());
    		pkey.getEncoded();
    		//System.out.println("cert: "+ cert.toString()+" public key: " + field+ " issuer: "+cert.getIssuerDN() );
        }       
        
        // send the request to registe this client
        byte[] cipherText = encrypt("registe",cert.getPublicKey());
        objServer.sendCipherText(cipherText, port);
        
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

	@Override
	public void sendChallenge(String msg) throws RemoteException {
		System.out.println("entrou na msg e a msg e: "+msg);
	}

	@Override
	public void sendCipherText(byte[] ciphertex) throws RemoteException {
		// TODO Auto-generated method stub
		
	}
}

