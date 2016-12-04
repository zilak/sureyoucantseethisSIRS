package projeto;

import java.io.FileInputStream;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import javax.crypto.Cipher;

public class RMIClient { 
    public static void main(String args[]) throws Exception {
    	Registry registry = LocateRegistry.getRegistry("localhost");
        RMIServerIntf obj = (RMIServerIntf) registry.lookup("RMIServer");
        System.out.println(obj.getMessage()); 
        // abasdawda
        //awdaw
        //vitor
        
        FileInputStream is = new FileInputStream("C:/Users/joao-/Desktop/Mestrado/1º Ano/Segurança Informática em Redes e Sistemas/sureyoucantseethisSIRS/keystore");
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(is, null);
        String alias = "INEM";
        
        Certificate cert = ks.getCertificate(alias);
        cert.getPublicKey();
        
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
}

