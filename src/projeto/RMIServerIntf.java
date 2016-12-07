package projeto;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.cert.X509Certificate;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;

public interface RMIServerIntf extends Remote {
	public X509Certificate getCertificate() throws RemoteException;
	public String registarClient(int port) throws RemoteException;
	public void sendCipherText(byte[] ciphertex, int port) throws RemoteException, Base64DecodingException;
}