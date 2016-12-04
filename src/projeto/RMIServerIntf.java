package projeto;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface RMIServerIntf extends Remote {
	public String registarClient(int port) throws RemoteException;
	public void sendCipherText(byte[] ciphertex) throws RemoteException;
}