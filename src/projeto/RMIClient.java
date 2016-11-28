package projeto;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class RMIClient { 
    public static void main(String args[]) throws Exception {
        Registry registry = LocateRegistry.getRegistry("localhost");
        RMIServerIntf obj = (RMIServerIntf) registry.lookup("RMIServer");
        System.out.println(obj.getMessage()); 
        // abasdawda
        //awdaw
        //vitor
    }
}
