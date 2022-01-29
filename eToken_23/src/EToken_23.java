
import java.io.File;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Scanner;
import javax.crypto.Cipher;

public class EToken_23 {
	

	static PrivateKey  privateKey;
	static  PublicKey publicKey;
	
	
	public static void main(String[] args)throws Exception
    {

				

	    // Create instance of SunPKCS11 provider
     	    String pkcs11Config = "C:\\Users\\\\Hello\\eclipse-workspace\\EToken_23\\config.cfg";
    	    java.io.ByteArrayInputStream pkcs11ConfigStream = new java.io.ByteArrayInputStream(pkcs11Config.getBytes());
	    sun.security.pkcs11.SunPKCS11 providerPKCS11 = new sun.security.pkcs11.SunPKCS11(pkcs11Config);
	    java.security.Security.addProvider(providerPKCS11);   

	    // Get provider KeyStore and login with PIN 
	    KeyStore.CallbackHandlerProtection chp = new KeyStore.CallbackHandlerProtection(new MyGuiCallbackHandler() {});
	    KeyStore.Builder builder = KeyStore.Builder.newInstance("PKCS11", null, chp);
	    KeyStore keyStore = builder.getKeyStore();
         
	    
	    // Enumerate items (certificates and private keys) in the KeyStore
            java.util.Enumeration<String> aliases = keyStore.aliases();	 
            String alias = null;   
      
  
          while (aliases.hasMoreElements()) {

        
          alias = aliases.nextElement();
  
          Certificate cert = keyStore.getCertificate(alias);
          X509Certificate x509Certificate =  (X509Certificate)cert ;
          
          
          // x509Certificate.getKeyUsage()[0]  Check whether the certificate has : digitalSignature         
          if( x509Certificate.getKeyUsage()[0] == true) {
          	
          Key key = keyStore.getKey(alias, null); // Here I try to access the private key of my hardware certificate
          privateKey  =  (PrivateKey )key ; 
          publicKey = x509Certificate.getPublicKey();
          
       
          // print all certificate information
          // System.out.println(cert);
         
         break;
         
          }     
        
        }
          
          
          
          
          Signature signer = Signature.getInstance("SHA256withRSA", keyStore.getProvider());      
          String data = "Hello world......";
          signer.initSign(privateKey);
          signer.update(data.getBytes());  // SLOW HERE! THE BIGGER THE DATA, THE SLOWER IT IS.
          byte[] signedData = signer.sign();
        
          
         
          verify(signedData ,data.getBytes() ,publicKey);

          
          
        }
	public static void verify(byte[] sig, byte[] original ,PublicKey publicKey) throws Exception {

		 
		  
		
	    Signature s = Signature.getInstance("SHA256withRSA");
	    s.initVerify(publicKey);
	    s.update(original);

	    if ( ! s.verify(sig)) {
	        System.out.println("Signature check FAILED");
	        return;
	    }
	    System.out.println("Signature check PASSED");
	}




}
