package com.crypto.cryp;

import com.crypto.cryp.encryption.CryptoUtilImpl;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSATest {
  
	public static void main(String[] args) throws Exception {
    CryptoUtilImpl cryptoUtil = new CryptoUtilImpl();
    KeyPair keyPair = cryptoUtil.generateKeyPair();
    PublicKey publicKey =keyPair.getPublic();
    String pkBase64 =cryptoUtil.encodeToBase64(publicKey.getEncoded());
    System.out.println("========================================================= pour generer les clé");
    System.out.println(pkBase64);
    PrivateKey privateKey =keyPair.getPrivate();
    
    String prvBase64 =cryptoUtil.encodeToBase64(privateKey.getEncoded());
    System.out.println(prvBase64);
    System.out.println("========================================================= pour crypter");
    String data ="Hello world";
    
    PublicKey publicKey1=cryptoUtil.publicKeyFromBase64(pkBase64);
    String encrypted=cryptoUtil.encryptRSA(data.getBytes(), publicKey1);
    System.out.println("Encrypted data:");
    System.out.println(encrypted);
    System.out.println("Decrypted data:");
    PrivateKey privateKey1=cryptoUtil.privateKeyFromBase64(prvBase64);
    byte[] bytes = cryptoUtil.decryptRSA(encrypted, privateKey1);
    System.out.println(new String(bytes));

}
}
