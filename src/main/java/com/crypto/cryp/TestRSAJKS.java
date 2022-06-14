package com.crypto.cryp;

import com.crypto.cryp.encryption.CryptoUtilImpl;
import java.security.PrivateKey;
import java.security.PublicKey;

public class TestRSAJKS {
public static void main(String[] args) throws Exception {


CryptoUtilImpl cryptoUtil = new CryptoUtilImpl();
PublicKey publicKey = cryptoUtil.publicKeyFromCertificate("myCertificate.cert");
System.out.println(cryptoUtil.encodeToBase64(publicKey.getEncoded()));
PrivateKey privateKey =cryptoUtil.privateKeyFromJKS("tchoufa.jks", "123456", "tchoufa");
System.out.println(cryptoUtil.encodeToBase64(privateKey.getEncoded()));   


        String data="My secret message";
        String encrypted = cryptoUtil.encryptRSA(data.getBytes(), publicKey);
        System.out.println("encrypted");
        System.out.println(encrypted);
        byte[] decryptedBytes = cryptoUtil.decryptRSA(encrypted, privateKey);
        System.out.println("decrypted:");
        System.out.println(new String(decryptedBytes));

        
}
}