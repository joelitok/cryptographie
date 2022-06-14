package com.crypto.cryp;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import com.crypto.cryp.encryption.CryptoUtilImpl;

public class GenerateRSAKeys {
    public static void main(String[] args) throws Exception{
         // implement in CryptoUtilImpl
        // KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        // keyPairGenerator.initialize(1024);
        // KeyPair keyPair =keyPairGenerator.generateKeyPair();
        

        CryptoUtilImpl cryptoUtilImpl = new CryptoUtilImpl();
        KeyPair keyPair = cryptoUtilImpl.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey =keyPair.getPublic();

        System.out.println("Private Key :");
       // System.out.println(Arrays.toString(privateKey.getEncoded()));
        //System.out.println(privateKey.getEncoded().length);
        System.out.println(Base64.getEncoder().encodeToString(privateKey.getEncoded()));


        System.out.println("Public Key :");
       // System.out.println(Arrays.toString(publicKey.getEncoded()));
       // System.out.println(publicKey.getEncoded().length);
        System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
    }
}
