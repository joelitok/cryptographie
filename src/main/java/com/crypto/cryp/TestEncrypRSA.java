package com.crypto.cryp;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;

import com.crypto.cryp.encryption.CryptoUtilImpl;

public class TestEncrypRSA {
    public static void main(String[] args) throws Exception {

        /**
         * 
         * Private Key :
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAnmGo2N+mnfhDSFLi2l2CN+Enmk/qRV2EOarq0GQpCILenyrnzXI31SmVTaiLXjVMzQhw5xqjjQequalWydoa8wIDAQABAkBdcgtYIeTBcXfpFRZJdkBdTde64Qm88WcRSzmNyHq5TOeRnco3dLKZgeID4TZ45nUh/DUIU2sib2UChF0VetgJAiEA1j6aMxvYHfQqQC33822jActjt48H//MKrq6Jh8AiQ/cCIQC9P9thjNumz5oPUvOtlPLw1kvBfZGvmw6on8L4YoVp5QIhAMECOuaqQgOSMPIKt6Ls9XorYlU+nOVfbhM6mBnc5MG3AiBYQwDo5Q3IJYhfXzugmBgZtIgOTKb2dGWIxUHkH+bC9QIgUvbVlDBw1iYoRUz9mARJXYyIP2TRlnM90P0HS2RXyIk=
Public Key :
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJ5hqNjfpp34Q0hS4tpdgjfhJ5pP6kVdhDmq6tBkKQiC3p8q581yN9UplU2oi141TM0IcOcao40HqrmpVsnaGvMCAwEAAQ==
         */
        
    //     // implement in CryptoUtilImpl
    //     // KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    //     // keyPairGenerator.initialize(1024);
    //     // KeyPair keyPair =keyPairGenerator.generateKeyPair();
        

    //     CryptoUtilImpl cryptoUtilImpl = new CryptoUtilImpl();
    //     KeyPair keyPair = cryptoUtilImpl.generateKeyPair();

    //     PrivateKey privateKey = keyPair.getPrivate();
    //     PublicKey publicKey =keyPair.getPublic();

    //     System.out.println("Private Key :");
    //    // System.out.println(Arrays.toString(privateKey.getEncoded()));
    //     //System.out.println(privateKey.getEncoded().length);
    //     System.out.println(Base64.getEncoder().encodeToString(privateKey.getEncoded()));


    //     System.out.println("Public Key :");
    //    // System.out.println(Arrays.toString(publicKey.getEncoded()));
    //    // System.out.println(publicKey.getEncoded().length);
    //     System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));


String publicKeyBase64="MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJ5hqNjfpp34Q0hS4tpdgjfhJ5pP6kVdhDmq6tBkKQiC3p8q581yN9UplU2oi141TM0IcOcao40HqrmpVsnaGvMCAwEAAQ==";
KeyFactory keyFactory = KeyFactory.getInstance("RSA");
byte[] decodeKey =Base64.getDecoder().decode(publicKeyBase64);
PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(decodeKey));


         String data ="Voici mon message clair à chiffrer";
         Cipher cipher =Cipher.getInstance("RSA");
         cipher.init(Cipher.ENCRYPT_MODE, publicKey);
         byte[] encryptedBytes =cipher.doFinal(data.getBytes());
         System.out.println("Encrypted message :");
         System.out.println(Base64.getEncoder().encodeToString(encryptedBytes));

    }
}
