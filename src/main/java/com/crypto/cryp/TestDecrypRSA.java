package com.crypto.cryp;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

public class TestDecrypRSA {

    public static void main(String[] args) throws Exception {

        /**
         * 
         * Private Key :
         * MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAnmGo2N+mnfhDSFLi2l2CN+Enmk/qRV2EOarq0GQpCILenyrnzXI31SmVTaiLXjVMzQhw5xqjjQequalWydoa8wIDAQABAkBdcgtYIeTBcXfpFRZJdkBdTde64Qm88WcRSzmNyHq5TOeRnco3dLKZgeID4TZ45nUh/DUIU2sib2UChF0VetgJAiEA1j6aMxvYHfQqQC33822jActjt48H//MKrq6Jh8AiQ/cCIQC9P9thjNumz5oPUvOtlPLw1kvBfZGvmw6on8L4YoVp5QIhAMECOuaqQgOSMPIKt6Ls9XorYlU+nOVfbhM6mBnc5MG3AiBYQwDo5Q3IJYhfXzugmBgZtIgOTKb2dGWIxUHkH+bC9QIgUvbVlDBw1iYoRUz9mARJXYyIP2TRlnM90P0HS2RXyIk=
         * Public Key :
         * MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJ5hqNjfpp34Q0hS4tpdgjfhJ5pP6kVdhDmq6tBkKQiC3p8q581yN9UplU2oi141TM0IcOcao40HqrmpVsnaGvMCAwEAAQ==
         */

        String privateKeyBase64 = "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAnmGo2N+mnfhDSFLi2l2CN+Enmk/qRV2EOarq0GQpCILenyrnzXI31SmVTaiLXjVMzQhw5xqjjQequalWydoa8wIDAQABAkBdcgtYIeTBcXfpFRZJdkBdTde64Qm88WcRSzmNyHq5TOeRnco3dLKZgeID4TZ45nUh/DUIU2sib2UChF0VetgJAiEA1j6aMxvYHfQqQC33822jActjt48H//MKrq6Jh8AiQ/cCIQC9P9thjNumz5oPUvOtlPLw1kvBfZGvmw6on8L4YoVp5QIhAMECOuaqQgOSMPIKt6Ls9XorYlU+nOVfbhM6mBnc5MG3AiBYQwDo5Q3IJYhfXzugmBgZtIgOTKb2dGWIxUHkH+bC9QIgUvbVlDBw1iYoRUz9mARJXYyIP2TRlnM90P0HS2RXyIk=";
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] decodeKey = Base64.getDecoder().decode(privateKeyBase64);
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodeKey));
        String encryptedData = "Eci04oS5eq+LR1mbtULfzGaNCz6W1DzpawfqM9EQv0CdOZP0j37BRC2SshK67YNiaOABW0R/YfSIGZwidnSwXQ==";
        System.out.println("Encrypted message");
        System.out.println(encryptedData);
        byte[] decodeEncryptedData = Base64.getDecoder().decode(encryptedData);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(decodeEncryptedData);
        System.out.println("Decrypted message :");
        System.out.println(new String(decryptedBytes));

    }

}
