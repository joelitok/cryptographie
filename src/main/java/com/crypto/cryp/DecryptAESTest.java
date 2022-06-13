package com.crypto.cryp;

import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;

public class DecryptAESTest {
    public static void main(String[] args) throws Exception {
        String receivedEncryptedData = "WiehfbJ7GaOxGo0ZLOssYkqxuF32Pzaaatbwq9cGh9c=";
        byte[] decodeEcryptedData = Base64.getDecoder().decode(receivedEncryptedData);

        String mySecret = "azerty_azerty_az"; //128 bits
        SecretKey secretKey = new SecretKeySpec(mySecret.getBytes(), 0, mySecret.length(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(decodeEcryptedData);
        System.out.println(new String(decryptedBytes));
    }
}
