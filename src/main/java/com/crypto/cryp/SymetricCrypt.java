package com.crypto.cryp;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.crypto.cryp.encryption.CryptoUtilImpl;


public class SymetricCrypt {
    public static void main(String[] args) throws Exception {
    //     String data ="this is my message";
    //     String secret ="azerty_azerty_az"; // 128 bits, 192, 256 = 16, 24, 32
    //     Cipher cipher =Cipher.getInstance("AES");

    //     //exception NoSuchAlgorithmException, NoSuchPaddingException
    //     SecretKey secretKey = new SecretKeySpec(secret.getBytes(),0, secret.length(),"AES");
    //     //exeption invalideKeyException
    //     cipher.init(Cipher.ENCRYPT_MODE, secretKey);

    //     //IllegalBlockSizeException, BadPaddingException  
    //    byte[] encryptedData = cipher.doFinal(data.getBytes());
    //    String encodedEncryptedData =Base64.getEncoder().encodeToString(encryptedData);
    //    System.out.println(data);
    //    System.out.println(encodedEncryptedData);


CryptoUtilImpl cryptoUtil = new CryptoUtilImpl();

SecretKey secretKey=cryptoUtil.generateSecretKey();
SecretKey secretKey2=cryptoUtil.generateSecretKey("azerty_azerty_az");


byte[] secretKeyBytes = secretKey.getEncoded();

System.out.println(Arrays.toString(secretKeyBytes));
String encodedSecretKey = Base64.getEncoder().encodeToString(secretKeyBytes);

System.out.println(new String(encodedSecretKey));
System.out.println("=======================================");


String data ="My Data..... ....";
//String secret="azerty_azerty_az";

String secret =new String(Base64.getDecoder().decode(encodedSecretKey));
String encryptedData =cryptoUtil.encryptAES(data.getBytes(), secretKey2);

System.out.println(encryptedData);//77kFUCcyO9wAofBsEOcyPb8H+C/UZJyVoEHUD4eT2qk=

byte[]  decryptedBytes = cryptoUtil.decryptAES(encryptedData, secretKey2);
System.out.println(new String(decryptedBytes));










    }
}
