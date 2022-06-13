package com.crypto.cryp.encryption;

import java.util.Base64;
import java.util.Formatter;

import javax.xml.bind.DatatypeConverter;

import org.apache.commons.codec.binary.Hex;
import java.util.Arrays;


import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class CryptoUtilImpl {
    public String encodeToBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public byte[] decodeFromBase64(String data) {
        return Base64.getDecoder().decode(data.getBytes());
    }

    public String encodeToBase64URL(byte[] data) {
        return Base64.getUrlEncoder().encodeToString(data);
    }

    public byte[] decodeFromBase64URL(String data) {
        return Base64.getUrlDecoder().decode(data.getBytes());
    }

    public String encodeToHex(byte[] data){
        return DatatypeConverter.printHexBinary(data);
    }

    public String encodeToHexApacheCodec(byte[] data){
        return Hex.encodeHexString(data);
    }

    public String encodeToHexNative(byte[] data){
        Formatter formatter = new Formatter();
        for(byte b :data){
            formatter.format("%02x", b);
        }

        return formatter.toString();
    }



    //pour generer une cle
    
public SecretKey generateSecretKey() throws Exception{
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);//available value 128,192 or 256
        return keyGenerator.generateKey();
    }



// autre methode  pour generer un cle secret 
public SecretKey generateSecretKey(String secret) throws Exception{
       SecretKey secretKey = new SecretKeySpec(secret.getBytes(), 0,secret.length(),"AES");
       return secretKey;
}



    public String encryptAES(byte[] data,SecretKey secretKey) throws Exception{
        Cipher cipher =Cipher.getInstance("AES");

        //exception NoSuchAlgorithmException, NoSuchPaddingException
      //  SecretKey secretKey = new SecretKeySpec(secret.getBytes(),0, secret.length(),"AES");
        //exeption invalideKeyException
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        //IllegalBlockSizeException, BadPaddingException  
       
       byte[] encryptedData = cipher.doFinal(data);
       String encodedEncryptedData =Base64.getEncoder().encodeToString(encryptedData);
       return encodedEncryptedData;
    }

    public byte[] decryptAES(String encodeEncryptedData,SecretKey secretKey) throws Exception{
        byte[] decodeEcryptedData = Base64.getDecoder().decode(encodeEncryptedData);

       // SecretKey secretKey = new SecretKeySpec(secret.getBytes(), 0, secret.length(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(decodeEcryptedData);
        //System.out.println(new String(decryptedBytes));
         return decryptedBytes;
    }

    


}
