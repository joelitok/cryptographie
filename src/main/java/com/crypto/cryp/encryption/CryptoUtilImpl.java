package com.crypto.cryp.encryption;

import java.util.Base64;
import java.util.Formatter;

import javax.xml.bind.DatatypeConverter;

import org.apache.commons.codec.binary.Hex;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;

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

    public String encodeToHex(byte[] data) {
        return DatatypeConverter.printHexBinary(data);
    }

    public String encodeToHexApacheCodec(byte[] data) {
        return Hex.encodeHexString(data);
    }

    public String encodeToHexNative(byte[] data) {
        Formatter formatter = new Formatter();
        for (byte b : data) {
            formatter.format("%02x", b);
        }

        return formatter.toString();
    }

    // pour generer une cle

    public SecretKey generateSecretKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);// available value 128,192 or 256
        return keyGenerator.generateKey();
    }

    // autre methode pour generer un cle secret
    public SecretKey generateSecretKey(String secret) throws Exception {
        SecretKey secretKey = new SecretKeySpec(secret.getBytes(), 0, secret.length(), "AES");
        return secretKey;
    }

    public String encryptAES(byte[] data, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");

        // exception NoSuchAlgorithmException, NoSuchPaddingException
        // SecretKey secretKey = new SecretKeySpec(secret.getBytes(),0,
        // secret.length(),"AES");
        // exeption invalideKeyException
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // IllegalBlockSizeException, BadPaddingException

        byte[] encryptedData = cipher.doFinal(data);
        String encodedEncryptedData = Base64.getEncoder().encodeToString(encryptedData);
        return encodedEncryptedData;
    }

    public byte[] decryptAES(String encodeEncryptedData, SecretKey secretKey) throws Exception {
        byte[] decodeEcryptedData = Base64.getDecoder().decode(encodeEncryptedData);

        // SecretKey secretKey = new SecretKeySpec(secret.getBytes(), 0,
        // secret.length(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(decodeEcryptedData);
        // System.out.println(new String(decryptedBytes));
        return decryptedBytes;
    }

    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(512);
        return keyPairGenerator.generateKeyPair();
    }

    public PublicKey publicKeyFromBase64(String pkBase64) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] decodedPK = Base64.getDecoder().decode(pkBase64);
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(decodedPK));
        return publicKey;
    }

    public PrivateKey privateKeyFromBase64(String pkBase64) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] decodedPK = Base64.getDecoder().decode(pkBase64);
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodedPK));
        return privateKey;
    }

    public String encryptRSA(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] bytes = cipher.doFinal(data);
        return encodeToBase64(bytes);
    }

    public byte[] decryptRSA(String dataBase64, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedEncryptedData = decodeFromBase64(dataBase64);
        byte[] decryptedData = cipher.doFinal(decodedEncryptedData);
        return decryptedData;
    }

}
