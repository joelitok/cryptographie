package com.crypto.cryp;

import java.util.Arrays;
import java.util.Base64;

import javax.xml.bind.DatatypeConverter;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.crypto.cryp.encryption.CryptoUtilImpl;

@SpringBootApplication
public class CrypApplication {

	public static void main(String[] args) {
		SpringApplication.run(CrypApplication.class, args);

		/*
		 * String document ="this is my message";
		 * byte[] bytes =document.getBytes();
		 * System.out.println(Arrays.toString(bytes));
		 * String documentBase64 = Base64.getEncoder().encodeToString(bytes);
		 * System.out.println(documentBase64);
		 * byte[] decoded =Base64.getDecoder().decode(documentBase64);
		 * System.out.println(new String(decoded));
		 * 
		 * 
		 * String encodeBase64Url=
		 * Base64.getUrlEncoder().encodeToString(document.getBytes());
		 * System.out.println(encodeBase64Url);
		 */


		CryptoUtilImpl cryptoUtilImpl = new CryptoUtilImpl();
		String data = "Hello from ENSET////";
		String dataBase64 = cryptoUtilImpl.encodeToBase64(data.getBytes());
		String dataBase64URL = cryptoUtilImpl.encodeToBase64URL(data.getBytes());
		System.out.println(dataBase64);
		System.out.println(dataBase64URL);

		byte[] decodeBytes = cryptoUtilImpl.decodeFromBase64(dataBase64);
		System.out.println(new String(decodeBytes));
		byte[] decodeBytes2 = cryptoUtilImpl.decodeFromBase64URL(dataBase64);
		System.out.println(new String(decodeBytes2));

		// byte[] dataBytes = dataBase64.getBytes();
		// System.out.println(Arrays.toString(dataBytes));
		// String dataHex = DatatypeConverter.printHexBinary(dataBytes);
		// System.out.println(dataHex);

		// byte[] bytes = DatatypeConverter.parseHexBinary(dataHex);
		// System.out.println(Arrays.toString(bytes));

		
		String s = cryptoUtilImpl.encodeToHex(data.getBytes());
		String s1 = cryptoUtilImpl.encodeToHexApacheCodec(data.getBytes());
		String s2 = cryptoUtilImpl.encodeToHexNative(data.getBytes());
		System.out.println(s);
		System.out.println(s1);
		System.out.println(s2);








	}

}
