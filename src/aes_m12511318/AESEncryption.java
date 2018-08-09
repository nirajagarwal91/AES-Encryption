package aes_m12511318;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import java.security.SecureRandom;
import javax.crypto.spec.IvParameterSpec;

public class AESEncryption {
	
	static byte[] globalIv;
	public static void main(String[] args) throws Exception {
		String message = getFileData("plaintext.txt");
		System.out.println("Message:=\t\t\t\t"+ message);
		
		// Generation of key using the Secret Key library in Java
		SecretKey secureKey = keyGeneration();
		String key = convertBytesToHex(secureKey.getEncoded());
		System.out.println("AES Key generated:=\t\t\t"+convertBytesToHex(secureKey.getEncoded())+ " Length ="+ convertBytesToHex(secureKey.getEncoded()).length());
		printInFileData("key.txt",key);
		
		System.out.println("=======================================================================================================================");
		System.out.println("                                              AES - ECB ");
		System.out.println("=======================================================================================================================");
		double startTime, endTime;
		//Encryption of Plaintext using AES-ECB mode
		
		startTime = System.nanoTime();
		byte[] cipherText = encryptTextInECB(message, secureKey); 
		endTime = System.nanoTime();
		System.out.println("For AES-ECB Encryption Function takes:= " + (endTime - startTime) + " ns");
		System.out.println("Cipher Text in AES-ECB mode generated:= "+convertBytesToHex(cipherText) + " Length = "+ convertBytesToHex(cipherText).length());
		printInFileData("ciphertextECB.txt",convertBytesToHex(cipherText)); // Saving the Cipher text to a file to ciphertextECB.txt
		
		
		//Decryption of ciphertext using AES-ECB mode
		startTime = System.nanoTime();
		String decryptedMessageECB = decryptTextInECB(cipherText,secureKey);
		endTime = System.nanoTime();
		System.out.println("For AES-ECB Decryption Function takes:= " + (endTime - startTime) + " ns");
		printInFileData("resultECB.txt",decryptedMessageECB);// Saving the Decrypted ciphertext to file resultECB.txt
		System.out.println("Decrypt Text in AES-ECB mode generated:= "+decryptedMessageECB);	
		
		System.out.println("=======================================================================================================================");
		System.out.println("                                              AES - CBC ");
		System.out.println("=======================================================================================================================");
		
		//Encryption of Plaintext using AES-CBC mode
		byte[] cipherTextCBC = encryptTextInCBC(message,secureKey);	
		String finalCipher = convertBytesToHex(globalIv)+convertBytesToHex(cipherTextCBC); // IV + Encrypted message
		System.out.println("Cipher Text in AES-CBC mode generated := "+ finalCipher+" Length="+ finalCipher.length());
		printInFileData("ciphertextCBC.txt",finalCipher);
		
		//Decryption of Cipher Text using AES-CBC mode
		startTime = System.nanoTime();
		String decryptedTextCBC = decrypt(cipherTextCBC, secureKey);
		endTime = System.nanoTime();
		System.out.println("For AES-CBC Decryption Function takes:= " + (endTime - startTime) + " ns");
		System.out.println("Decrypted Text in AES-CBC mode generated := "+ decryptedTextCBC);
		printInFileData("resultCBC.txt",decryptedTextCBC);
	}
	
	// Function to get the data from each file in the Data subfolder.
	public static String getFileData(String filename) throws FileNotFoundException, UnsupportedEncodingException
	{
		File fileFetch = new File("C:\\Users\\Niraj\\eclipse-workspace\\aes_m12511318\\Data\\"+filename);
		Scanner scanFileFetch = new Scanner(fileFetch);
		String textInFile = null;
		while(scanFileFetch.hasNextLine()) 
		{
			textInFile = scanFileFetch.nextLine(); //Reading text data from file
		}
		scanFileFetch.close();
		return textInFile;
	}
	
	// Method to print the message Encrypted or Decrypted to the called text file
	public static void printInFileData(String fileName, String message) throws FileNotFoundException 
	{
		PrintWriter fileStore = new PrintWriter("C:\\Users\\Niraj\\eclipse-workspace\\aes_m12511318\\data\\"+ fileName);
    	fileStore.print(message);
    	fileStore.close(); 
	}
	
	// Method that generates a Secret key of 256 bits.
	public static SecretKey keyGeneration() throws Exception
	{
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		generator.init(256); // The AES key size in number of bits
		SecretKey secretKey = generator.generateKey();
		return secretKey;
	}
	
	// Method that converts bytes to Hexadecimal of base 16
	public static String convertBytesToHex(byte[] bytemessage)
	{
		return DatatypeConverter.printHexBinary(bytemessage);
	}
	
	// -- Encryption Function for AES - ECB mode
	public static byte[] encryptTextInECB(String plainTextMessage,SecretKey secretKey) throws Exception
	{
		//Encryption using AES mode is encrypted using ECB mode by default
		Cipher aesCipherECB = Cipher.getInstance("AES/ECB/PKCS5Padding");
		aesCipherECB.init(Cipher.ENCRYPT_MODE, secretKey);
		byte[] cipherText = aesCipherECB.doFinal(plainTextMessage.getBytes());
		return cipherText;
	}
	
	// -- Decryption function for the AES - ECB mode
	public static String decryptTextInECB(byte[] cipherText, SecretKey secretKey) throws Exception 
	{
		// AES defaults to AES/ECB/PKCS5Padding
		Cipher aesCipherECB = Cipher.getInstance("AES/ECB/PKCS5Padding");
		aesCipherECB.init(Cipher.DECRYPT_MODE, secretKey);
		byte[] bytePlainTextMessage = aesCipherECB.doFinal(cipherText);
		return new String(bytePlainTextMessage);
	}

	// Method that returns byte value after converting the plaintext message to cipher text. In CBC algorithm IV vector is also generated.
	// IV is generated to do XOR operation with message internally.
	
	public static byte[] encryptTextInCBC(String plainTextMessage,SecretKey secretKey) throws Exception
	{
		//Generating the Initialization Vector
        byte[] iVector = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iVector);
        globalIv = iVector;
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iVector);
        System.out.println("Initialization Vector\t\t\t:="+ convertBytesToHex(ivParameterSpec.getIV())+ " Length = "+ convertBytesToHex(ivParameterSpec.getIV()).length());
        printInFileData("iv.txt",convertBytesToHex(ivParameterSpec.getIV()));
        
        // Encryption of the plaintext message to ciphertext
        double startTime = System.nanoTime();
        byte[] newMessageInBytes = plainTextMessage.getBytes();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptedMessage = cipher.doFinal(newMessageInBytes);
        double endTime = System.nanoTime();
		System.out.println("For AES-CBC Encryption Function takes:= " + (endTime - startTime) + " ns");
        
        return encryptedMessage;
	}
	
	//Method that does Decryption of the Cipher Text and then returns the decoded cipher in a plain text format
	
	public static String decrypt(byte[] encryptedCipherTextInBytes, SecretKey secretKey) throws Exception
	{
        // Fetching IV from static global variable
        byte[] iVector = new byte[16];
        iVector = globalIv;
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iVector);

        // Decryption Logic to decrypt the cipher text to the original Message
        Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] decryptedMessage = cipherDecrypt.doFinal(encryptedCipherTextInBytes);

        return new String(decryptedMessage);
    }
	
	
}
