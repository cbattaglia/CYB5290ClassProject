import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

public class PKI {
	private static String PUBLIC_KEY_FILE;
	private static String PRIVATE_KEY_FILE;
	
	public PKI(String pubKeyname, String privKeyname) {
		PUBLIC_KEY_FILE = pubKeyname;
		PRIVATE_KEY_FILE = privKeyname;
	}
	
	/*
	 * Key generation method.
	 * name of keys are provided as parameters. Uses RSA to generate KeyPair and 
	 * create the Public and Private keys.
	 * Both the Client and Server will call this method on startup
	 */
	public static void generatekeys(String pubKeyname, String privKeyname) throws IOException {
		try {
			
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();
			
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec rsaPubKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
			RSAPrivateKeySpec rsaPrivKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
			
			PKI rsaObj = new PKI(pubKeyname, privKeyname);
			rsaObj.saveKeys(pubKeyname, rsaPubKeySpec.getModulus(), rsaPubKeySpec.getPublicExponent());
			rsaObj.saveKeys(privKeyname, rsaPrivKeySpec.getModulus(), rsaPrivKeySpec.getPrivateExponent());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
	}
	
	/*
	 * Saves the generated keys into the workspace folder
	 */
	public void saveKeys(String filename, BigInteger mod, BigInteger exp) throws IOException {
		FileOutputStream fos = null;
		ObjectOutputStream oos = null;
		
		try {
			fos = new FileOutputStream(filename);
			oos = new ObjectOutputStream(new BufferedOutputStream(fos));
			
			oos.writeObject(mod);
			oos.writeObject(exp);
		} catch (Exception e) {
			e.printStackTrace();
		}
		finally {
			if(oos != null) {
				oos.close();
				if(fos != null) {
					fos.close();
				}
			}
		}
	}
	/*
	 * Following methods does encryption and decryption with Private and Public Keys
	 * methods are divided up into four, encrypt and decrypt with Private and with Public.
	 * Encrypt Functions:
	 * 	Takes in a string and returns a byte array of the string
	 * Decrypt Functions:
	 * 	Takes in a byte array and returns a string
	 */
	public static byte[] encryptwithPub(String data, PublicKey pubKey) throws IOException {
		byte[] toEncrypt = data.getBytes();
		byte[] encrypted = null;
		
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			encrypted = cipher.doFinal(toEncrypt);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return encrypted;
	}
	
	public static byte[] encryptwithPriv(String data, PrivateKey privKey) throws IOException {
		byte[] toEncrypt = data.getBytes();
		byte[] encrypted = null;
		
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, privKey);
			encrypted = cipher.doFinal(toEncrypt);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return encrypted;
	}
	
	public static String decrpytwithPub(byte[] data, PublicKey pubKey) throws IOException {
		byte[] decrypted = null;
		String sdecrypted = "";
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, pubKey);
			decrypted = cipher.doFinal(data);
		} catch (Exception e) {
			e.printStackTrace();
		}
		for(int i = 0; i < decrypted.length; i++) {
			sdecrypted += decrypted[i];
			sdecrypted += ", ";
		}
		return sdecrypted;
	}
	
	public static String decrpytwithPriv(byte[] data, PrivateKey privKey) throws IOException {
		byte[] decrypted = null;
		
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privKey);
			decrypted = cipher.doFinal(data);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return decrypted.toString();
	}
	/* @Params: String of PublicKey file
	 * This method reads the data from the provided key file to be able to perform
	 * encryption and decryption with Public Keys
	 */
	public static PublicKey readPublicKeyFromFile(String filename) throws IOException {
		FileInputStream fis = null;
		ObjectInputStream ois = null;
		
		try {
			fis = new FileInputStream(new File(filename));
			ois = new ObjectInputStream(fis);
			
			BigInteger modulus = (BigInteger) ois.readObject();
			BigInteger exponent = (BigInteger) ois.readObject();
			
			RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);
			KeyFactory fact = KeyFactory.getInstance("RSA");
			PublicKey publicKey = fact.generatePublic(rsaPublicKeySpec);
			
			return publicKey;
		} catch (Exception e) {
			e.printStackTrace();
		}
		finally {
			if(ois != null) {
				ois.close();
				if(fis != null) {
					fis.close();
				}
			}
		}
		return null;
	}
	
	/*
	 * @Params: String of PrivateKey file
	* This method reads the data from the provided key file to be able to perform
	* encryption and decryption with PrivateKeys
	*/
	public static PrivateKey readPrivateKeyFromFile(String filename) throws IOException {
		FileInputStream fis = null;
		ObjectInputStream ois = null;
		
		try {
			fis = new FileInputStream(new File(filename));
			ois = new ObjectInputStream(fis);
			
			BigInteger modulus = (BigInteger) ois.readObject();
			BigInteger exponent = (BigInteger) ois.readObject();
			
			RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(modulus, exponent);
			KeyFactory fact = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = fact.generatePrivate(rsaPrivateKeySpec);
			
			return privateKey;
		} catch (Exception e) {
			e.printStackTrace();
		}
		finally {
			if(ois != null) {
				ois.close();
				if(fis != null) {
					fis.close();
				}
			}
		}
		return null;
	}

	//Sha-1 encryption method
	public static String sha1(String input) throws NoSuchAlgorithmException {
		MessageDigest mDigest = MessageDigest.getInstance("SHA1");
		byte[] result = mDigest.digest(input.getBytes());
		StringBuffer sb = new StringBuffer();
		for(int i = 0; i < result.length; i++) {
			sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
		}
		return sb.toString();
	}
	
	//Verifies hashes
	public static boolean verifyChecksum(String input, String Checksum) throws NoSuchAlgorithmException {
		return input.equals(Checksum);
		
	}
	/*
	 * The main method here were intial tests to ensure the proper steps 
	 * were taken before implementing into the Server-Client program.
	 */
	/*
	public static void main(String args[]) {
		String test = "REQUEST_BALANCE, 1";
		String Cpub = "Cpub", Cpriv = "Cpriv", Spub = "Spub", Spriv = "Spriv";
		String M1, M2, M3, M4, HM, SHM;
		String accountNo, signature="", oldM1, sCpubBytes = "", key, keylength, sEHM = "";
		byte[] EHM, CpubBytes, SigBytes;
		String[] byteValues, byteValuesSig;
		PublicKey CpubforServ;
		int x,y;
		try {
			generatekeys(Cpub, Cpriv);
			generatekeys(Spub, Spriv);
			
			byte[] CpubEncoded = readPublicKeyFromFile(Cpub).getEncoded();
			for(int i = 0; i < CpubEncoded.length; i++) {
				sCpubBytes += CpubEncoded[i];
				sCpubBytes += ", ";
			}
			x = sCpubBytes.length();
			
			System.out.println("TESTING CLIENT SEND");
			M1 = test.concat(Integer.toString(x)).concat(sCpubBytes);
			System.out.println("M1: "+M1);
			HM = sha1(M1);
			EHM = encryptwithPriv(HM, readPrivateKeyFromFile(Cpriv));
			
			for(int i = 0; i < EHM.length; i++) {
				sEHM += EHM[i];
				sEHM += ", ";
			}
			
			M2 = M1.concat(sEHM);
			System.out.println("Send M2 to server: "+M2);
			
			System.out.println("TESTING SERVER RECEIVE");
			keylength = M2.substring(18,22);
			oldM1 = M2.substring(0, 21+Integer.parseInt(keylength)+1);
			key = M2.substring(22, 22+Integer.parseInt(keylength));
			signature = M2.substring(22+Integer.parseInt(keylength));
			
			byteValues = key.substring(0, key.length()-1).split(",");
			
			CpubBytes = new byte[byteValues.length];
			for(int i = 0; i < CpubBytes.length; i++) {
				CpubBytes[i] = Byte.valueOf(byteValues[i].trim());
			}
			
			KeyFactory kf = KeyFactory.getInstance("RSA");
			EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(CpubBytes);
			CpubforServ = kf.generatePublic(pubKeySpec);
			
			accountNo = M2.substring(17,18);
			//System.out.println("KEY: "+key);
			//System.out.println("oldM1, accountNo & signature: ["+oldM1+"] ["+accountNo+"] & ("+signature+")");
			
			byteValuesSig = signature.substring(0, signature.length()-1).split(",");
			SigBytes = new byte[byteValuesSig.length];
			for(int i = 0; i < SigBytes.length; i++) {
				SigBytes[i] = Byte.valueOf(byteValuesSig[i].trim());
			}
			
			SHM = sha1(oldM1);
			String decryptSig = decrpytwithPub(SigBytes, CpubforServ);
			String[] decryptSigValues = decryptSig.substring(0, decryptSig.length()-1).split(",");
			String finaldecrypt = "";
			byte[] decrypted = new byte[decryptSigValues.length];
			for(int i = 0; i < decrypted.length; i++) {
				decrypted[i] = Byte.valueOf(decryptSigValues[i].trim());
				finaldecrypt += Character.valueOf((char)decrypted[i]);
			}
			
			boolean result = verifyChecksum(SHM, finaldecrypt);
			if(result == true) {
				M3 = "IT WORKED!";
				byte[] encryptedM3 = encryptwithPriv(M3, readPrivateKeyFromFile(Spriv));
				//send to client
				String decryptedM3 = decrpytwithPub(encryptedM3, readPublicKeyFromFile(Spub));
				String[] decryptSigValues1 = decryptedM3.substring(0, decryptedM3.length()-1).split(",");
				String finaldecrypt1 = "";
				byte[] decrypted1 = new byte[decryptSigValues1.length];
				for(int i = 0; i < decrypted1.length; i++) {
					decrypted1[i] = Byte.valueOf(decryptSigValues1[i].trim());
					finaldecrypt1 += Character.valueOf((char)decrypted1[i]);
				}
				System.out.println(finaldecrypt1);
			} else {
				System.out.println("boooooo");
			}
			//System.out.println("CpubforServ: "+CpubforServ);
			
		} catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
		}
	} */
}
