package org.suai.hostapplication;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

public class Crypto {
	
	/* В данном классе реализован протокол 
				OPACITY для хост приложения */
		
	/* Поля класса */
	private BCECPrivateKey privateKey;
	private BCECPublicKey publicKey;
	private BCECPublicKey publicKeySC;
	
	public SecretKey secretKey;
	private byte[] iv;
	
	private ECCurve curve;
	private ECParameterSpec ecSpec;

	public Crypto() {
		// Добавляем криптопровайдер BouncyCastle (находится в папке lib проекта)
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		// Параметры эллиптической кривой
		curve = new ECCurve.Fp(
	            new BigInteger("fffffffffffffffffffffffffffffffeffffffffffffffff", 16),
	            new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
	            new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16));
		
		ecSpec = new ECParameterSpec(
	            curve,
	            curve.decodePoint(Hex.decode("04188da80eb03090f67cbf20eb43a18800f4ff"
	            		+ "0afd82ff101207192b95ffc8da78631011ed6b24cdd573f977a11e794811")), 
	            new BigInteger("ffffffffffffffffffffffff99def836146bc9b1b4d22831", 16));
		
		// Инициализирующий вектор для шифрования AES в режиме CBC
		iv = new byte[16];
		for(int i = 0; i < 16; i++) {
			iv[i] = (byte)0;
		}
	}

	/* Функция генерирует публичный и приватный ключи EC
				Ключи записываются в файлы PK.key и SK.key 	*/
	public void generateKey() {
		KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance("ECDH", "BC");
			keyGen.initialize(ecSpec, new SecureRandom());
			
			KeyPair keyPair = keyGen.generateKeyPair();
			privateKey = (BCECPrivateKey)keyPair.getPrivate();
			publicKey = (BCECPublicKey)keyPair.getPublic();
			
			FileOutputStream outputStream = new FileOutputStream("PK.key");
			byte[] pk = publicKey.getQ().getEncoded();
			outputStream.write(pk, 0, pk.length);
			outputStream.flush();
			outputStream.close();
			
			outputStream = new FileOutputStream("SK.key");
			byte[] sk = privateKey.getD().toByteArray();
			outputStream.write(sk, 0, sk.length);
			outputStream.flush();
			outputStream.close();
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	/* Функция загружает ключи из файлов PK.key и SK.key
		Инициализирует поля класса publicKey и privateKey */
	public void loadKey() {
		
		try {
			FileInputStream inputStream = new FileInputStream("PK.key");
			byte[] pkBuf = new byte[1000];
			int pkLength = inputStream.read(pkBuf);
			byte[] pk = new byte[pkLength];
			for(int i = 0; i < pkLength; i++) {
				pk[i] = pkBuf[i];
			}
			
			publicKey = (BCECPublicKey)rawdataToPublicKey(ecSpec, pk);
			inputStream.close();
			
			inputStream = new FileInputStream("SK.key");
			byte[] skBuf = new byte[1000];
			int skLength = inputStream.read(skBuf);
			byte[] sk = new byte[skLength];
			for(int i = 0; i < skLength; i++) {
				sk[i] = skBuf[i];
			}
			
			privateKey = (BCECPrivateKey)rawdataToPrivateKey(ecSpec, sk);
			inputStream.close();
			
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}
	/* Функция возвращает публичный ключ в виде массива байт */
	public byte[] getPK() {
		return publicKey.getQ().getEncoded();
	}
	
	/* Запись в файл PKS.key публичного ключа смарт-карты */
	public void setPKS(byte[] pks) {
		try {
			FileOutputStream outputStream = new FileOutputStream("PKS.key");
			outputStream.write(pks, 0, pks.length);
			outputStream.flush();
			outputStream.close();
			
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	/* Функция принимает зашифрованный уникальный идентификатор смарт-карты
		В файл IDC.key записывается рассшифрованный id карты */
	public void setIDC(byte[] eidC) {
		
		try {
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "BC");
			cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
			
			byte[] idC = cipher.doFinal(eidC);
			
			FileOutputStream outputStream = new FileOutputStream("IDC.key");
			outputStream.write(idC, 0, idC.length);
			outputStream.flush();
			outputStream.close();
			
		} catch (NoSuchAlgorithmException | NoSuchProviderException
				| NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}
	/* Загрузка публичного ключа смарт-карты из локального файла */
	private void loadPKS() {
		try {
			FileInputStream inputStream = new FileInputStream("PKS.key");
			byte[] pksBuf = new byte[1000];
			int pksLength = inputStream.read(pksBuf);
			byte[] pks = new byte[pksLength];
			for(int i = 0; i < pksLength; i++) {
				pks[i] = pksBuf[i];
			}
			
			publicKeySC = (BCECPublicKey)rawdataToPublicKey(ecSpec, pks);
			inputStream.close();
			
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	/* Выработка общего секретного ключа AES для авторизации */
	public void generateSKforAuth(byte[] rnd) {
		loadPKS();
		
		try {
			KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH", "BC");
			keyAgree.init(privateKey);
		    keyAgree.doPhase(publicKeySC, true);
		    MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
		    byte[] z = hash.digest(keyAgree.generateSecret());
		    
		    FileInputStream inputStream = new FileInputStream("IDC.key");
			byte[] idCBuf = new byte[1000];
			int idCLength = inputStream.read(idCBuf);
			byte[] idC = new byte[idCLength];
			for(int i = 0; i < idCLength; i++) {
				idC[i] = idCBuf[i];
			}
		    
		    hash = MessageDigest.getInstance("SHA256", "BC");
		    byte[] sk = hash.digest(concatArray(concatArray(z, rnd), idC));
		    
			secretKey = new SecretKeySpec(sk, 0, 16, "AES");
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	/* Выработка общего секретного ключа AES для регистрации */
	public void generateSK(byte[] rnd) {
		loadPKS();
		
		try {
			KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH", "BC");
			keyAgree.init(privateKey);
		    keyAgree.doPhase(publicKeySC, true);
		    MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
		    byte[] z = hash.digest(keyAgree.generateSecret());
		    
		    hash = MessageDigest.getInstance("SHA256", "BC");
		    byte[] sk = hash.digest(concatArray(z, rnd));
		    
			secretKey = new SecretKeySpec(sk, 0, 16, "AES");
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
	}
	/* Аутентификация (для регистрации и авторизации схема одинаковая) */
	public boolean isAuth(byte[] auth) {
		try {
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			
			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
		
			byte[] pk = publicKey.getQ().getEncoded();
			int trailerLength = (int)(16 - (pk.length % 16));
			byte[] trailer = new byte[trailerLength];
			for(int i = 0; i < trailerLength; i++) {
				trailer[i] = (byte)trailerLength;
			}
			
			byte[] result = cipher.doFinal(concatArray(pk, trailer));
			
			if(result.length != auth.length) {
				return false;
			}
			
			for(int i = 0; i < auth.length; i++) {
				if(auth[i] != result[i]) {
					return false;
				}
			}
			
			return true;

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		
		return false;
	}
	
	/* Генерация случайных данных */
	public byte[] generateRnd(int length) {
		SecureRandom rndGen = new SecureRandom();
		byte[] rnd = new byte[length];
		rndGen.nextBytes(rnd);
		return rnd;
	}
	
	/* Функция инициализирует публичный ключ EC
					На вход принимает массив байт */
	private PublicKey rawdataToPublicKey(ECParameterSpec parameter, byte[] data) {
	
		try {
			ECPoint p = parameter.getCurve().decodePoint(data);
			KeySpec keyspec = new ECPublicKeySpec(p, (ECParameterSpec)parameter);
			
			return KeyFactory.getInstance("ECDH","BC").generatePublic(keyspec);
			
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		
		return null;
	}
	/* Функция инициализирует приватный ключ EC
					На вход принимает массив байт */
	private PrivateKey rawdataToPrivateKey(ECParameterSpec parameter, byte[] data) {
		
		try {
			KeySpec keyspec = new ECPrivateKeySpec(new BigInteger(data), (ECParameterSpec)parameter);
			
			return KeyFactory.getInstance("ECDH","BC").generatePrivate(keyspec);
			
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		
		return null;
	}
	/* Конкатенация массивов байт */
	private byte[] concatArray(byte[] a, byte[] b) {
		byte[] r = new byte[a.length + b.length];
		System.arraycopy(a, 0, r, 0, a.length);
		System.arraycopy(b, 0, r, a.length, b.length);
		return r;
	}
}
