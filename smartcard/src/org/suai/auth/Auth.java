package org.suai.auth;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

public class Auth extends Applet {

	/* Instruction */
	final static byte APP_CLA = (byte)0xB0;
	final static byte AUTH = (byte)0x20;
	final static byte REGISTRATION = (byte)0x30;
	
	/* Crypto */
	ECPrivateKey privateKey;
	ECPublicKey publicKey;
	byte[] iv;
	byte[] idC; 
	
	RandomData rnd;
	KeyAgreement keyAgr;
	MessageDigest sha256;
	AESKey aesKey;
	Cipher cipher;
	
	/* Fields */
	byte[] pkw;
	byte[] rndData;
	byte[] data;
	short dataLength;
	
	/* Const */
	final static short LENGTH256 = 256;
	final static short LENGTH128 = 128;
	final static short LENGTH64 = 64;
	final static short LENGTH32 = 32;
	final static short LENGTH16 = 16;
	
	final static short pkwLength = 49;
	final static short rndLength = 8;
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new Auth();
	}
	
	public Auth() {
		KeyPair keyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);
		keyPair.genKeyPair();
		privateKey = (ECPrivateKey)keyPair.getPrivate();
		publicKey = (ECPublicKey)keyPair.getPublic();
		
		iv = new byte[LENGTH16];
		for(short i = 0; i < LENGTH16; i++) {
			iv[i] = (byte)0;
		}
		
		rnd = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		idC = new byte[LENGTH16];
		rnd.generateData(idC, (short)0, (short)LENGTH16);
		
		pkw = new byte[pkwLength];
		
		keyAgr = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
		keyAgr.init(privateKey);
		
		sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
		
		aesKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		
		cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		
		data = JCSystem.makeTransientByteArray(LENGTH256, JCSystem.CLEAR_ON_DESELECT);
		dataLength = LENGTH256;
		
		rndData = JCSystem.makeTransientByteArray(rndLength, JCSystem.CLEAR_ON_DESELECT);
		
		register();
	}
	
	public void process(APDU apdu) throws ISOException {
		byte[] buffer = apdu.getBuffer();
		
		if(selectingApplet()) {
			return;
		}
		
		if(buffer[ISO7816.OFFSET_CLA] != APP_CLA) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		switch(buffer[ISO7816.OFFSET_INS]) {
			case AUTH:
				auth(apdu);
				return;
			case REGISTRATION:
				registration(apdu);
				return;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	private void auth(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		
		dataLength = keyAgr.generateSecret(pkw, (short)0, (short)pkwLength, data, (short)0);
		
		rnd.generateData(rndData, (short)0, rndLength);
		Util.arrayCopyNonAtomic(rndData, (short)0, data, (short)dataLength, (short)rndLength);
		Util.arrayCopyNonAtomic(idC, (short)0, data, (short)(dataLength + rndLength), (short)LENGTH16);
		sha256.reset();
		sha256.doFinal(data, (short)0, (short)(dataLength + rndLength + LENGTH16), buffer, (short)0);
		aesKey.setKey(buffer, (short)0);
		
		short trailerLength = (short)(16 - (pkwLength % 16)); 
		Util.arrayCopyNonAtomic(pkw, (short)0, buffer, (short)0, (short)pkwLength);
		for(short i = 0; i < trailerLength; i++) {
			buffer[(short)(pkwLength + i)] = (byte)trailerLength;
		}
		
		cipher.init(aesKey, Cipher.MODE_ENCRYPT, iv, (short)0, (short)LENGTH16);
		cipher.doFinal(buffer, (short)0, (short)(pkwLength + trailerLength), data, (short)0);
		Util.arrayCopyNonAtomic(rndData, (short)0, data, (short)(pkwLength + trailerLength), (short)rndLength);
		
		apdu.setOutgoing();
		apdu.setOutgoingLength((short)(pkwLength + trailerLength + rndLength));
		apdu.sendBytesLong(data, (short)0, (short)(pkwLength + trailerLength + rndLength));
	}
	private void registration(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		
		Util.arrayCopyNonAtomic(buffer, (short)ISO7816.OFFSET_CDATA, 
				pkw, (short)0, (short)pkwLength);
		
		dataLength = keyAgr.generateSecret(pkw, (short)0, (short)pkwLength, data, (short)0);
		
		for(short i = 0; i < rndLength; i++) {
			data[(short)(dataLength + i)] = buffer[(short)(ISO7816.OFFSET_CDATA + pkwLength + i)];
		}
		sha256.reset();
		sha256.doFinal(data, (short)0, (short)(dataLength + rndLength), buffer, (short)0);
		aesKey.setKey(buffer, (short)0);
		
		dataLength = publicKey.getW(data, (short)0);
		
		cipher.init(aesKey, Cipher.MODE_ENCRYPT, iv, (short)0, (short)LENGTH16);
		cipher.doFinal(idC, (short)0, (short)LENGTH16, data, (short)dataLength);
		
		short trailerLength = (short)(16 - (pkwLength % 16)); 
		Util.arrayCopyNonAtomic(pkw, (short)0, buffer, (short)0, (short)pkwLength);
		for(short i = 0; i < trailerLength; i++) {
			buffer[(short)(pkwLength + i)] = (byte)trailerLength;
		}
		cipher.doFinal(buffer, (short)0, (short)(pkwLength + trailerLength), data, (short)(dataLength + LENGTH16));
		
		apdu.setOutgoing();
		apdu.setOutgoingLength((short)(dataLength + LENGTH16 + pkwLength + trailerLength));
		apdu.sendBytesLong(data, (short)0, (short)(dataLength + LENGTH16 + pkwLength + trailerLength));
	}

}
