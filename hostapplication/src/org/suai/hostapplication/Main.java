package org.suai.hostapplication;

public class Main {

	private static int PKW_LENGTH = 49;
	private static int PKS_LENGTH = 49;
	private static int RND_LENGTH = 8;
	
	private static int LENGTH16 = 16;
	private static int LENGTH64 = 64;
	
	/* Инструкции для команды APDU */
	private static byte[] SELECT = { (byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, (byte)0x08, 
    		(byte)0xD4, (byte)0xD4, (byte)0xD4, (byte)0xD4, (byte)0xD4, (byte)0xD4, (byte)0x01, (byte)0x01 };
	private static byte[] REGISTRATION = { (byte)0xB0, (byte)0x30, (byte)0x00, (byte)0x00, (byte)(PKW_LENGTH + RND_LENGTH) };
	private static byte[] AUTH = { (byte)0xB0, (byte)0x20, (byte)0x00, (byte)0x00, (byte)0x00 };
	
	public static void main(String [] argv) {
		registration();
		auth();
	}
	
	/* Функция для авторизации */
	public static void auth() {
		System.out.println("AUTHORIZATION\n========================\n");
		
		Crypto crypto = new Crypto();
		crypto.loadKey();
		
		Host host = new Host();
		host.connect();
		
		long timeStart = System.nanoTime();
		
		byte[] data = host.sendCommand(SELECT);
		System.out.print("Status SELECT: ");
		disp(host.getStatus(data));
		
		data = host.sendCommand(AUTH);
		System.out.print("\nStatus AUTH: ");
		disp(host.getStatus(data));
		
		long timeEnd = System.nanoTime();
		
		byte[] auth = new byte[LENGTH64];
		System.arraycopy(host.getData(data), 0, auth, 0, LENGTH64);
		
		byte[] rnd = new byte[RND_LENGTH];
		System.arraycopy(host.getData(data), LENGTH64, rnd, 0, RND_LENGTH);
		
		crypto.generateSKforAuth(rnd);
		if(crypto.isAuth(auth)) {
			System.out.println("\n\nAuthentication is successful");
			System.out.println("Authorization successful\n");
			System.out.printf("Total time: %.2f ms (Smart Card)", (double)(timeEnd - timeStart)/1000000.0);
		}
		
		host.disconnect();
	}
	
	/* Функция для регистрации */
	public static void registration() {
		System.out.println("REGISTRATION\n========================\n");
		
		Crypto crypto = new Crypto();
		crypto.loadKey();
		
		Host host = new Host();
		host.connect();
		
		long timeStart = System.nanoTime();
		
		byte[] data = host.sendCommand(SELECT);
		System.out.print("Status SELECT: ");
		disp(host.getStatus(data));
		
		byte[] rnd = crypto.generateRnd(RND_LENGTH);
		data = host.sendCommand(REGISTRATION, concatArray(crypto.getPK(), rnd));
		System.out.print("\nStatus REGISTRATION: ");
		disp(host.getStatus(data));
		
		long timeEnd = System.nanoTime();
		
		byte[] pks = new byte[PKS_LENGTH];
		System.arraycopy(data, 0, pks, 0, PKS_LENGTH);
		
		byte[] eidC = new byte[LENGTH16];
		System.arraycopy(data, PKS_LENGTH, eidC, 0, LENGTH16);
		
		byte[] auth = new byte[LENGTH64];
		System.arraycopy(data, (PKS_LENGTH + LENGTH16), auth, 0, LENGTH64);
		
		crypto.setPKS(pks);
		crypto.generateSK(rnd);
		if(crypto.isAuth(auth)) {
			System.out.println("\n\nAuthentication is successful");
			crypto.setIDC(eidC);
			System.out.println("Registration successful\n");
			System.out.printf("Total time: %.2f ms (Smart Card)", (double)(timeEnd - timeStart)/1000000.0);
		}
		
		host.disconnect();
	}
	
	private static void disp(byte[] data) {
		for(int i = 0; i < data.length; i++) {
			System.out.printf("%02X", data[i]);
		}
	}
	private static byte[] concatArray(byte[] a, byte[] b) {
		byte[] r = new byte[a.length + b.length];
		System.arraycopy(a, 0, r, 0, a.length);
		System.arraycopy(b, 0, r, a.length, b.length);
		return r;
	}
}

