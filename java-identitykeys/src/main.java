import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;

import net.i2p.crypto.eddsa.*;

import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

public class main {

	/**
	 * @param test If "test" is used on commandline, the testCalls function will run
	 *             otherwise, include jar file in project and call public functions
	 *             for key handling use one of the set functions before signing,
	 *             verifying, or get calls
	 */

	private static String idsecString = "";
	private static String idpubString = "";
	private static byte[] privateBytes;
	private static byte[] publicBytes;
	private static EdDSAPublicKey publicKey;
	private static EdDSAPrivateKey privateKey;

	public static void main(String[] args) {

		// if (args.length > 0) {
		// if (args[0].equals("test")) {
		testCalls();
		// }

		// }

		// possible TODO, add commandline tools

	}

	public static void testCalls() {

		// byte[] privateBytes = new byte[32];
		// byte[] publicBytes = new byte[32];

		// you decide what the private key bytes are.
		// this takes 32 bytes
		// a private key can technically be 64 bytes
		// that is 32 bytes private + 32 bytes public
		// if your key is 64 bytes, send the first 32.
		// it SHOULD set public to the same bytes
		// as the last half of your 64

		// byte[] seed = sha256Bytes("test".getBytes());
		// System.out.println(bytesToHex(seed));
		// if you are using bytes for the private key
		// setIdentityFromPrivateKeyBytes(seed);

		// if you have no private key
		// setIdentityWithNewKey()

		// if you are using idsecXXX key
		setIdentityFromPrivateKeyString("idsec2NF5DhT2EKTo4ap7xFYNoVNDwWHygX8UdJim3RnURmkVX3LCiF");

		System.out.println("sec:" + idsecString);
		System.out.println(bytesToHex(privateBytes));
		System.out.println("");
		System.out.println("pub:" + idpubString);
		System.out.println(bytesToHex(publicBytes));
		System.out.println("");

		// test signature
		// this works AFTER one of the setIdentity calls
		byte[] sig = signData("hi".getBytes());
		System.out.println("Signature:" + bytesToHex(sig));
		Boolean validSig = verifyData("hi".getBytes(), sig);
		System.out.println("Signature Passed:" + validSig);

		// test again with 'new' public key
		// you don't need to feed this back in,
		// I am simply using the identity I already
		// have in idpub.

		setIdentityFromPublicKeyString(getIDPubString());
		validSig = verifyData("hi".getBytes(), sig);
		System.out.println("Signature Passed:" + idpubString);
		System.out.println("Signature Passed:" + validSig);

		// and again, loading public key as bytes
		setIdentityFromPublicKeyBytes(getIDPubBytes());
		validSig = verifyData("hi".getBytes(), sig);
		System.out.println("Signature Passed:" + idpubString);
		System.out.println("Signature Passed:" + validSig);

		// base64 is a java library. use something similar to the below
		// import java.util.Base64;
		// String encoded = Base64.getEncoder().encodeToString(publicBytes);
		// byte[] decoded = Base64.getDecoder().decode(encoded);

	}

	// get calls for identity values
	public static String getIDSecString() {
		return idsecString;
	}

	public static String getIDPubString() {
		return idpubString;
	}

	public static byte[] getIDSecBytes() {
		return privateBytes;
	}

	public static byte[] getIDPubBytes() {
		return publicBytes;
	}

	/**
	 * getIdentityFromKey - takes a 32 byte array holding the private key. if
	 * your private key is 64 bytes, it is the first 32
	 *
	 * @param key     byte[]
	 * @param keyType String either idsec or idpub
	 * @return idsec public key format or idpub public key format
	 *
	 **/
	public static String getIdentityFromKey(byte[] key, String keyType) {
		String identity = "";
		byte[] appendPrefix = new byte[37];
		byte[] appendSuffix = new byte[41];
		byte[] firstHash;

		if (keyType.equals("idsec")) {
			appendPrefix[0] = (byte) 0x03; // i
			appendPrefix[1] = (byte) 0x45; // d
			appendPrefix[2] = (byte) 0xf3; // s
			appendPrefix[3] = (byte) 0xd0; // e
			appendPrefix[4] = (byte) 0xd6; // c
		} else if (keyType.equals("idpub")) {
			appendPrefix[0] = (byte) 0x03; // i
			appendPrefix[1] = (byte) 0x45; // d
			appendPrefix[2] = (byte) 0xef; // p
			appendPrefix[3] = (byte) 0x9d; // u
			appendPrefix[4] = (byte) 0xe0; // b
		} else {
			return ""; // only works with those prefixes
		}

		System.arraycopy(key, 0, appendPrefix, 5, 32);
		firstHash = sha256Bytes(sha256Bytes(appendPrefix));
		System.arraycopy(appendPrefix, 0, appendSuffix, 0, 37);
		appendSuffix[37] = firstHash[0];
		appendSuffix[38] = firstHash[1];
		appendSuffix[39] = firstHash[2];
		appendSuffix[40] = firstHash[3];

		identity = Encode256to58(appendSuffix);
		return identity;

	}

	/**
	 * setIdentityWithNewKey - generates random seed then calls
	 * setIdentityFromPrivateKeyBytes and created the public/private key pairs seed
	 * is the private key * to get the keys, call get functions after set
	 *
	 * @return idsec public key format or idpub public key format
	 *
	 **/
	public static void setIdentityWithNewKey() {

		try {

			SecureRandom random = new SecureRandom();
			byte seed[] = random.generateSeed(32);
			byte seedHash[] = sha256Bytes(seed);
			setIdentityFromPrivateKeyBytes(seedHash);

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/**
	 * setIdentityFromPrivateKeyBytes - generates public key that goes with the private key
	 * (seed) and creates the public/private key pairs * to get the keys, call get
	 * functions after set
	 *
	 * @param seed. 32 byte private key
	 * @return none. user get calls to access keys
	 *
	 **/

	public static void setIdentityFromPrivateKeyBytes(byte[] seed) {

		try {

			EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("ed25519-sha-512");
			EdDSAPrivateKeySpec privateKeySpec = new EdDSAPrivateKeySpec(seed, spec);
			EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(privateKeySpec.getA(), spec);
			publicKey = new EdDSAPublicKey(pubKeySpec);
			privateKey = new EdDSAPrivateKey(privateKeySpec);

			privateBytes = seed;
			System.out.println(bytesToHex(privateBytes));
			publicBytes = publicKey.getAbyte();

			idsecString = getIdentityFromKey(privateBytes, "idsec");
			idpubString = getIdentityFromKey(publicBytes, "idpub");

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/**
	 * setIdentityFromPrivateKeyString - verifies private key is valid then pulls 32
	 * byte private key bytes * from idsec format and calls
	 * setIdentityFromPrivateKeyBytes and creates the public/private key pairs * to
	 * get the keys, call get functions after set
	 *
	 * @param privateKeyString idsec formatted string
	 * @return none. user get calls to access keys
	 *
	 **/
	public static void setIdentityFromPrivateKeyString(String privateKeyString) {

		try {

			byte[] b256 = new byte[41];
			byte[] hash = new byte[32];

			b256 = Encode58to256(privateKeyString);

			System.arraycopy(b256, 5, hash, 0, 32);
			System.out.println(bytesToHex(hash));

			setIdentityFromPrivateKeyBytes(hash);

			if (privateKeyString.equals(idsecString)) {
				return;
			} else {
				// key problem.
				System.out.println("Key Problem");
			}

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/**
	 * setIdentityFromPublicKeyBytes - sets public key bytes creates idpub format for
	 * idpubIdentity CLEARS PRIVATE KEY VALUES AS THEY MAY NOT MATCH * to get the
	 * keys, call get functions after set
	 *
	 * @param privateKeyString idsec formatted string
	 * @return none. user get calls to access keys
	 *
	 **/
	public static void setIdentityFromPublicKeyBytes(byte[] publicKeyBytes) {

		try {

			publicBytes = publicKeyBytes;
			idpubString = getIdentityFromKey(publicKeyBytes, "idpub");
			privateBytes = null;
			idsecString = "";

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/**
	 * setIdentityFromPublicKeyString - verifies public key is valid then pulls 32
	 * byte private key bytes Sets public string and public bytes (now you can
	 * verify signature) CLEARS PRIVATE KEY VALUES AS THEY MAY NOT MATCH * to get
	 * the keys, call get functions after set
	 *
	 * @param privateKeyString idsec formatted string
	 * @return none. user get calls to access keys
	 *
	 **/
	public static void setIdentityFromPublicKeyString(String publicKeyString) {

		try {

			byte[] b256 = new byte[41];
			byte[] hash = new byte[32];

			b256 = Encode58to256(publicKeyString);

			System.arraycopy(b256, 5, hash, 0, 32);
			System.out.println(bytesToHex(hash));

			publicBytes = hash;
			idpubString = getIdentityFromKey(hash, "idpub");
			privateBytes = null;
			idsecString = "";

			return;

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	// signature stuff

	/**
	 * signData - takes data as byte string to be signed by the private key that is
	 * already loaded into api
	 *
	 * @param data byte[]
	 *
	 * @return 64 byte signature
	 *
	 **/

	public static byte[] signData(byte[] data) {
		byte[] resp = new byte[0];
		try {
			Signature sgr = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));

			sgr.initSign(privateKey);
			sgr.update(data);
			return sgr.sign();
		} catch (Exception e) {
			return resp;
		}

	}

	/**
	 * verifyData - verifies that the data was signed by the private key sig is
	 * probably found in api.publickeybytes if you are checking against your private
	 * key
	 *
	 * @param data byte[]
	 * @param sig  byte[]
	 *
	 * @return true or false
	 *
	 **/

	public static Boolean verifyData(byte[] data, byte[] sig) {

		try {
			Signature sgr = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
			sgr.initVerify(publicKey);
			sgr.update(data);
			if (sgr.verify(sig)) {
				return true;
			} else {
				return false;
			}

		} catch (Exception e) {
			return false;
		}

	}

	// utility stuff

	private static String Encode256to58(byte[] data) {
		// you are doing signed integer math here. it may be unsigned in the
		// rest of the world. watch it
		String code_string = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
		String strResponse = "";
		int unsig = 0;
		byte[] response = new byte[55];
		// move bytestring to integer
		BigInteger intData = BigInteger.valueOf(0);
		for (int i = 0; i < data.length; i++) {
			intData = intData.multiply(BigInteger.valueOf(256));
			unsig = data[i] & 0xff;
			intData = intData.add((BigInteger.valueOf(unsig)));
		}

		// Encode BigInteger to Base58 string

		int j = 0;
		while (intData.compareTo(BigInteger.valueOf(0)) > 0) {
			byte remainder = (intData.mod(BigInteger.valueOf(58))).byteValue();
			intData = intData.divide(BigInteger.valueOf(58));
			strResponse = code_string.substring(remainder, remainder + 1) + strResponse;
			response[j] = remainder;
			j = j + 1;
		}
		return strResponse;
	}

	private static byte[] Encode58to256(String data) {
		// you are doing signed integer math here. it may be unsigned in the rest of the
		// world. watch it
		String code_string = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
		int pos = 0;
		byte[] response = new byte[39];
		// move bytestring to integer
		BigInteger intData = BigInteger.valueOf(0);
		for (int i = 0; i < data.length(); i++) {
			pos = code_string.indexOf(data.substring(i, i + 1));
			intData = intData.multiply(BigInteger.valueOf(58));
			intData = intData.add(BigInteger.valueOf(pos));
			// unsig=data[i] ;
		}

		// Encode BigInteger to Base256

		byte[] tmp = new byte[1];
		while (intData.compareTo(BigInteger.valueOf(0)) > 0) {
			int remainder = intData.mod(BigInteger.valueOf(256)).intValueExact();
			intData = intData.subtract(BigInteger.valueOf(remainder));
			intData = intData.divide(BigInteger.valueOf(256));
			tmp[0] = (byte) remainder;
			response = appendByteArrays(tmp, response);
			// response[j] = remainder ;
		}
		return response;
	}

	private static byte[] appendByteArrays(byte[] first, byte[] second) {
		byte[] temp = new byte[first.length + second.length];
		System.arraycopy(first, 0, temp, 0, first.length);
		System.arraycopy(second, 0, temp, first.length, second.length);
		return temp;
	}

	private static byte[] sha256Bytes(byte[] base) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(base);

			return hash;
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

	private static String bytesToHex(byte[] raw) {
		String HexCharacters = "0123456789ABCDEF";
		if (raw == null) {
			return null;
		}
		final StringBuilder hex = new StringBuilder(2 * raw.length);
		for (final byte b : raw) {
			hex.append(HexCharacters.charAt((b & 0xF0) >> 4)).append(HexCharacters.charAt((b & 0x0F)));
		}
		return hex.toString();
	}

}
