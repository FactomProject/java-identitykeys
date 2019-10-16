package com.factom.signatureapp;

import harmony_connect_client.*;
import harmony_connect_client.api.EntriesApi;
import harmony_connect_client.auth.*;
import harmony_connect_client.model.*;
import harmony_connect_client.model.EntryCreate;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Properties;
import java.util.TimeZone;
import net.i2p.crypto.eddsa.*;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

public class App {
    private static String idsecString = "";
    private static String idpubString = "";
    private static byte[] privateBytes;
    private static byte[] publicBytes;
    private static EdDSAPublicKey publicKey;
    private static EdDSAPrivateKey privateKey;

    public static void main(String[] args) {
        InputStream inputStream = null;

        try {
            Properties prop = new Properties();

            inputStream = App.class.getClassLoader().getResourceAsStream("config.properties");
            if (inputStream != null) {
                prop.load(inputStream);
            } else {
                throw new FileNotFoundException("config.properties file not found in the classpath");
            }

            String baseurl = prop.getProperty("baseurl");
            String appid = prop.getProperty("appid");
            String appkey = prop.getProperty("appkey");
            String signerkey = prop.getProperty("signerkey");
            String signerchainid = prop.getProperty("signerchainid");
            String entrychainid = prop.getProperty("entrychainid");

            ApiClient defaultClient = Configuration.getDefaultApiClient();
            defaultClient.setBasePath(baseurl);
            ApiKeyAuth AppId = (ApiKeyAuth) defaultClient.getAuthentication("AppId");
            AppId.setApiKey(appid);
            ApiKeyAuth AppKey = (ApiKeyAuth) defaultClient.getAuthentication("AppKey");
            AppKey.setApiKey(appkey);

            makeSignedEntry(entrychainid, // Chain id for entry
                    "EXAMPLE ENTRY CONTENT", // String representation of entry content
                    signerkey, // Signer private key ("idsec...")
                    signerchainid); // Signer identity chain id
        } catch (Exception e) {
            System.out.println("Exception: " + e);
        } finally {
            try {
                if (inputStream != null) {
                    inputStream.close();
                }
            } catch (Exception e) {
                System.out.println("Exception: " + e);
            }
        }
    }

    public static void makeSignedEntry(String chainId, String entryContent, String signerPrivateKey,
            String signerChainId) {
        makeSignedEntry(chainId, entryContent, signerPrivateKey, signerChainId, null);
    }

    public static void makeSignedEntry(String chainId, String entryContent, String signerPrivateKey,
            String signerChainId, String[] additionalExtIds) {
        EntriesApi entriesAPI = new EntriesApi();
        setIdentityFromPrivateKeyString(signerPrivateKey);

        Base64.Encoder encoder = Base64.getEncoder();
        String isoTimestamp = currentTime();

        EntryCreate entryCreate = new EntryCreate();
        entryCreate.addExternalIdsItem("U2lnbmVkRW50cnk="); // "SignedEntry"
        entryCreate.addExternalIdsItem("AQ=="); // "0x01"
        entryCreate.addExternalIdsItem(encoder.encodeToString(signerChainId.getBytes()));
        entryCreate.addExternalIdsItem(encoder.encodeToString(idpubString.getBytes()));

        // The signed content consists of a concatenation of the Signer Chain ID, the
        // Content, and the ISO-8601 timestamp.
        String signatureInput = signerChainId + entryContent + isoTimestamp;
        byte[] signatureOutput = signData(signatureInput.getBytes());

        entryCreate.addExternalIdsItem(encoder.encodeToString(signatureOutput));
        entryCreate.addExternalIdsItem(encoder.encodeToString(isoTimestamp.getBytes()));

        if (null != additionalExtIds && additionalExtIds.length > 0) {
            for (String additionalExtId : additionalExtIds) {
                entryCreate.addExternalIdsItem(encoder.encodeToString(additionalExtId.getBytes()));
            }
        }

        entryCreate.content(encoder.encodeToString(entryContent.getBytes()));
        try {
            EntryShort response = entriesAPI.postEntryToChainID(chainId, entryCreate);
            System.out.println(response.toString());
        } catch (Exception e) {
            System.out.println("Exception: " + e);
        }
    }

    public static String currentTime() {
        // Input
        Date date = new Date(System.currentTimeMillis());

        // Conversion
        SimpleDateFormat sdf;
        sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
        sdf.setTimeZone(TimeZone.getTimeZone("CST"));
        return sdf.format(date);
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
     * idpubString CLEARS PRIVATE KEY VALUES AS THEY MAY NOT MATCH * to get the
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
     * byte private key bytes Sets public key string and public bytes (now you can
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