# java-identitykeys
A small module of tools to generate and use key pairs for Factom Identities.

## Usage
3 options to import private key

seed is 32 byte private key.  An existing key or new byte array can be used.

  ```setAddressFromPrivateKeyBytes(seed);```

if you do not have a key already, this will generate a random one.  
To reload in the future, use the private key using 32 byte seed or idsec format

  ```setAddressWithNewKey();```

if you have the idsec format key

  ```setAddressFromPrivateKeyString("idsecXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");```

now that the address has been seet, 4 get calls are available and a sign and verify using those keys

To get idsec formatted string of private key

  ```  getIDSecAddress();```
  
To get idsec formatted string of public

  ```  getIDPubAddress();```
   
To get private key bytes

  ```  getIDSecBytes ();```
  
To get public key bytes

  ```	getIDPubBytes ();```
  
To sign byte data using private key  (key already loaded from set call)

  ```   byte[] Signature = new byte[64];
     Signature = signData( bytedata );
   ```
To verify signature using public key   (key already loaded from set call)

```
      Boolean valid= verifyData( bytedata, Signature)
```

If you need to load the public key for signature verification
``` 
  setAddressFromPublicKeyString( idpub key string);
 ```
 or
 ```
      setAddressFromPublicKeyBytes(public key bytes);
   ```
   then verify
