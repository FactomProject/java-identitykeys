# java-identitykeys
A small module of tools to generate and use key pairs for Factom Identities.

## Usage
Each instance of java-identitykeys can have a single Ed25519 key pair loaded into memory. Once a key is loaded, you can use the included functions to display information about the key as well as to sign and verify transactions.

### Creating a new Key
To create a new identity key, use the `setAddressWithNewKey()` method. This will return a randomly generated `idsec` formated private key.

```
setAddressWithNewKey();
```


### Importing a Private key
There are two options you can use to import an existing private key:

**From 32 byte private key**

An existing key or new byte array can be used to create an `idsec` formatted key.

  ```setAddressFromPrivateKeyBytes(seed);```
 

**From an existing `idsec` key string**

If you have the idsec format key, you can import it using the following command.

  ```setAddressFromPrivateKeyString("idsecXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");```


### Signing and Verification
Once the address has been seet, 4 methods are available to help you sign and verify using those keys. These will retuen the data of the currently loaded key.

**To get idsec formatted string of private key**

  ```  getIDSecAddress();```
  
**To get idsec formatted string of public**

  ```  getIDPubAddress();```
   
**To get private key bytes**

  ```  getIDSecBytes ();```
  
**To get public key bytes**

  ```	getIDPubBytes ();```
  

#### Signing
To sign byte data using private key  (key already loaded from set call)**

  ```   byte[] Signature = new byte[64];
     Signature = signData( bytedata );
   ```

#### Verification
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

## Format of an Identity Key Pair
*Note: the following text is taken from the [Application Identity Specification](https://github.com/FactomProject/FactomDocs/blob/FD-849_PublishNewIdentitySpec/ApplicationIdentity.md)*

For Factom Application Identities, ed25519 keys are used to sign and verify messages. Rather than simply using raw 32 byte arrays for keys, the following encoding scheme is used: 

Pseudo-code for constructing a private key string:
```
prefix_bytes = [0x03, 0x45, 0xf3, 0xd0, 0xd6]              // gives an "idsec" prefix once in base58 
key_bytes = [32 bytes of raw private key]                  // the actual ed25519 private key seed
checksum = sha256( sha256(prefix_bytes + key_bytes) )[:4]  // 4 byte integrity check on the previous 37 bytes

idsec_key_string = base58( prefix_bytes + key_bytes + checksum )
```

Pseudo-code for constructing a public key string:
```
prefix_bytes = [0x03, 0x45, 0xef, 0x9d, 0xe0]              // gives an "idpub" prefix once in base58 
key_bytes = [32 bytes of raw public key]                   // the actual ed25519 public key
checksum = sha256( sha256(prefix_bytes + key_bytes) )[:4]  // 4 byte integrity check on the previous 37 bytes

idpub_key_string = base58( prefix_bytes + key_bytes + checksum )
```

For the sake of human-readability, all characters must be in Bitcoin's base58 character set, the private key will always begin with "idsec", and the public key will always begin with "idpub". Additionally, the checksum at the end serves to signal that a user has incorrectly typed/copied their key.

Example key pair for the private key of all zeros:
- `idsec19zBQP2RjHg8Cb8xH2XHzhsB1a6ZkB23cbS21NSyH9pDbzhnN6 idpub2Cy86teq57qaxHyqLA8jHwe5JqqCvL1HGH4cKRcwSTbymTTh5n`

Example key pair for the private key of all ones:
- `idsec1ARpkDoUCT9vdZuU3y2QafjAJtCsQYbE2d3JDER8Nm56CWk9ix idpub2op91ghJbRLrukBArtxeLJotFgXhc6E21syu3Ef8V7rCcRY5cc`