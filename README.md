# Encryption
A Java class which provides simple encryption and decryption functionalities using the AES (Advanced Encryption Standard) algorithm. It allows Strings to be securely encrypted and decrypted using a randomly generated key. All methods are static and can be called without instantiating an Encro object.


1. First, a key should be generated, using:
```java
String key = Encro.generateKey();
```

2. Then, encrypt a string, using:
```java
String originalData = "This is a secret message.";
String encryptedData = Encro.encrypt(originalData, key);  // key here refers to the result of Encro.generateKey().
```

3. Finally, when needed, this encrpyted string can be decrypted, using:
 ```java
String decryptedData = Encro.decrypt(encryptedData, key);
```

With the above methods, strings can be securely encrypted and decrypted (so long as the key string is kept secret!).
