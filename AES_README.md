# AES-256-GCM Encryption System

Production-grade, military-level encryption using **AES-256 in GCM mode** (Galois/Counter Mode). This is **real security** suitable for protecting sensitive data.

## 🛡️ Security Features

✅ **AES-256-GCM**: NIST-approved authenticated encryption  
✅ **PBKDF2 Key Derivation**: 100,000 iterations with SHA-256  
✅ **Authenticated Encryption**: Tamper detection included  
✅ **Random Nonces**: Unique IV for each encryption  
✅ **Cross-Language Compatible**: Python and JavaScript implementations  
✅ **Production Ready**: Suitable for sensitive data and real-world use  

## 🎯 What Makes This Secure?

Unlike the simple algorithms in this workspace, AES-256-GCM provides:

1. **Military-Grade Encryption**: Used by governments and militaries worldwide
2. **Authenticated Encryption**: Detects any tampering with encrypted data
3. **Key Derivation**: PBKDF2 with 100K iterations protects against brute-force attacks
4. **Perfect Forward Secrecy**: Random nonces ensure each encryption is unique
5. **NIST Approved**: Meets government and compliance standards

## 🐍 Python Usage

### Installation
```bash
pip install cryptography
```

### Basic Password-Based Encryption
```python
from aes_encrypt import aes_encrypt, aes_decrypt

# Encrypt with password
plaintext = "This is highly sensitive data!"
password = "MyStr0ngP@ssw0rd!"

encrypted = aes_encrypt(plaintext, password)
print(f"Encrypted: {encrypted}")

# Decrypt with same password
decrypted = aes_decrypt(encrypted, password)
print(f"Decrypted: {decrypted}")
```

### Key-Based Encryption (for shared keys)
```python
from aes_encrypt import generate_key, aes_encrypt_with_key, aes_decrypt_with_key

# Generate a 256-bit key
key = generate_key()
print(f"Generated Key: {key}")
# Share this key securely with other party

# Encrypt
encrypted = aes_encrypt_with_key("Secret message", key)

# Decrypt
decrypted = aes_decrypt_with_key(encrypted, key)
```

### Run Tests
```bash
python aes_encrypt.py
```

## 🟨 JavaScript Usage

### Node.js
```javascript
const { aesEncrypt, aesDecrypt, generateKey } = require('./aes_encrypt.js');

// Password-based encryption
(async () => {
    const plaintext = "This is highly sensitive data!";
    const password = "MyStr0ngP@ssw0rd!";
    
    const encrypted = await aesEncrypt(plaintext, password);
    console.log(`Encrypted: ${encrypted}`);
    
    const decrypted = await aesDecrypt(encrypted, password);
    console.log(`Decrypted: ${decrypted}`);
})();
```

### Browser
```html
<!DOCTYPE html>
<html>
<head>
    <script src="aes_encrypt.js"></script>
</head>
<body>
    <script>
        (async () => {
            const encrypted = await aesEncrypt("Secret!", "mypassword");
            console.log(encrypted);
            
            const decrypted = await aesDecrypt(encrypted, "mypassword");
            console.log(decrypted);
        })();
    </script>
</body>
</html>
```

### Run Tests
```bash
node aes_encrypt.js
```

## 🔐 Technical Specifications

| Component | Specification |
|-----------|--------------|
| **Algorithm** | AES-256-GCM |
| **Key Size** | 256 bits (32 bytes) |
| **Nonce Size** | 96 bits (12 bytes) |
| **Authentication Tag** | 128 bits (16 bytes) |
| **Key Derivation** | PBKDF2-HMAC-SHA256 |
| **KDF Iterations** | 100,000 (OWASP minimum) |
| **Salt Size** | 128 bits (16 bytes) |
| **Encoding** | Base64 for text safety |

## 🧪 Cross-Language Verification

The output format is designed for cross-language compatibility:

### Python
```python
from aes_encrypt import aes_encrypt, aes_decrypt

# Use a fixed password for testing
encrypted = aes_encrypt("test message", "shared_password")
# Send encrypted data to JavaScript
```

### JavaScript
```javascript
// Receive encrypted data from Python
const decrypted = await aesDecrypt(encrypted_from_python, "shared_password");
console.log(decrypted); // "test message"
```

**Note**: Each encryption produces different output (due to random nonces), but all can be decrypted with the correct password.

## 📝 Output Format

Encrypted data is packaged as Base64-encoded JSON:

```json
{
    "salt": "base64_encoded_salt",
    "nonce": "base64_encoded_nonce",
    "ciphertext": "base64_encoded_encrypted_data_with_auth_tag"
}
```

For key-based encryption (no password derivation):
```json
{
    "nonce": "base64_encoded_nonce",
    "ciphertext": "base64_encoded_encrypted_data_with_auth_tag"
}
```

## ⚠️ Security Best Practices

### Strong Passwords
✅ **DO**: Use long, complex passwords (minimum 16 characters)  
✅ **DO**: Include uppercase, lowercase, numbers, and symbols  
✅ **DO**: Use unique passwords for different purposes  
❌ **DON'T**: Use dictionary words or common phrases  
❌ **DON'T**: Reuse passwords across systems  

### Key Management
✅ **DO**: Store keys in secure key management systems (AWS KMS, Azure Key Vault)  
✅ **DO**: Use environment variables, never hardcode keys  
✅ **DO**: Rotate keys periodically  
❌ **DON'T**: Store keys in source code or version control  
❌ **DON'T**: Share keys via insecure channels (email, chat)  

### General Security
✅ **DO**: Use HTTPS/TLS for transmitting encrypted data  
✅ **DO**: Implement proper access controls  
✅ **DO**: Log security events for auditing  
❌ **DON'T**: Trust client-side encryption alone  
❌ **DON'T**: Roll your own crypto (use this tested implementation)  

## 🆚 Comparison with Other Methods

| Feature | Adjacent Swap | XOR+Base64 | **AES-256-GCM** |
|---------|--------------|------------|-----------------|
| Security Level | Very Low | Low | **Very High** |
| Use Case | Learning | Obfuscation | **Production** |
| Key Required | Optional | Yes | **Yes** |
| Authenticated | No | No | **Yes** |
| Tamper Detection | No | No | **Yes** |
| NIST Approved | No | No | **Yes** |
| Suitable for Sensitive Data | ❌ | ❌ | **✅** |

## 🔬 How It Works

### 1. Key Derivation (Password Mode)
```
Password + Random Salt → PBKDF2 (100K iterations) → 256-bit Key
```

### 2. Encryption Process
```
Plaintext → UTF-8 Bytes
             ↓
    [AES-256-GCM Encryption]
    Key + Random Nonce
             ↓
    Ciphertext + Auth Tag
             ↓
    Base64 Encode (with salt & nonce)
```

### 3. Decryption Process
```
Base64 Decode → Extract salt, nonce, ciphertext
                         ↓
                 Derive Key from Password
                         ↓
                 [AES-256-GCM Decryption]
                 Verify Auth Tag
                         ↓
                 UTF-8 Decode → Plaintext
```

## 🧪 Test Suite

Both implementations include comprehensive tests:

- ✅ Basic encryption/decryption
- ✅ Unicode and emoji support
- ✅ Wrong password detection
- ✅ Key-based encryption
- ✅ Long text handling
- ✅ Empty string handling
- ✅ Special characters

All tests verify:
- Correct encryption/decryption
- Authentication tag validation
- Error handling
- Cross-platform compatibility

## 📚 Standards & References

- **NIST SP 800-38D**: GCM Mode Specification
- **FIPS 197**: AES Standard
- **RFC 8018**: PBKDF2 Specification
- **OWASP**: Password Storage Cheat Sheet

## 🔗 Related Documentation

- [Main README](README.md) - Overview of all encryption methods
- [COMPARISON](COMPARISON.md) - Side-by-side comparison
- [XOR_README](XOR_README.md) - XOR cipher documentation

## 💡 When to Use This

### ✅ USE AES-256-GCM for:
- Encrypting sensitive user data
- Protecting passwords and credentials
- Securing financial information
- Storing personal identifiable information (PII)
- Meeting compliance requirements (GDPR, HIPAA, PCI-DSS)
- Production applications
- Data at rest encryption
- Secure file storage

### ❌ Don't Need AES-256 for:
- Public data or non-sensitive information
- Educational demonstrations (use simpler methods)
- Data that's already public
- Temporary obfuscation without security requirements

## 📄 License

This is an educational implementation using standard cryptographic libraries. Production use is encouraged with proper security auditing.

## ⚖️ Legal Notice

**Export Controls**: Strong encryption may be subject to export controls in some countries. Ensure compliance with local laws.

**Disclaimer**: While this implementation follows best practices, always conduct security audits for production use.

---

**Last Updated**: November 17, 2025  
**Status**: ✅ Production-ready implementation with comprehensive tests

🔐 **Remember**: This is REAL security. Treat your keys and passwords accordingly!
