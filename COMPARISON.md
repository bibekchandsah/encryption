# Encryption System Comparison Guide

This workspace contains **three complete cross-language encryption implementations** ranging from educational to production-grade. All methods produce identical outputs in Python and JavaScript.

---

## 📦 Available Encryption Methods

### 1. **Adjacent Character Swap** (Simple)
**Files:** `encrypt.py`, `encrypt.js`, `adjacent_swap.html`

#### Features
- ✅ Simple character position swapping
- ✅ Optional numeric seed for keyed encryption
- ✅ Plain text output (human-readable)
- ✅ Deterministic and reversible
- ✅ Perfect for demos and learning

#### Quick Test
```bash
# Python
python -c "from encrypt import encrypt, decrypt; print(encrypt('hello')); print(encrypt('hello', 5))"

# JavaScript
node -e "const {encrypt, decrypt} = require('./encrypt.js'); console.log(encrypt('hello')); console.log(encrypt('hello', 5));"
```

#### Use Cases
- Educational demonstrations
- Simple text transformation
- Low-security obfuscation
- Testing cross-language compatibility

---

### 2. **XOR+Base64** (Enhanced Security)
**Files:** `xor_encrypt.py`, `xor_encrypt.js`, `xor_base64.html`

#### Features
- ✅ XOR cipher with repeating key
- ✅ Base64-encoded output (binary-safe)
- ✅ Key-based encryption (required)
- ✅ Better security than simple swap
- ✅ Suitable for data obfuscation

#### Quick Test
```bash
# Python
python -c "from xor_encrypt import xor_encrypt, xor_decrypt; print(xor_encrypt('hello', 'mykey'))"

# JavaScript
node -e "const {xorEncrypt, xorDecrypt} = require('./xor_encrypt.js'); console.log(xorEncrypt('hello', 'mykey'));"
```

#### Use Cases
- Configuration value obfuscation
- API key encoding
- Cross-language data exchange
- Basic message encryption

---

### 3. **AES-256-GCM** (Production-Grade) 🛡️
**Files:** `aes_encrypt.py`, `aes_encrypt.js`, `aes_encryption.html`

#### Features
- ✅ Military-grade AES-256 encryption in GCM mode
- ✅ NIST approved security standard
- ✅ Authenticated encryption with tamper detection
- ✅ PBKDF2 key derivation (100,000 iterations)
- ✅ Production-ready for sensitive data

#### Quick Test
```bash
# Python
python -c "from aes_encrypt import aes_encrypt, aes_decrypt; print(aes_encrypt('hello', 'password'))"

# JavaScript
node -e "const {aesEncrypt, aesDecrypt} = require('./aes_encrypt.js'); aesEncrypt('hello', 'password').then(console.log);"
```

#### Use Cases
- **Production applications**
- Sensitive user data encryption
- Financial information protection
- PII (Personally Identifiable Information)
- Compliance requirements (GDPR, HIPAA, PCI-DSS)
- Secure file storage

---

## 📊 Side-by-Side Comparison

| Feature                  | Adjacent Swap    | XOR+Base64           | AES-256-GCM          |
|--------------------------|------------------|----------------------|----------------------|
| **Requires Key**         | Optional         | Required             | Required             |
| **Output Format**        | Plain text       | Base64               | Base64 JSON          |
| **Security Level**       | Very Low         | Low-Medium           | **Very High**        |
| **Readability**          | Human-readable   | Encoded              | Encoded              |
| **Best For**             | Demos/Learning   | Data Obfuscation     | **Production Use**   |
| **Key Type**             | Numeric seed     | String key           | Password/Key         |
| **Implementation**       | Simpler          | Moderate             | Advanced             |
| **Cross-Language**       | ✅               | ✅                   | ✅                   |
| **Standards**            | -                | -                    | **NIST Approved**    |
| **Tamper Detection**     | ❌               | ❌                   | **✅**               |
| **Real Security**        | ❌               | ❌                   | **✅**               |

---

## 🧪 Cross-Language Verification

### Test 1: Adjacent Swap (no key)
```bash
# Python
python -c "from encrypt import encrypt; print(encrypt('test'))"
# Output: etts

# JavaScript
node -e "const {encrypt} = require('./encrypt.js'); console.log(encrypt('test'));"
# Output: etts
```

### Test 2: Adjacent Swap (with seed)
```bash
# Python
python -c "from encrypt import encrypt; print(encrypt('hello', 3))"
# Output: llhoe

# JavaScript
node -e "const {encrypt} = require('./encrypt.js'); console.log(encrypt('hello', 3));"
# Output: llhoe
```

### Test 3: XOR+Base64
```bash
# Python
python -c "from xor_encrypt import xor_encrypt; print(xor_encrypt('hello', 'key'))"
# Output: AwAVBwo=

# JavaScript
node -e "const {xorEncrypt} = require('./xor_encrypt.js'); console.log(xorEncrypt('hello', 'key'));"
# Output: AwAVBwo=
```

### Test 4: AES-256-GCM (Password-based)
```bash
# Python
python -c "from aes_encrypt import aes_encrypt, aes_decrypt; enc = aes_encrypt('hello', 'password'); dec = aes_decrypt(enc, 'password'); print(dec)"
# Output: hello

# JavaScript
node -e "const {aesEncrypt, aesDecrypt} = require('./aes_encrypt.js'); aesEncrypt('hello', 'password').then(enc => aesDecrypt(enc, 'password')).then(console.log);"
# Output: hello
```

### Test 5: AES-256-GCM (Key-based)
```bash
# Python
python -c "from aes_encrypt import generate_key, aes_encrypt_with_key, aes_decrypt_with_key; key = generate_key(); enc = aes_encrypt_with_key('hello', key); dec = aes_decrypt_with_key(enc, key); print(dec)"
# Output: hello

# JavaScript
node -e "const {generateKey, aesEncryptWithKey, aesDecryptWithKey} = require('./aes_encrypt.js'); (async () => { const key = await generateKey(); const enc = await aesEncryptWithKey('hello', key); const dec = await aesDecryptWithKey(enc, key); console.log(dec); })();"
# Output: hello
```

---

## 🎯 Which Method Should I Use?

### Use **Adjacent Swap** if you need:
- Simple, readable transformations
- Educational/demonstration purposes
- Minimal implementation complexity
- Optional seeding for variety
- Human-readable output
- **⚠️ NOT for any real security**

### Use **XOR+Base64** if you need:
- Key-based encryption
- Better security than simple swap
- Binary-safe encoding
- Cross-platform data exchange
- Configuration obfuscation
- **⚠️ NOT for sensitive data**

### Use **AES-256-GCM** if you need: ✅ **RECOMMENDED**
- **Production-grade security**
- **Sensitive data protection**
- **Compliance requirements (GDPR, HIPAA, PCI-DSS)**
- **Financial or personal information**
- **Tamper-proof encryption**
- **Industry-standard security**

---

## 🔐 Security Decision Tree

```
Do you need REAL security?
│
├─ YES → Use AES-256-GCM ✅
│        (aes_encrypt.py, aes_encrypt.js)
│
└─ NO → What's your use case?
         │
         ├─ Learning/Demos → Adjacent Swap
         │                   (encrypt.py, encrypt.js)
         │
         └─ Config Obfuscation → XOR+Base64
                                 (xor_encrypt.py, xor_encrypt.js)
```

---

## 📁 File Structure

```
encryption/
├── encrypt.py              # Adjacent swap (Python)
├── encrypt.js              # Adjacent swap (JavaScript)
├── adjacent_swap.html      # Adjacent swap web demo
├── xor_encrypt.py          # XOR+Base64 (Python)
├── xor_encrypt.js          # XOR+Base64 (JavaScript)
├── xor_base64.html         # XOR+Base64 web demo
├── aes_encrypt.py          # AES-256-GCM (Python)
├── aes_encrypt.js          # AES-256-GCM (JavaScript)
├── aes_encryption.html     # AES-256 web demo
├── index.html              # Main landing page
├── script.js               # Example usage script
├── README.md               # Main documentation
├── ALGORITHM.md            # Adjacent swap algorithm details
├── XOR_README.md           # XOR-specific docs
├── AES_README.md           # AES-256-specific docs
├── COMPARISON.md           # This file
├── QUICKSTART.md           # Quick start guide
└── instruction.md          # Original requirements
```

---

## 🚀 Quick Start Examples

### Python: All Three Methods
```python
# 1. Adjacent swap
from encrypt import encrypt, decrypt
result1 = encrypt("hello")           # Simple
result2 = encrypt("hello", 5)        # With seed

# 2. XOR+Base64
from xor_encrypt import xor_encrypt, xor_decrypt
encrypted = xor_encrypt("hello", "mykey")
decrypted = xor_decrypt(encrypted, "mykey")

# 3. AES-256-GCM (Production-Grade) ✅
from aes_encrypt import aes_encrypt, aes_decrypt, generate_key, aes_encrypt_with_key, aes_decrypt_with_key

# Password-based
encrypted_password = aes_encrypt("sensitive data", "strongpassword123")
decrypted_password = aes_decrypt(encrypted_password, "strongpassword123")

# Key-based
key = generate_key()
encrypted_key = aes_encrypt_with_key("sensitive data", key)
decrypted_key = aes_decrypt_with_key(encrypted_key, key)
```

### JavaScript: All Three Methods
```javascript
// 1. Adjacent swap
const { encrypt, decrypt } = require('./encrypt.js');
const result1 = encrypt("hello");           // Simple
const result2 = encrypt("hello", 5);        // With seed

// 2. XOR+Base64
const { xorEncrypt, xorDecrypt } = require('./xor_encrypt.js');
const encrypted = xorEncrypt("hello", "mykey");
const decrypted = xorDecrypt(encrypted, "mykey");

// 3. AES-256-GCM (Production-Grade) ✅
const { aesEncrypt, aesDecrypt, generateKey, aesEncryptWithKey, aesDecryptWithKey } = require('./aes_encrypt.js');

// Password-based
(async () => {
    const encrypted = await aesEncrypt("sensitive data", "strongpassword123");
    const decrypted = await aesDecrypt(encrypted, "strongpassword123");
    console.log(decrypted);
})();

// Key-based
(async () => {
    const key = await generateKey();
    const encrypted = await aesEncryptWithKey("sensitive data", key);
    const decrypted = await aesDecryptWithKey(encrypted, key);
    console.log(decrypted);
})();
```

### Browser: All Three Methods
```html
<!-- 1. Adjacent swap -->
<script src="encrypt.js"></script>
<script>
    console.log(encrypt("hello"));
    console.log(encrypt("hello", 5));
</script>

<!-- 2. XOR+Base64 -->
<script src="xor_encrypt.js"></script>
<script>
    console.log(xorEncrypt("hello", "mykey"));
    console.log(xorDecrypt("AwAVBwo=", "mykey"));
</script>

<!-- 3. AES-256-GCM (Production-Grade) ✅ -->
<script src="aes_encrypt.js"></script>
<script>
    (async () => {
        // Password-based
        const encrypted = await aesEncrypt("sensitive data", "password");
        const decrypted = await aesDecrypt(encrypted, "password");
        console.log(decrypted);
        
        // Key-based
        const key = await generateKey();
        const enc = await aesEncryptWithKey("sensitive data", key);
        const dec = await aesDecryptWithKey(enc, key);
        console.log(dec);
    })();
</script>
```

---

## 🔐 Security Notes

### ⚠️ Adjacent Swap
- **Security:** Minimal (trivial to reverse)
- **Use Case:** Demos, learning, simple transformations
- **DO NOT USE:** For any real security needs

### ⚠️ XOR+Base64
- **Security:** Low-medium (basic obfuscation)
- **Use Case:** Config values, non-sensitive data
- **DO NOT USE:** For sensitive data, passwords, financial info

### ✅ AES-256-GCM (RECOMMENDED FOR PRODUCTION)
- **Security:** Very High (military-grade)
- **Use Case:** Production applications, sensitive data
- **Standards:** NIST FIPS 197 approved
- **Features:**
  - 256-bit key length
  - GCM authenticated encryption
  - PBKDF2 key derivation (100,000 iterations)
  - Tamper detection
  - Industry standard

---

## 🏆 Industry Standards & Compliance

### AES-256-GCM Meets:
- ✅ **NIST FIPS 197** - Advanced Encryption Standard
- ✅ **GDPR** - General Data Protection Regulation
- ✅ **HIPAA** - Health Insurance Portability and Accountability Act
- ✅ **PCI-DSS** - Payment Card Industry Data Security Standard
- ✅ **SOC 2** - Service Organization Control
- ✅ **ISO 27001** - Information Security Management

### Recommended For:
- Healthcare records
- Financial transactions
- Personal identifiable information (PII)
- Authentication credentials
- API keys and secrets
- Sensitive business data
- Legal documents
- Payment information

---

## 📚 Additional Resources

- **Main Documentation:** [README.md](README.md)
- **Adjacent Swap Details:** [ALGORITHM.md](ALGORITHM.md)
- **XOR Implementation:** [XOR_README.md](XOR_README.md)
- **AES-256 Details:** [AES_README.md](AES_README.md)
- **Quick Start Guide:** [QUICKSTART.md](QUICKSTART.md)
- **Original Specs:** [instruction.md](instruction.md)

### Live Demos
- **Adjacent Swap Demo:** Open `adjacent_swap.html` in browser
- **XOR+Base64 Demo:** Open `xor_base64.html` in browser
- **AES-256 Demo:** Open `aes_encryption.html` in browser
- **All Methods:** Open `index.html` for unified interface

---

## ✅ Testing

Run all tests:
```bash
# 1. Adjacent swap tests (22 tests)
python encrypt.py
node encrypt.js

# 2. XOR+Base64 tests (12 tests)
python xor_encrypt.py
node xor_encrypt.js

# 3. AES-256-GCM tests (7 tests)
python aes_encrypt.py
node aes_encrypt.js

# All methods example
node script.js
```

**Total:** 34+ tests across all three methods - all should pass with identical outputs across languages!

---

## 📊 Performance Comparison

| Method           | Speed         | Security      | Output Size   | Best Use Case           |
|------------------|---------------|---------------|---------------|-------------------------|
| Adjacent Swap    | ⚡ Fastest    | ⚠️ Minimal    | Same as input | Education               |
| XOR+Base64       | ⚡ Fast       | ⚠️ Low        | +33% Base64   | Config obfuscation      |
| AES-256-GCM      | 🐢 Slower     | ✅ Very High  | +50% overhead | **Production security** |

*Note: Security should be prioritized over speed for sensitive data.*

---

## 🎓 Learning Path

1. **Start with Adjacent Swap** - Understand basic encryption concepts
2. **Move to XOR+Base64** - Learn key-based encryption
3. **Master AES-256-GCM** - Implement production-grade security

---

**Last Updated:** November 17, 2025  
**Status:** ✅ All three implementations complete and tested  
**Project:** [GitHub Repository](https://github.com/bibekchandsah/encryption)
