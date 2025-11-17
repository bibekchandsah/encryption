# Encryption System Comparison Guide

This workspace contains **two complete cross-language encryption implementations**. Both produce identical outputs in Python and JavaScript.

---

## 📦 Available Encryption Methods

### 1. **Adjacent Character Swap** (Simple)
**Files:** `encrypt.py`, `encrypt.js`, `demo.html`

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
**Files:** `xor_encrypt.py`, `xor_encrypt.js`, `xor_demo.html`

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

## 📊 Side-by-Side Comparison

| Feature                  | Adjacent Swap    | XOR+Base64           |
|--------------------------|------------------|----------------------|
| **Requires Key**         | Optional         | Required             |
| **Output Format**        | Plain text       | Base64               |
| **Security Level**       | Very Low         | Low-Medium           |
| **Readability**          | Human-readable   | Encoded              |
| **Best For**             | Demos/Learning   | Data Obfuscation     |
| **Key Type**             | Numeric seed     | String key           |
| **Implementation**       | Simpler          | Moderate             |
| **Cross-Language**       | ✅               | ✅                   |

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

---

## 🎯 Which Method Should I Use?

### Use **Adjacent Swap** if you need:
- Simple, readable transformations
- Educational/demonstration purposes
- Minimal implementation complexity
- Optional seeding for variety
- Human-readable output

### Use **XOR+Base64** if you need:
- Key-based encryption
- Better security than simple swap
- Binary-safe encoding
- Cross-platform data exchange
- Configuration obfuscation

### Use **Neither** if you need:
- Production-grade security
- Sensitive data protection
- Compliance requirements
- Strong cryptographic guarantees

**For production:** Use established libraries:
- Python: `cryptography`, `PyCryptodome`
- JavaScript: `crypto-js`, `node-crypto`

---

## 📁 File Structure

```
encryption/
├── encrypt.py              # Adjacent swap (Python)
├── encrypt.js              # Adjacent swap (JavaScript)
├── demo.html               # Adjacent swap web demo
├── xor_encrypt.py          # XOR+Base64 (Python)
├── xor_encrypt.js          # XOR+Base64 (JavaScript)
├── xor_demo.html           # XOR+Base64 web demo
├── README.md               # Main documentation
├── XOR_README.md           # XOR-specific docs
├── ALGORITHM.md            # Algorithm details
├── COMPARISON.md           # This file
└── instruction.md          # Original requirements
```

---

## 🚀 Quick Start Examples

### Python: Both Methods
```python
# Adjacent swap
from encrypt import encrypt, decrypt
result1 = encrypt("hello")           # Simple
result2 = encrypt("hello", 5)        # With seed

# XOR+Base64
from xor_encrypt import xor_encrypt, xor_decrypt
encrypted = xor_encrypt("hello", "mykey")
decrypted = xor_decrypt(encrypted, "mykey")
```

### JavaScript: Both Methods
```javascript
// Adjacent swap
const { encrypt, decrypt } = require('./encrypt.js');
const result1 = encrypt("hello");           // Simple
const result2 = encrypt("hello", 5);        // With seed

// XOR+Base64
const { xorEncrypt, xorDecrypt } = require('./xor_encrypt.js');
const encrypted = xorEncrypt("hello", "mykey");
const decrypted = xorDecrypt(encrypted, "mykey");
```

### Browser: Both Methods
```html
<!-- Adjacent swap -->
<script src="encrypt.js"></script>
<script>
    console.log(encrypt("hello"));
    console.log(encrypt("hello", 5));
</script>

<!-- XOR+Base64 -->
<script src="xor_encrypt.js"></script>
<script>
    console.log(xorEncrypt("hello", "mykey"));
    console.log(xorDecrypt("AwAVBwo=", "mykey"));
</script>
```

---

## 🔐 Security Notes

### Adjacent Swap
- **Security:** Minimal (trivial to reverse)
- **Use Case:** Demos, learning, simple transformations
- **DO NOT USE:** For any real security needs

### XOR+Base64
- **Security:** Low-medium (basic obfuscation)
- **Use Case:** Config values, non-sensitive data
- **DO NOT USE:** For sensitive data, passwords, financial info

### ⚠️ For Real Production Security

**Use AES-256 (Advanced Encryption Standard with 256-bit keys):**

#### Python (using `cryptography` library)
```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# AES-256-GCM example
key = os.urandom(32)  # 256-bit key
iv = os.urandom(12)   # 96-bit IV for GCM
cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
```

#### JavaScript (using Web Crypto API)
```javascript
// Browser or Node.js with Web Crypto
const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
);
```

#### Node.js (using built-in crypto)
```javascript
const crypto = require('crypto');
const algorithm = 'aes-256-gcm';
const key = crypto.randomBytes(32);  // 256-bit key
const iv = crypto.randomBytes(16);
```

**Additional Security Standards:**
- **RSA-2048/4096** for asymmetric encryption
- **HTTPS/TLS 1.3** for data in transit
- **bcrypt/Argon2** for password hashing
- **HMAC-SHA256** for message authentication

---

## 📚 Additional Resources

- **Adjacent Swap Details:** [ALGORITHM.md](ALGORITHM.md)
- **XOR Implementation:** [XOR_README.md](XOR_README.md)
- **General Usage:** [README.md](README.md)
- **Original Specs:** [instruction.md](instruction.md)

---

## ✅ Testing

Run all tests:
```bash
# Adjacent swap tests
python encrypt.py
node encrypt.js

# XOR+Base64 tests
python xor_encrypt.py
node xor_encrypt.js
```

All tests should pass with identical outputs across languages!

---

**Last Updated:** November 17, 2025  
**Status:** ✅ All implementations complete and tested
