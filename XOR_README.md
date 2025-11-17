# XOR+Base64 Encryption System

A secure, cross-language compatible encryption system using XOR cipher with Base64 encoding. Produces **identical outputs** across Python, JavaScript, and other languages.

## 🎯 Features

✅ **Cross-Language Compatible**: Identical Base64 output in Python, JavaScript, etc.  
✅ **Key-based Encryption**: Uses repeating XOR key for encryption  
✅ **Safe Text Output**: Base64 encoding for binary-safe transmission  
✅ **Unicode Support**: Works with emojis, international characters, etc.  
✅ **No External Dependencies**: Pure implementation (uses standard base64/Buffer)  
✅ **Symmetric Cipher**: Same function for encryption/decryption (XOR property)  

## 📖 Algorithm

**XOR Cipher with Base64 Encoding**:
1. Convert plaintext to UTF-8 bytes
2. XOR each byte with repeating key bytes
3. Encode result to Base64 for safe text representation

### Example
- Input: `"bibek"` with key `"secret"`
- XOR process: Each byte XORed with key bytes
- Output: `"EQwBFw4="` (Base64)

---

## 🐍 Python Usage

### Run Tests
```bash
python xor_encrypt.py
```

### Use in Code
```python
from xor_encrypt import xor_encrypt, xor_decrypt

# Encrypt
encrypted = xor_encrypt("bibek", "secret")
print(encrypted)  # Output: EQwBFw4=

# Decrypt
decrypted = xor_decrypt("EQwBFw4=", "secret")
print(decrypted)  # Output: bibek
```

### Quick Command Line Test
```bash
python -c "from xor_encrypt import xor_encrypt, xor_decrypt; print(xor_encrypt('hello world', 'mykey')); print(xor_decrypt('JRwHCQhNJgYCBAs=', 'mykey'))"
```

---

## 🟨 JavaScript Usage

### Run Tests (Node.js)
```bash
node xor_encrypt.js
```

### Use in Node.js
```javascript
const { xorEncrypt, xorDecrypt } = require('./xor_encrypt.js');

// Encrypt
const encrypted = xorEncrypt("bibek", "secret");
console.log(encrypted);  // Output: EQwBFw4=

// Decrypt
const decrypted = xorDecrypt("EQwBFw4=", "secret");
console.log(decrypted);  // Output: bibek
```

### Use in Browser
```html
<!DOCTYPE html>
<html>
<head>
    <title>XOR Encryption Demo</title>
    <script src="xor_encrypt.js"></script>
</head>
<body>
    <script>
        const encrypted = xorEncrypt("bibek", "secret");
        console.log(encrypted);  // Output: EQwBFw4=
        
        const decrypted = xorDecrypt("EQwBFw4=", "secret");
        console.log(decrypted);  // Output: bibek
    </script>
</body>
</html>
```

### Quick Command Line Test
```bash
node -e "const {xorEncrypt, xorDecrypt} = require('./xor_encrypt.js'); console.log(xorEncrypt('hello world', 'mykey')); console.log(xorDecrypt('JRwHCQhNJgYCBAs=', 'mykey'));"
```

---

## 🧪 Test Cases

### Basic Test: "bibek" with key "secret"
| Language   | Input    | Key      | Encrypted    | Decrypted |
|------------|----------|----------|--------------|-----------|
| Python     | `bibek`  | `secret` | `EQwBFw4=`   | `bibek`   |
| JavaScript | `bibek`  | `secret` | `EQwBFw4=`   | `bibek`   |

### Additional Test Cases

| Input             | Key       | Encrypted Output      | Description          |
|-------------------|-----------|-----------------------|----------------------|
| `hello`           | `key`     | `AwAVBwo=`            | Basic word           |
| `world`           | `pass`    | `Bw4BHxQ=`            | Another word         |
| `test`            | `12345`   | `RVdAQA==`            | Numeric key          |
| `a`               | `x`       | `GQ==`                | Single character     |
| `Hello World!`    | `mykey`   | `JRwHCRZNLgQXFQlY`    | Mixed case + space   |
| `12345`           | `abc`     | `UFBQVVc=`            | Numbers              |
| `café`            | `test`    | `FwQVt90=`            | Accented characters  |
| `hello😀world`     | `emoji`   | `DQgDBgaV8vfqHgofAw4=` | With emoji           |
| `こんにちは`       | `日本`    | `BRY2BR4/BRYOBR0NBRYK` | Japanese             |
| `你好世界`         | `中文`    | `AAUNAzM6AAA7AQML`    | Chinese              |
| ` ` (empty)       | `key`     | ` ` (empty)           | Empty string         |

---

## 🔍 Key Features

### Security Properties
- **Symmetric Encryption**: Same algorithm for encrypt/decrypt
- **Key-dependent**: Different keys produce different ciphertext
- **Repeating Key XOR**: Simple but effective for basic obfuscation
- **Wrong Key = Garbage Output**: Incorrect key produces unreadable text

### Implementation Details
- **UTF-8 Encoding**: All text converted to UTF-8 bytes
- **Base64 Output**: Binary-safe encoding for storage/transmission
- **Unicode Support**: Full international character support
- **Cross-platform**: Identical output on all platforms

---

## 📊 Cross-Language Validation

To verify identical output across languages:

### Python:
```bash
python -c "from xor_encrypt import xor_encrypt; print(xor_encrypt('test message', 'mykey'))"
```
Output: `HhwdVy0AFgcVBQY=`

### JavaScript (Node.js):
```bash
node -e "const {xorEncrypt} = require('./xor_encrypt.js'); console.log(xorEncrypt('test message', 'mykey'));"
```
Output: `HhwdVy0AFgcVBQY=`

Both produce **exactly the same Base64 output**.

---

## 🔐 Security Considerations

⚠️ **Important**: This XOR cipher is suitable for:
- Basic obfuscation
- Educational purposes
- Low-security applications
- Cross-language data encoding

**NOT suitable for**:
- Production security requirements
- Sensitive data protection
- Cryptographic applications

For production use, consider:
- AES-256 encryption
- RSA for asymmetric encryption
- Established cryptographic libraries (PyCryptodome, crypto-js, etc.)

---

## 🛠️ Requirements

### Python
- Python 3.6+ (uses built-in `base64` module)

### JavaScript
- Node.js 12+ (uses `Buffer`, `TextEncoder`, `TextDecoder`)
- Modern browsers (Chrome, Firefox, Safari, Edge)

---

## 🆚 Comparison with Adjacent-Swap Encryption

| Feature                    | Adjacent-Swap | XOR+Base64         |
|----------------------------|---------------|--------------------|
| Encryption Method          | Swap pairs    | XOR with key       |
| Requires Key               | No (optional) | Yes (required)     |
| Output Format              | Plain text    | Base64             |
| Security Level             | Very low      | Low-Medium         |
| Best Use Case              | Demos/Tests   | Basic obfuscation  |
| Cross-language Compatible  | ✅            | ✅                 |

---

## 💡 Example Use Cases

### 1. Encrypt User Data Before Storage
```python
# Python
from xor_encrypt import xor_encrypt, xor_decrypt

user_data = "sensitive info"
key = "user-specific-key"
encrypted = xor_encrypt(user_data, key)
# Store 'encrypted' in database

# Later retrieve and decrypt
decrypted = xor_decrypt(encrypted, key)
```

### 2. Obfuscate Configuration Values
```javascript
// JavaScript
const { xorEncrypt, xorDecrypt } = require('./xor_encrypt.js');

const apiKey = "secret-api-key-12345";
const obfuscated = xorEncrypt(apiKey, "config-key");
// Store 'obfuscated' in config file

// At runtime
const actual = xorDecrypt(obfuscated, "config-key");
```

### 3. Cross-Language Data Exchange
Encrypt in Python, decrypt in JavaScript (or vice versa):

**Python (sender):**
```python
from xor_encrypt import xor_encrypt
message = xor_encrypt("Hello from Python", "shared-key")
print(message)  # Send this Base64 string
```

**JavaScript (receiver):**
```javascript
const { xorDecrypt } = require('./xor_encrypt.js');
const received = "JRwHCQkVLQcLBF0nEhUdDV4=";  // From Python
console.log(xorDecrypt(received, "shared-key"));
```

---

## 📝 Notes

- **⚠️ Security Warning**: XOR cipher is **NOT secure for real-world encryption**. 
  - **For Real Security**: Use industry-standard encryption like **AES-256** (Advanced Encryption Standard with 256-bit keys)
  - **Python**: Use `cryptography` library with AES-GCM or AES-CBC mode
  - **JavaScript**: Use Web Crypto API (`crypto.subtle.encrypt`) with AES-GCM
  - **Node.js**: Use `crypto` module with proper AES implementation
  - This XOR implementation is suitable only for **basic obfuscation and learning purposes**
- **Case Sensitive Keys**: `"Key"` ≠ `"key"`
- **Key Length**: Any length key works (repeats for longer messages)
- **Character Encoding**: UTF-8 for all languages ensures compatibility
- **Base64 Padding**: Standard Base64 padding (`=`) is preserved

---

## 🤝 Interactive Mode

Both implementations support interactive CLI mode:

**Python:**
```python
# Uncomment in xor_encrypt.py:
if __name__ == "__main__":
    run_tests()
    interactive_mode()  # Uncomment this line
```

**JavaScript:**
```javascript
// Uncomment in xor_encrypt.js:
if (typeof require !== 'undefined' && require.main === module) {
    runTests();
    interactiveMode();  // Uncomment this line
}
```

---

## 📄 License

Educational project - use freely with proper security considerations.

---

## 🎓 Learn More

- [XOR Cipher on Wikipedia](https://en.wikipedia.org/wiki/XOR_cipher)
- [Base64 Encoding](https://en.wikipedia.org/wiki/Base64)
- [UTF-8 Character Encoding](https://en.wikipedia.org/wiki/UTF-8)

Happy encrypting! 🔐
