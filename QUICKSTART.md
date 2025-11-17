# 🚀 Quick Start Guide

Get started with cross-language encryption in 2 minutes!

## 📥 What You Have

Two complete encryption systems with Python + JavaScript implementations:
1. **Adjacent Swap** - Simple character swapping
2. **XOR+Base64** - Key-based encryption with Base64 output

---

## ⚡ 30-Second Test

### Test Adjacent Swap
```bash
# Python
python encrypt.py

# JavaScript
node encrypt.js
```
Both should show: **✓ ALL TESTS PASSED!**

### Test XOR+Base64
```bash
# Python
python xor_encrypt.py

# JavaScript  
node xor_encrypt.js
```
Both should show: **✓ ALL TESTS PASSED!**

---

## 💻 Quick Usage

### Python
```python
# Method 1: Adjacent Swap
from encrypt import encrypt, decrypt
encrypted = encrypt("hello", 3)      # with seed
print(encrypted)                      # llhoe
print(decrypt(encrypted, 3))          # hello

# Method 2: XOR+Base64
from xor_encrypt import xor_encrypt, xor_decrypt
encrypted = xor_encrypt("hello", "mykey")
print(encrypted)                      # AwAVBwo=
print(xor_decrypt(encrypted, "mykey")) # hello
```

### JavaScript
```javascript
// Method 1: Adjacent Swap
const { encrypt, decrypt } = require('./encrypt.js');
const encrypted = encrypt("hello", 3);  // with seed
console.log(encrypted);                  // llhoe
console.log(decrypt(encrypted, 3));      // hello

// Method 2: XOR+Base64
const { xorEncrypt, xorDecrypt } = require('./xor_encrypt.js');
const encrypted = xorEncrypt("hello", "mykey");
console.log(encrypted);                  // AwAVBwo=
console.log(xorDecrypt(encrypted, "mykey")); // hello
```

### Browser
Open in browser:
- `demo.html` - Adjacent swap demo
- `xor_demo.html` - XOR+Base64 demo

---

## 🎯 When to Use Which?

| Need                        | Use This              |
|-----------------------------|-----------------------|
| Simple demo/learning        | Adjacent Swap         |
| Readable output             | Adjacent Swap         |
| Key-based encryption        | XOR+Base64           |
| Config value obfuscation    | XOR+Base64           |
| Real security               | ⚠️ Neither - use AES  |

---

## 📖 Full Documentation

- **General:** [README.md](README.md)
- **XOR Details:** [XOR_README.md](XOR_README.md)
- **Algorithm:** [ALGORITHM.md](ALGORITHM.md)
- **Comparison:** [COMPARISON.md](COMPARISON.md)

---

## ✅ Verify Cross-Language Compatibility

```bash
# Should output identical results:
python -c "from xor_encrypt import xor_encrypt; print(xor_encrypt('test', 'key'))"
node -e "const {xorEncrypt} = require('./xor_encrypt.js'); console.log(xorEncrypt('test', 'key'));"
```

Both output: `HwAKHw==` ✓

---

## 🎓 Examples

### Encrypt in Python, Decrypt in JavaScript
```bash
# Python: Encrypt
python -c "from xor_encrypt import xor_encrypt; print(xor_encrypt('secret message', 'mykey'))"
# Output: HRwdVy0AFgcVBQY=

# JavaScript: Decrypt (paste the output above)
node -e "const {xorDecrypt} = require('./xor_encrypt.js'); console.log(xorDecrypt('HRwdVy0AFgcVBQY=', 'mykey'));"
# Output: secret message
```

### Encrypt in JavaScript, Decrypt in Python
```bash
# JavaScript: Encrypt
node -e "const {xorEncrypt} = require('./xor_encrypt.js'); console.log(xorEncrypt('hello world', 'key123'));"
# Output: AwQXChtcAQQEAQA=

# Python: Decrypt (paste the output above)
python -c "from xor_encrypt import xor_decrypt; print(xor_decrypt('AwQXChtcAQQEAQA=', 'key123'))"
# Output: hello world
```

---

## 🔧 Troubleshooting

### Tests Failing?
- Ensure Python 3.6+ and Node.js 12+ installed
- Run from the correct directory
- Check file permissions

### Import Errors?
```bash
# Python
python -c "import sys; print(sys.version)"

# JavaScript
node --version
```

### Different Outputs?
- Verify you're using same key/seed
- Check character encoding (should be UTF-8)
- Ensure latest file versions

---

## 🎉 You're Ready!

Pick a method, start encrypting, and enjoy cross-language compatibility!

**Need help?** Check the full docs or the comparison guide.
