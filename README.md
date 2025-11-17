# Multilingual Encryption-Decryption System

Two complete cross-language encryption systems that produce **identical outputs** across different programming languages (Python, JavaScript, and more).

## 🚀 Quick Start

**New to this project?** → See [QUICKSTART.md](QUICKSTART.md)

**Want key-based encryption?** → See [XOR_README.md](XOR_README.md) for XOR+Base64 implementation

**Compare methods?** → See [COMPARISON.md](COMPARISON.md)

## 🎯 Features (Adjacent Character Swap)

✅ **Cross-Language Compatible**: Identical encryption output in Python, JavaScript, etc.  
✅ **Deterministic**: Same input always produces the same output  
✅ **No Dependencies**: Pure implementation, no external libraries required  
✅ **Symmetric**: Encryption and decryption use the same algorithm  
✅ **Unicode Support**: Works with emojis, international characters, etc.  
✅ **Optional Seeding**: Add numeric seed for customizable encryption  

## 📖 Algorithm

**Adjacent Character Swap**: Swaps each pair of adjacent characters in the string.

### Example
- Input: `"bibek"`
- Process: Swap `(b,i)` → `(i,b)`, Swap `(b,e)` → `(e,b)`, Keep `k`
- Output: `"ibeibk"`

See [ALGORITHM.md](ALGORITHM.md) for detailed explanation.

---

## 🐍 Python Usage

### Run Tests
```bash
python encrypt.py
```

### Use in Code
```python
from encrypt import encrypt, decrypt

# Encrypt
encrypted = encrypt("bibek")
print(encrypted)  # Output: ibeibk

# Decrypt
decrypted = decrypt("ibeibk")
print(decrypted)  # Output: bibek
```

### Interactive Mode
Uncomment the last line in `encrypt.py`:
```python
if __name__ == "__main__":
    run_tests()
    interactive_mode()  # Uncomment this line
```

---

## 🟨 JavaScript Usage

### Run Tests (Node.js)
```bash
node encrypt.js
```

### Use in Node.js
```javascript
const { encrypt, decrypt } = require('./encrypt.js');

// Encrypt
const encrypted = encrypt("bibek");
console.log(encrypted);  // Output: ibeibk

// Decrypt
const decrypted = decrypt("ibeibk");
console.log(decrypted);  // Output: bibek
```

### Use in Browser
```html
<!DOCTYPE html>
<html>
<head>
    <title>Encryption Demo</title>
    <script src="encrypt.js"></script>
</head>
<body>
    <script>
        const encrypted = encrypt("bibek");
        console.log(encrypted);  // Output: ibeibk
        
        const decrypted = decrypt("ibeibk");
        console.log(decrypted);  // Output: bibek
    </script>
</body>
</html>
```

### Interactive Mode (Node.js)
Uncomment the last line in `encrypt.js`:
```javascript
if (typeof require !== 'undefined' && require.main === module) {
    runTests();
    interactiveMode();  // Uncomment this line
}
```

---

## 🧪 Test Cases

### Basic Test: "bibek"
| Language   | Input    | Encrypted | Decrypted |
|------------|----------|-----------|-----------||
| Python     | `bibek`  | `ibebk`   | `bibek`   |
| JavaScript | `bibek`  | `ibebk`   | `bibek`   |

### Additional Test Cases

| Input             | Encrypted Output  | Description          |
|-------------------|-------------------|----------------------|
| `hello`           | `ehllo`           | Basic word           |
| `world`           | `owlrd`           | Another word         |
| `test`            | `etts`            | 4 characters         |
| `a`               | `a`               | Single character     |
| `ab`              | `ba`              | Two characters       |
| `abc`             | `bac`             | Odd length           |
| `HELLO`           | `EHLLO`           | Uppercase            |
| `Hello World!`    | `eHll ooWlr!d`    | Mixed case + space   |
| `12345`           | `21435`           | Numbers              |
| `!@#$%`           | `@!$#%`           | Special characters   |
| `café`            | `acéf`            | Accented characters  |
| `hello😀world`     | `ehll😀oowlrd`     | With emoji           |
| `こんにちは`       | `んこちには`        | Japanese             |
| `你好世界`         | `好你界世`          | Chinese              |
| ` ` (empty)       | ` ` (empty)       | Empty string         |

---

## 🔍 Edge Cases Handled

| Case                  | Behavior                              |
|-----------------------|---------------------------------------|
| Empty string          | Returns empty string                  |
| Single character      | Returns same character                |
| Odd-length string     | Last character stays in place         |
| Numbers               | Treated as characters, swapped        |
| Uppercase/Lowercase   | Case preserved (case-sensitive)       |
| Unicode (emoji, etc.) | Full Unicode support                  |
| Spaces/Punctuation    | Treated as regular characters         |

---

## 🔄 Alternative Algorithms

If you need different encryption methods, here are alternatives:

### 1. **XOR+Base64 Cipher with Key** ⭐ **IMPLEMENTED**
- XOR each byte with a repeating key
- Encode result in Base64 for safe text representation
- **Pros**: Key-based, cross-language compatible, more secure than Caesar
- **Files**: `xor_encrypt.py`, `xor_encrypt.js`
- **Documentation**: See [XOR_README.md](XOR_README.md)

**Quick Example:**
```bash
# Python
python -c "from xor_encrypt import xor_encrypt; print(xor_encrypt('hello', 'key'))"
# Output: AwAVBwo=

# JavaScript
node -e "const {xorEncrypt} = require('./xor_encrypt.js'); console.log(xorEncrypt('hello', 'key'));"
# Output: AwAVBwo=
```

### 2. **Caesar Cipher with Fixed Shift**
- Shift each character by a fixed number (e.g., +3)
- `a` → `d`, `b` → `e`, etc.
- **Pros**: Simple, well-known
- **Cons**: Easily breakable, doesn't preserve character types

---

## 📊 Cross-Language Validation

To verify identical output across languages:

1. **Python**:
   ```bash
   python -c "from encrypt import encrypt; print(encrypt('bibek'))"
   ```
   Output: `ibebk`

2. **JavaScript (Node.js)**:
   ```bash
   node -e "const {encrypt} = require('./encrypt.js'); console.log(encrypt('bibek'))"
   ```
   Output: `ibebk`

Both should produce **exactly the same output**.

---

## 🔐 Using a Seed (Custom Value)

You can pass an optional numeric seed to both `encrypt` and `decrypt` to change the transformation deterministically. The implementations rotate the string by `seed % len` before (encrypt) / after (decrypt) swapping pairs.

Python example:
```bash
python -c "from encrypt import encrypt, decrypt; print(encrypt('bibek', 2)); print(decrypt('keibb', 2))"
```

Node.js example:
```bash
node -e "const {encrypt, decrypt} = require('./encrypt.js'); console.log(encrypt('bibek', 2)); console.log(decrypt('keibb', 2));"
```

Both commands will output the same encrypted/decrypted results when using the same seed.

---

## 🛠️ Requirements

### Python
- Python 3.6+ (no external dependencies)

### JavaScript
- Node.js 12+ (for CLI usage)
- Any modern browser (for web usage)

---

## 📝 Notes

- **⚠️ Security Warning**: This is a simple educational algorithm, **NOT suitable for real-world encryption**. 
  - **For Real Security**: Use industry-standard encryption like **AES-256** (Advanced Encryption Standard with 256-bit keys)
  - **Python**: Use `cryptography` library with AES-GCM mode
  - **JavaScript**: Use Web Crypto API (`crypto.subtle.encrypt`) or Node.js `crypto` module
  - These implementations are for **learning and demonstration purposes only**
- **Character Encoding**: Both implementations use UTF-8/Unicode, ensuring international character support.
- **Performance**: O(n) time complexity, where n is the string length.

---

## 📄 License

This is an educational project. Feel free to use and modify as needed.

---

## 🤝 Contributing

To add support for another language:
1. Implement the adjacent character swap logic
2. Ensure it passes all test cases
3. Verify output matches Python/JavaScript exactly

---

## 📞 Support

If you find any inconsistencies between language implementations, please verify:
- String encoding (use UTF-8)
- Character iteration order
- Handling of Unicode characters

Happy encrypting! 🔐
