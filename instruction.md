

**I want to build a multilingual encryption–decryption system where the encrypted output is identical across different programming languages (Python, JavaScript, or any other language).
Please generate a complete solution including:**

### **1. Encryption–Decryption Requirements**

* Encryption algorithm must produce **the same encrypted value regardless of the language** used (Python, JavaScript, etc.).
* Decryption algorithm must correctly reverse the encrypted text back to original text in **any language environment**.
* Use an encryption method that:

  * Is deterministic (same input → same output).
  * Does NOT rely on random values unless a shared key/IV is used uniformly.
  * Is simple enough to implement in multiple languages.
  * Ensures **full compatibility** across languages.
* Example:
  Input `"bibek"` encrypts to `"beibk"` in Python, JavaScript, or any other language.
  And decrypting `"beibk"` in any language returns `"bibek"`.

### **2. Deliverables**

Provide:

#### **A. Algorithm Design**

* Clear explanation of the encryption & decryption logic.
* Step-by-step encoding/decoding rules.
* Mention if the algorithm uses a key (optional).
* Make sure there is no language-specific behavior like:

  * Different Unicode handling
  * Different random number generators
  * Different byte order issues

#### **B. Complete Code in Both Languages**

Provide **fully working code** for:

1. **Python (encrypt + decrypt)**
2. **JavaScript (encrypt + decrypt)**

Ensure:

* Identical output across languages
* No external libraries unless absolutely necessary
* Code must be copy-paste ready

#### **C. Testing Instructions**

* Show how to test with `"bibek" → "beibk" → "bibek"`
* Show at least 3 additional test cases to validate cross-language compatibility.

#### **D. Edge Cases to Handle**

* Empty string
* Numbers
* Uppercase vs lowercase
* Unicode characters (optional)
* Punctuation
* Strings with spaces

### **3. Provide Optional Variations**

Also suggest **two alternative algorithms** that would work cross-language such as:

* Fixed character swapping
* Caesar cipher with fixed shift
* XOR with fixed key (base64 output)

