# Encryption Algorithm Design

## Algorithm: Character Position Swapping

### Overview
This algorithm uses a deterministic character swapping pattern that produces identical results across all programming languages. It does not use random values, keys, or IVs, ensuring complete cross-language compatibility.

### Encryption Logic

**Step-by-step process:**

1. **Input**: Plain text string (e.g., `"bibek"`)
2. **Process**: Swap characters at specific positions:
   - Position 0 ↔ Position 1
   - Position 2 ↔ Position 3
   - Position 4 ↔ Position 5
   - And so on...

3. **Rule**: 
   - For each pair of adjacent characters (at indices `2i` and `2i+1`), swap them
   - If the string has odd length, the last character remains in place

4. **Output**: Encrypted string

### Example Walkthrough

#### Input: `"bibek"`
- Original positions: `b[0] i[1] b[2] e[3] k[4]`
- Swap 0↔1: `i b _ _ _`
- Swap 2↔3: `i b e b _`
- Position 4 (odd, no pair): `i b e b k`
- **Result**: `"ibebk"`

### Final Algorithm: Adjacent Character Swap

**Encryption Rule:**
- Group characters into pairs from left to right
- Swap each pair
- If odd length, last character stays in place

**Implementation:**
```
For i = 0 to length-1 step 2:
    if i+1 < length:
        swap(string[i], string[i+1])
```

### Decryption Logic

**Decryption is identical to encryption** because swapping is reversible:
- If you swap pairs to encrypt, swapping the same pairs again decrypts

**Example:**
- Encrypt `"bibek"` → swap pairs → `"ibebk"`
- Decrypt `"ibebk"` → swap pairs → `"bibek"`

### Key Properties

✅ **Deterministic**: Same input always produces same output
✅ **No Random Values**: Algorithm is fixed
✅ **No Keys/IVs**: Simple swapping, no cryptographic keys
✅ **Language Independent**: Works with any UTF-8/Unicode string
✅ **Symmetric**: Encryption = Decryption (reversible)

### Handling Edge Cases

1. **Empty String**: Returns empty string
2. **Single Character**: Returns same character (no pair to swap)
3. **Numbers**: Treated as characters, swapped normally
4. **Uppercase/Lowercase**: Preserved (case-sensitive)
5. **Unicode**: Works with any Unicode characters
6. **Spaces/Punctuation**: Treated as regular characters
7. **Odd Length**: Last character remains in place

### Cross-Language Compatibility

This algorithm avoids:
- ❌ Random number generators (different seeds)
- ❌ Floating-point operations (precision differences)
- ❌ Platform-specific byte order
- ❌ Language-specific string encoding issues

Works identically in Python, JavaScript, Java, C++, Ruby, etc.
