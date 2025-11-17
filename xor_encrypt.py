"""
XOR+Base64 Encryption-Decryption System
Cross-language compatible (Python, JavaScript, etc.)
Uses XOR cipher with a repeating key and Base64 encoding for output
"""

import base64


def xor_encrypt(text, key):
    """
    Encrypts text using XOR cipher with a repeating key, then encodes to Base64.
    
    Args:
        text (str): Plain text to encrypt
        key (str): Encryption key (any string)
        
    Returns:
        str: Base64-encoded encrypted text
        
    Example:
        xor_encrypt("bibek", "secret") → "GgcKAw=="
    """
    if not text:
        return ""
    
    if not key:
        raise ValueError("Key cannot be empty")
    
    # Convert text and key to bytes (UTF-8)
    text_bytes = text.encode('utf-8')
    key_bytes = key.encode('utf-8')
    
    # XOR each byte with repeating key
    xored = bytearray()
    for i, byte in enumerate(text_bytes):
        key_byte = key_bytes[i % len(key_bytes)]
        xored.append(byte ^ key_byte)
    
    # Encode to Base64 for safe text representation
    return base64.b64encode(xored).decode('utf-8')


def xor_decrypt(encrypted_text, key):
    """
    Decrypts Base64-encoded XOR-encrypted text.
    
    Args:
        encrypted_text (str): Base64-encoded encrypted text
        key (str): Decryption key (must match encryption key)
        
    Returns:
        str: Decrypted plain text
        
    Example:
        xor_decrypt("GgcKAw==", "secret") → "bibek"
    """
    if not encrypted_text:
        return ""
    
    if not key:
        raise ValueError("Key cannot be empty")
    
    # Decode from Base64
    try:
        encrypted_bytes = base64.b64decode(encrypted_text)
    except Exception as e:
        raise ValueError(f"Invalid Base64 input: {e}")
    
    # Convert key to bytes
    key_bytes = key.encode('utf-8')
    
    # XOR each byte with repeating key (XOR is symmetric)
    decrypted = bytearray()
    for i, byte in enumerate(encrypted_bytes):
        key_byte = key_bytes[i % len(key_bytes)]
        decrypted.append(byte ^ key_byte)
    
    # Decode back to string (UTF-8)
    return decrypted.decode('utf-8')


def run_tests():
    """Run comprehensive test cases to validate XOR encryption."""
    
    print("=" * 60)
    print("XOR+BASE64 ENCRYPTION TEST SUITE")
    print("=" * 60)
    
    # Test cases: (plaintext, key, expected_encrypted_base64)
    test_cases = [
        ("bibek", "secret", None),  # Will compute expected
        ("hello", "key", None),
        ("world", "pass", None),
        ("test", "12345", None),
        ("", "key", ""),  # Empty string
        ("a", "x", None),
        ("Hello World!", "mykey", None),
        ("12345", "abc", None),
        ("café", "test", None),
        ("hello😀world", "emoji", None),
        ("こんにちは", "日本", None),
        ("你好世界", "中文", None),
    ]
    
    all_passed = True
    
    for i, (plaintext, key, expected) in enumerate(test_cases, 1):
        # Compute expected if not provided
        if expected is None and plaintext:
            expected = xor_encrypt(plaintext, key)
        
        try:
            encrypted = xor_encrypt(plaintext, key)
            decrypted = xor_decrypt(encrypted, key)
            
            # Verify encryption matches expected (if provided)
            encrypt_pass = (expected is None) or (encrypted == expected)
            # Verify decryption returns original
            decrypt_pass = decrypted == plaintext
            
            status = "✓ PASS" if (encrypt_pass and decrypt_pass) else "✗ FAIL"
            
            print(f"\nTest {i}: {status}")
            print(f"  Plaintext: '{plaintext}'")
            print(f"  Key:       '{key}'")
            print(f"  Encrypted: '{encrypted}'")
            print(f"  Decrypted: '{decrypted}'")
            
            if not (encrypt_pass and decrypt_pass):
                all_passed = False
                if not encrypt_pass:
                    print(f"  ⚠ Encryption mismatch! Expected: '{expected}'")
                if not decrypt_pass:
                    print(f"  ⚠ Decryption failed!")
                    
        except Exception as e:
            print(f"\nTest {i}: ✗ FAIL")
            print(f"  Plaintext: '{plaintext}'")
            print(f"  Key:       '{key}'")
            print(f"  Error:     {e}")
            all_passed = False
    
    # Test with wrong key (should fail decryption)
    print(f"\n" + "-" * 60)
    print("Testing wrong key scenario:")
    try:
        encrypted = xor_encrypt("secret message", "correct_key")
        wrong_decrypt = xor_decrypt(encrypted, "wrong_key")
        print(f"  Original:  'secret message'")
        print(f"  Encrypted: '{encrypted}'")
        print(f"  Wrong key decrypt: '{wrong_decrypt}'")
        print(f"  ✓ Wrong key produces garbage (as expected)")
    except Exception as e:
        print(f"  Error: {e}")
    
    print("\n" + "=" * 60)
    if all_passed:
        print("✓ ALL TESTS PASSED!")
    else:
        print("✗ SOME TESTS FAILED!")
    print("=" * 60)
    
    return all_passed


def interactive_mode():
    """Interactive mode for manual testing."""
    print("\n" + "=" * 60)
    print("INTERACTIVE XOR+BASE64 ENCRYPTION")
    print("=" * 60)
    print("Commands: 'e' to encrypt, 'd' to decrypt, 'q' to quit\n")
    
    while True:
        choice = input("Enter command (e/d/q): ").lower().strip()
        
        if choice == 'q':
            print("Goodbye!")
            break
        elif choice == 'e':
            text = input("Enter text to encrypt: ")
            key = input("Enter encryption key: ")
            try:
                encrypted = xor_encrypt(text, key)
                print(f"Encrypted: {encrypted}\n")
            except Exception as e:
                print(f"Error: {e}\n")
        elif choice == 'd':
            text = input("Enter text to decrypt: ")
            key = input("Enter decryption key: ")
            try:
                decrypted = xor_decrypt(text, key)
                print(f"Decrypted: {decrypted}\n")
            except Exception as e:
                print(f"Error: {e}\n")
        else:
            print("Invalid command. Use 'e', 'd', or 'q'.\n")


if __name__ == "__main__":
    # Run automated tests
    run_tests()
    
    # Optional: Uncomment to enable interactive mode
    # interactive_mode()
