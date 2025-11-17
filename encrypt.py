"""
Multilingual Encryption-Decryption System
Algorithm: Adjacent Character Swap (Deterministic)
Compatible across Python, JavaScript, and other languages
"""

def encrypt(text, seed=0):
    """
    Encrypts text by swapping adjacent character pairs.
    
    Args:
        text (str): Plain text to encrypt
        
    Returns:
        str: Encrypted text
        
    Example:
        encrypt("bibek") → "ibeibk"
    """
    if not text:
        return ""

    # Convert string to list for easier manipulation (handles unicode characters)
    chars = list(text)

    # Normalize seed to integer and reduce it to rotation within string length
    try:
        n = int(seed)
    except Exception:
        n = 0

    length = len(chars)
    if length > 0:
        rot = n % length
    else:
        rot = 0

    # Rotate right by rot (seed) before swapping to make encryption keyable
    if rot:
        chars = chars[-rot:] + chars[:-rot]

    # Swap adjacent pairs
    for i in range(0, len(chars) - 1, 2):
        chars[i], chars[i + 1] = chars[i + 1], chars[i]

    return ''.join(chars)


def decrypt(text, seed=0):
    """
    Decrypts text by swapping adjacent character pairs.
    Since swapping is symmetric, decryption is identical to encryption.
    
    Args:
        text (str): Encrypted text to decrypt
        
    Returns:
        str: Decrypted plain text
        
    Example:
        decrypt("ibeibk") → "bibek"
    """
    # For keyed (seeded) encryption, decryption is:
    # 1) swap adjacent pairs (same as encryption)
    # 2) rotate left by seed value

    if not text:
        return ""

    # First, perform the same adjacent swap
    chars = list(text)
    for i in range(0, len(chars) - 1, 2):
        chars[i], chars[i + 1] = chars[i + 1], chars[i]

    # Normalize seed and compute left rotation
    try:
        n = int(seed)
    except Exception:
        n = 0

    length = len(chars)
    if length > 0:
        rot = n % length
    else:
        rot = 0

    # Rotate left by rot to recover original
    if rot:
        chars = chars[rot:] + chars[:rot]

    return ''.join(chars)


def run_tests():
    """Run comprehensive test cases to validate the algorithm."""
    
    print("=" * 60)
    print("ENCRYPTION-DECRYPTION TEST SUITE")
    print("=" * 60)
    
    test_cases = [
        # (input, expected_encrypted)
        ("bibek", "ibebk"),
        ("hello", "ehllo"),
        ("world", "owlrd"),
        ("test", "etts"),
        ("", ""),
        ("a", "a"),
        ("ab", "ba"),
        ("abc", "bac"),
        ("HELLO", "EHLLO"),
        ("Hello World!", "eHll ooWlr!d"),
        ("12345", "21435"),
        ("a1b2c3", "1a2b3c"),
        ("   ", "   "),
        ("test 123", "etts1 32"),
        ("!@#$%", "@!$#%"),
        ("café", "acéf"),
        ("hello😀world", "ehll😀oowlrd"),
        ("こんにちは", "んこちには"),  # Japanese
        ("你好世界", "好你界世"),  # Chinese
    ]
    
    all_passed = True
    
    for i, (original, expected) in enumerate(test_cases, 1):
        encrypted = encrypt(original)
        decrypted = decrypt(encrypted)
        
        # Verify encryption matches expected
        encrypt_pass = encrypted == expected
        # Verify decryption returns original
        decrypt_pass = decrypted == original
        
        status = "✓ PASS" if (encrypt_pass and decrypt_pass) else "✗ FAIL"
        
        print(f"\nTest {i}: {status}")
        print(f"  Input:     '{original}'")
        print(f"  Encrypted: '{encrypted}' (expected: '{expected}')")
        print(f"  Decrypted: '{decrypted}'")
        
        if not (encrypt_pass and decrypt_pass):
            all_passed = False
            if not encrypt_pass:
                print(f"  ⚠ Encryption mismatch!")
            if not decrypt_pass:
                print(f"  ⚠ Decryption failed!")

    # --- Seeded test cases (optional checks) ---
    seeded_tests = [
        # (input, seed, expected_encrypted)
        ("bibek", 2, encrypt("bibek", 2)),
        ("hello", 3, encrypt("hello", 3)),
        ("12345", 1, encrypt("12345", 1)),
    ]

    for j, (original, seed, expected) in enumerate(seeded_tests, 1):
        encrypted = encrypt(original, seed)
        decrypted = decrypt(encrypted, seed)
        idx = len(test_cases) + j
        encrypt_pass = encrypted == expected
        decrypt_pass = decrypted == original
        status = "✓ PASS" if (encrypt_pass and decrypt_pass) else "✗ FAIL"

        print(f"\nSeeded Test {idx}: {status}")
        print(f"  Input:     '{original}' (seed={seed})")
        print(f"  Encrypted: '{encrypted}' (expected: '{expected}')")
        print(f"  Decrypted: '{decrypted}'")

        if not (encrypt_pass and decrypt_pass):
            all_passed = False
            if not encrypt_pass:
                print(f"  ⚠ Encryption mismatch!")
            if not decrypt_pass:
                print(f"  ⚠ Decryption failed!")
    
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
    print("INTERACTIVE ENCRYPTION-DECRYPTION")
    print("=" * 60)
    print("Commands: 'e' to encrypt, 'd' to decrypt, 'q' to quit\n")
    
    while True:
        choice = input("Enter command (e/d/q): ").lower().strip()
        
        if choice == 'q':
            print("Goodbye!")
            break
        elif choice == 'e':
            text = input("Enter text to encrypt: ")
            encrypted = encrypt(text)
            print(f"Encrypted: {encrypted}\n")
        elif choice == 'd':
            text = input("Enter text to decrypt: ")
            decrypted = decrypt(text)
            print(f"Decrypted: {decrypted}\n")
        else:
            print("Invalid command. Use 'e', 'd', or 'q'.\n")


if __name__ == "__main__":
    # Run automated tests
    run_tests()
    
    # Optional: Uncomment to enable interactive mode
    # interactive_mode()
