"""
AES-256-GCM Encryption/Decryption System
Cross-language compatible, production-grade encryption using AES-256 in GCM mode.

Requirements:
    pip install cryptography

Features:
    - AES-256-GCM (Galois/Counter Mode) for authenticated encryption
    - 256-bit keys for maximum security
    - 96-bit nonces (IV) for GCM mode
    - Base64 encoding for safe text transmission
    - Cross-language compatible output format
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import json


def derive_key(password: str, salt: bytes = None) -> tuple:
    """
    Derive a 256-bit key from a password using PBKDF2.
    
    Args:
        password: User-provided password string
        salt: Optional salt bytes (generates new if not provided)
    
    Returns:
        tuple: (derived_key, salt)
    """
    if salt is None:
        salt = os.urandom(16)  # 128-bit salt
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=100000,  # OWASP recommended minimum
    )
    key = kdf.derive(password.encode('utf-8'))
    return key, salt


def aes_encrypt(plaintext: str, password: str) -> str:
    """
    Encrypt plaintext using AES-256-GCM with password-based key derivation.
    
    Args:
        plaintext: Text to encrypt
        password: Password for encryption
    
    Returns:
        Base64-encoded JSON string containing salt, nonce, ciphertext, and tag
    """
    # Derive key from password
    key, salt = derive_key(password)
    
    # Create AES-GCM cipher
    aesgcm = AESGCM(key)
    
    # Generate random nonce (96 bits for GCM)
    nonce = os.urandom(12)
    
    # Encrypt (GCM automatically handles authentication tag)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    
    # Package everything together
    result = {
        'salt': base64.b64encode(salt).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
    }
    
    # Return as Base64-encoded JSON
    return base64.b64encode(json.dumps(result).encode('utf-8')).decode('utf-8')


def aes_decrypt(encrypted_data: str, password: str) -> str:
    """
    Decrypt AES-256-GCM encrypted data.
    
    Args:
        encrypted_data: Base64-encoded JSON string from aes_encrypt
        password: Password for decryption
    
    Returns:
        Decrypted plaintext
    
    Raises:
        Exception: If decryption fails (wrong password or corrupted data)
    """
    try:
        # Decode the Base64-encoded JSON
        json_data = base64.b64decode(encrypted_data.encode('utf-8')).decode('utf-8')
        data = json.loads(json_data)
        
        # Extract components
        salt = base64.b64decode(data['salt'])
        nonce = base64.b64decode(data['nonce'])
        ciphertext = base64.b64decode(data['ciphertext'])
        
        # Derive the same key from password and salt
        key, _ = derive_key(password, salt)
        
        # Create AES-GCM cipher
        aesgcm = AESGCM(key)
        
        # Decrypt (will raise exception if authentication fails)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        return plaintext.decode('utf-8')
    
    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}")


def aes_encrypt_with_key(plaintext: str, key_b64: str) -> str:
    """
    Encrypt using a pre-generated Base64-encoded 256-bit key.
    
    Args:
        plaintext: Text to encrypt
        key_b64: Base64-encoded 32-byte key
    
    Returns:
        Base64-encoded JSON with nonce and ciphertext
    """
    key = base64.b64decode(key_b64)
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (256 bits)")
    
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    
    result = {
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
    }
    
    return base64.b64encode(json.dumps(result).encode('utf-8')).decode('utf-8')


def aes_decrypt_with_key(encrypted_data: str, key_b64: str) -> str:
    """
    Decrypt using a pre-generated Base64-encoded 256-bit key.
    
    Args:
        encrypted_data: Base64-encoded JSON from aes_encrypt_with_key
        key_b64: Base64-encoded 32-byte key
    
    Returns:
        Decrypted plaintext
    """
    key = base64.b64decode(key_b64)
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (256 bits)")
    
    json_data = base64.b64decode(encrypted_data.encode('utf-8')).decode('utf-8')
    data = json.loads(json_data)
    
    nonce = base64.b64decode(data['nonce'])
    ciphertext = base64.b64decode(data['ciphertext'])
    
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    
    return plaintext.decode('utf-8')


def generate_key() -> str:
    """
    Generate a random 256-bit key.
    
    Returns:
        Base64-encoded 32-byte key
    """
    key = AESGCM.generate_key(bit_length=256)
    return base64.b64encode(key).decode('utf-8')


def run_tests():
    """Run comprehensive test suite."""
    print("=" * 60)
    print("AES-256-GCM Encryption Test Suite")
    print("=" * 60)
    
    tests_passed = 0
    tests_failed = 0
    
    # Test 1: Basic encryption/decryption with password
    print("\n[Test 1] Password-based encryption/decryption")
    try:
        original = "Hello, AES-256!"
        password = "super_secure_password"
        encrypted = aes_encrypt(original, password)
        decrypted = aes_decrypt(encrypted, password)
        assert decrypted == original, f"Expected '{original}', got '{decrypted}'"
        print(f"✓ Original: {original}")
        print(f"✓ Encrypted: {encrypted[:50]}...")
        print(f"✓ Decrypted: {decrypted}")
        tests_passed += 1
    except Exception as e:
        print(f"✗ Failed: {e}")
        tests_failed += 1
    
    # Test 2: Unicode support
    print("\n[Test 2] Unicode and emoji support")
    try:
        original = "Hello 世界! 🔐🌍"
        password = "test123"
        encrypted = aes_encrypt(original, password)
        decrypted = aes_decrypt(encrypted, password)
        assert decrypted == original
        print(f"✓ Original: {original}")
        print(f"✓ Decrypted: {decrypted}")
        tests_passed += 1
    except Exception as e:
        print(f"✗ Failed: {e}")
        tests_failed += 1
    
    # Test 3: Wrong password should fail
    print("\n[Test 3] Wrong password detection")
    try:
        original = "Secret message"
        encrypted = aes_encrypt(original, "correct_password")
        try:
            aes_decrypt(encrypted, "wrong_password")
            print("✗ Failed: Should have raised exception")
            tests_failed += 1
        except:
            print("✓ Correctly rejected wrong password")
            tests_passed += 1
    except Exception as e:
        print(f"✗ Failed: {e}")
        tests_failed += 1
    
    # Test 4: Key-based encryption
    print("\n[Test 4] Direct key-based encryption")
    try:
        key = generate_key()
        original = "Direct key encryption"
        encrypted = aes_encrypt_with_key(original, key)
        decrypted = aes_decrypt_with_key(encrypted, key)
        assert decrypted == original
        print(f"✓ Generated Key: {key[:30]}...")
        print(f"✓ Original: {original}")
        print(f"✓ Decrypted: {decrypted}")
        tests_passed += 1
    except Exception as e:
        print(f"✗ Failed: {e}")
        tests_failed += 1
    
    # Test 5: Long text
    print("\n[Test 5] Long text encryption")
    try:
        original = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 10
        password = "long_text_password"
        encrypted = aes_encrypt(original, password)
        decrypted = aes_decrypt(encrypted, password)
        assert decrypted == original
        print(f"✓ Text length: {len(original)} characters")
        print(f"✓ Encrypted length: {len(encrypted)} characters")
        print("✓ Long text encrypted and decrypted successfully")
        tests_passed += 1
    except Exception as e:
        print(f"✗ Failed: {e}")
        tests_failed += 1
    
    # Test 6: Empty string
    print("\n[Test 6] Empty string handling")
    try:
        original = ""
        password = "empty_test"
        encrypted = aes_encrypt(original, password)
        decrypted = aes_decrypt(encrypted, password)
        assert decrypted == original
        print("✓ Empty string handled correctly")
        tests_passed += 1
    except Exception as e:
        print(f"✗ Failed: {e}")
        tests_failed += 1
    
    # Test 7: Special characters
    print("\n[Test 7] Special characters")
    try:
        original = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"
        password = "special_chars"
        encrypted = aes_encrypt(original, password)
        decrypted = aes_decrypt(encrypted, password)
        assert decrypted == original
        print(f"✓ Original: {original}")
        print(f"✓ Decrypted: {decrypted}")
        tests_passed += 1
    except Exception as e:
        print(f"✗ Failed: {e}")
        tests_failed += 1
    
    # Summary
    print("\n" + "=" * 60)
    print(f"Tests Passed: {tests_passed}")
    print(f"Tests Failed: {tests_failed}")
    print("=" * 60)
    
    return tests_failed == 0


if __name__ == "__main__":
    run_tests()
    
    # Interactive example
    print("\n" + "=" * 60)
    print("Interactive Example")
    print("=" * 60)
    
    print("\nExample 1: Password-based encryption")
    message = "This is a secret message!"
    password = "my_secure_password"
    
    encrypted = aes_encrypt(message, password)
    print(f"Original: {message}")
    print(f"Password: {password}")
    print(f"Encrypted: {encrypted}")
    
    decrypted = aes_decrypt(encrypted, password)
    print(f"Decrypted: {decrypted}")
    
    print("\nExample 2: Key-based encryption")
    key = generate_key()
    print(f"Generated Key: {key}")
    
    encrypted2 = aes_encrypt_with_key("Another secret!", key)
    print(f"Encrypted: {encrypted2}")
    
    decrypted2 = aes_decrypt_with_key(encrypted2, key)
    print(f"Decrypted: {decrypted2}")
