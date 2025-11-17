# Adjacent Character Swap
from encrypt import encrypt, decrypt

encrypted = encrypt("bibek")
print("The encrypted text is:", encrypted)  # Output: ibebk
decrypted = decrypt("ibebk")
print("The decrypted text is:", decrypted)  # Output: bibek
print()  # New line for better readability

# With seed
encrypted_seed = encrypt("bibek", 2)
print("The encrypted text with seed is:", encrypted_seed)  # Output: keibb
decrypted_seed = decrypt("keibb", 2)
print("The decrypted text with seed is:", decrypted_seed)  # Output: bibek




# XOR Encryption with Base64 Encoding
from xor_encrypt import xor_encrypt, xor_decrypt

print()  # New line for better readability
encrypted = xor_encrypt("bibek", "secret")
print("The encrypted text is:", encrypted)  # Output: EQwBFw4=
decrypted = xor_decrypt("EQwBFw4=", "secret")
print("The decrypted text is:", decrypted)  # Output: bibek



# AES-256-GCM
from aes_encrypt import aes_encrypt, aes_decrypt, generate_key, aes_encrypt_with_key, aes_decrypt_with_key

print()  # New line for better readability
# Password-based
encrypted = aes_encrypt("sensitive data", "MyStr0ngP@ssw0rd")
print("The encrypted text is:", encrypted)
decrypted = aes_decrypt(encrypted, "MyStr0ngP@ssw0rd")
print("The decrypted text is:", decrypted)  # Output: sensitive data

# Key-based
key = generate_key()
print()  # New line for better readability
encrypted = aes_encrypt_with_key("secret message", key)
print("The encrypted text with key is:", encrypted)
decrypted = aes_decrypt_with_key(encrypted, key)
print("The decrypted text with key is:", decrypted)