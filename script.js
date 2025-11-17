// node script.js
// Adjacent Swap Encryption Example
const { encrypt, decrypt } = require('./encrypt.js');

const encrypted = encrypt("bibek");
console.log("The encrypted text is:", encrypted);  // Output: ibebk
const decrypted = decrypt("ibebk");
console.log("The decrypted text is:", decrypted);  // Output: bibek

// With seed
console.log();  // New line for better readability
const encryptedSeed = encrypt("bibek", 2);
console.log("The encrypted text with seed is:", encryptedSeed);  // Output: keibb
const decryptedSeed = decrypt("keibb", 2);
console.log("The decrypted text with seed is:", decryptedSeed);  // Output: bibek





// XOR + Base64 Encryption Example
const { xorEncrypt, xorDecrypt } = require('./xor_encrypt.js');

console.log();  // New line for better readability
const xorencrypted = xorEncrypt("bibek", "secret");
console.log("The encrypted text is:", xorencrypted);  // Output: EQwBFw4=
const xordecrypted = xorDecrypt("EQwBFw4=", "secret");
console.log("The decrypted text is:", xordecrypted);  // Output: bibek





// AES-256-GCM Encryption Example
const { aesEncrypt, aesDecrypt, generateKey, aesEncryptWithKey, aesDecryptWithKey } = require('./aes_encrypt.js');

// Password-based (async)
(async () => {
    const AESencrypted = await aesEncrypt("sensitive data", "MyStr0ngP@ssw0rd");
    console.log();  // New line for better readability
    console.log("The encrypted text is:", AESencrypted);
    const AESdecrypted = await aesDecrypt(AESencrypted, "MyStr0ngP@ssw0rd");
    console.log("The decrypted text is:", AESdecrypted);  // Output: sensitive data
    
    // Key-based
    const key = await generateKey();
    const AESencrypted2 = await aesEncryptWithKey("secret", key);
    console.log();  // New line for better readability
    console.log("The encrypted text with key is:", AESencrypted2);
    const AESdecrypted2 = await aesDecryptWithKey(AESencrypted2, key);
    console.log("The decrypted text with key is:", AESdecrypted2);  // Output: secret
})();