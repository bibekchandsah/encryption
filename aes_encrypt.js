/**
 * AES-256-GCM Encryption/Decryption System
 * Cross-language compatible, production-grade encryption using AES-256 in GCM mode.
 * 
 * Node.js: Uses built-in crypto module
 * Browser: Uses Web Crypto API (crypto.subtle)
 * 
 * Features:
 *   - AES-256-GCM (Galois/Counter Mode) for authenticated encryption
 *   - 256-bit keys for maximum security
 *   - 96-bit nonces (IV) for GCM mode
 *   - Base64 encoding for safe text transmission
 *   - Cross-language compatible output format
 */

// Detect environment
const isNode = typeof process !== 'undefined' && process.versions && process.versions.node;
const isBrowser = typeof window !== 'undefined';

// Import crypto based on environment
let crypto, nodeCrypto;
if (isNode) {
    nodeCrypto = require('crypto');
    crypto = nodeCrypto.webcrypto || globalThis.crypto;
} else if (isBrowser) {
    crypto = window.crypto;
}

/**
 * Derive a 256-bit key from a password using PBKDF2
 * @param {string} password - User-provided password
 * @param {Uint8Array} salt - Optional salt (generates new if not provided)
 * @returns {Promise<{key: CryptoKey, salt: Uint8Array, rawKey: Uint8Array}>}
 */
async function deriveKey(password, salt = null) {
    if (!salt) {
        salt = crypto.getRandomValues(new Uint8Array(16)); // 128-bit salt
    }
    
    const encoder = new TextEncoder();
    const passwordKey = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveBits', 'deriveKey']
    );
    
    const key = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,  // OWASP recommended minimum
            hash: 'SHA-256'
        },
        passwordKey,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
    
    // Export raw key for Node.js compatibility if needed
    const rawKey = await crypto.subtle.exportKey('raw', key);
    
    return { key, salt, rawKey: new Uint8Array(rawKey) };
}

/**
 * Encrypt plaintext using AES-256-GCM with password-based key derivation
 * @param {string} plaintext - Text to encrypt
 * @param {string} password - Password for encryption
 * @returns {Promise<string>} Base64-encoded JSON containing salt, nonce, and ciphertext
 */
async function aesEncrypt(plaintext, password) {
    const encoder = new TextEncoder();
    
    // Derive key from password
    const { key, salt, rawKey } = await deriveKey(password);
    
    // Generate random nonce (96 bits for GCM)
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    
    // Encrypt
    let ciphertext;
    if (isNode && nodeCrypto && nodeCrypto.createCipheriv) {
        // Use Node.js native crypto for better performance
        const cipher = nodeCrypto.createCipheriv('aes-256-gcm', rawKey, nonce);
        const encrypted = Buffer.concat([
            cipher.update(plaintext, 'utf8'),
            cipher.final()
        ]);
        const tag = cipher.getAuthTag();
        ciphertext = new Uint8Array([...encrypted, ...tag]);
    } else {
        // Use Web Crypto API
        const encryptedBuffer = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce },
            key,
            encoder.encode(plaintext)
        );
        ciphertext = new Uint8Array(encryptedBuffer);
    }
    
    // Package everything together
    const result = {
        salt: arrayBufferToBase64(salt),
        nonce: arrayBufferToBase64(nonce),
        ciphertext: arrayBufferToBase64(ciphertext)
    };
    
    // Return as Base64-encoded JSON
    return btoa(JSON.stringify(result));
}

/**
 * Decrypt AES-256-GCM encrypted data
 * @param {string} encryptedData - Base64-encoded JSON from aesEncrypt
 * @param {string} password - Password for decryption
 * @returns {Promise<string>} Decrypted plaintext
 */
async function aesDecrypt(encryptedData, password) {
    try {
        // Decode the Base64-encoded JSON
        const jsonData = atob(encryptedData);
        const data = JSON.parse(jsonData);
        
        // Extract components
        const salt = base64ToArrayBuffer(data.salt);
        const nonce = base64ToArrayBuffer(data.nonce);
        const ciphertext = base64ToArrayBuffer(data.ciphertext);
        
        // Derive the same key from password and salt
        const { key, rawKey } = await deriveKey(password, salt);
        
        // Decrypt
        let plaintext;
        if (isNode && nodeCrypto && nodeCrypto.createDecipheriv) {
            // Use Node.js native crypto
            const authTagLength = 16; // GCM auth tag is 128 bits
            const encryptedData = ciphertext.slice(0, -authTagLength);
            const authTag = ciphertext.slice(-authTagLength);
            
            const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', rawKey, nonce);
            decipher.setAuthTag(authTag);
            
            plaintext = Buffer.concat([
                decipher.update(encryptedData),
                decipher.final()
            ]).toString('utf8');
        } else {
            // Use Web Crypto API
            const decryptedBuffer = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: nonce },
                key,
                ciphertext
            );
            const decoder = new TextDecoder();
            plaintext = decoder.decode(decryptedBuffer);
        }
        
        return plaintext;
    } catch (e) {
        throw new Error(`Decryption failed: ${e.message}`);
    }
}

/**
 * Encrypt using a pre-generated Base64-encoded 256-bit key
 * @param {string} plaintext - Text to encrypt
 * @param {string} keyB64 - Base64-encoded 32-byte key
 * @returns {Promise<string>} Base64-encoded JSON with nonce and ciphertext
 */
async function aesEncryptWithKey(plaintext, keyB64) {
    const encoder = new TextEncoder();
    const keyBytes = base64ToArrayBuffer(keyB64);
    
    if (keyBytes.length !== 32) {
        throw new Error('Key must be 32 bytes (256 bits)');
    }
    
    const key = await crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt']
    );
    
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    
    const encryptedBuffer = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce },
        key,
        encoder.encode(plaintext)
    );
    
    const result = {
        nonce: arrayBufferToBase64(nonce),
        ciphertext: arrayBufferToBase64(new Uint8Array(encryptedBuffer))
    };
    
    return btoa(JSON.stringify(result));
}

/**
 * Decrypt using a pre-generated Base64-encoded 256-bit key
 * @param {string} encryptedData - Base64-encoded JSON from aesEncryptWithKey
 * @param {string} keyB64 - Base64-encoded 32-byte key
 * @returns {Promise<string>} Decrypted plaintext
 */
async function aesDecryptWithKey(encryptedData, keyB64) {
    const keyBytes = base64ToArrayBuffer(keyB64);
    
    if (keyBytes.length !== 32) {
        throw new Error('Key must be 32 bytes (256 bits)');
    }
    
    const key = await crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt']
    );
    
    const jsonData = atob(encryptedData);
    const data = JSON.parse(jsonData);
    
    const nonce = base64ToArrayBuffer(data.nonce);
    const ciphertext = base64ToArrayBuffer(data.ciphertext);
    
    const decryptedBuffer = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce },
        key,
        ciphertext
    );
    
    const decoder = new TextDecoder();
    return decoder.decode(decryptedBuffer);
}

/**
 * Generate a random 256-bit key
 * @returns {Promise<string>} Base64-encoded 32-byte key
 */
async function generateKey() {
    const key = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
    
    const exported = await crypto.subtle.exportKey('raw', key);
    return arrayBufferToBase64(new Uint8Array(exported));
}

// Utility functions for Base64 conversion
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

// Polyfill for btoa/atob in Node.js if needed
if (isNode && typeof btoa === 'undefined') {
    global.btoa = function(str) {
        return Buffer.from(str, 'binary').toString('base64');
    };
    global.atob = function(str) {
        return Buffer.from(str, 'base64').toString('binary');
    };
}

/**
 * Run comprehensive test suite
 */
async function runTests() {
    console.log("=".repeat(60));
    console.log("AES-256-GCM Encryption Test Suite");
    console.log("=".repeat(60));
    
    let testsPassed = 0;
    let testsFailed = 0;
    
    // Test 1: Basic encryption/decryption with password
    console.log("\n[Test 1] Password-based encryption/decryption");
    try {
        const original = "Hello, AES-256!";
        const password = "super_secure_password";
        const encrypted = await aesEncrypt(original, password);
        const decrypted = await aesDecrypt(encrypted, password);
        
        if (decrypted !== original) {
            throw new Error(`Expected '${original}', got '${decrypted}'`);
        }
        
        console.log(`✓ Original: ${original}`);
        console.log(`✓ Encrypted: ${encrypted.substring(0, 50)}...`);
        console.log(`✓ Decrypted: ${decrypted}`);
        testsPassed++;
    } catch (e) {
        console.log(`✗ Failed: ${e.message}`);
        testsFailed++;
    }
    
    // Test 2: Unicode support
    console.log("\n[Test 2] Unicode and emoji support");
    try {
        const original = "Hello 世界! 🔐🌍";
        const password = "test123";
        const encrypted = await aesEncrypt(original, password);
        const decrypted = await aesDecrypt(encrypted, password);
        
        if (decrypted !== original) {
            throw new Error("Decryption mismatch");
        }
        
        console.log(`✓ Original: ${original}`);
        console.log(`✓ Decrypted: ${decrypted}`);
        testsPassed++;
    } catch (e) {
        console.log(`✗ Failed: ${e.message}`);
        testsFailed++;
    }
    
    // Test 3: Wrong password should fail
    console.log("\n[Test 3] Wrong password detection");
    try {
        const original = "Secret message";
        const encrypted = await aesEncrypt(original, "correct_password");
        
        try {
            await aesDecrypt(encrypted, "wrong_password");
            console.log("✗ Failed: Should have raised exception");
            testsFailed++;
        } catch {
            console.log("✓ Correctly rejected wrong password");
            testsPassed++;
        }
    } catch (e) {
        console.log(`✗ Failed: ${e.message}`);
        testsFailed++;
    }
    
    // Test 4: Key-based encryption
    console.log("\n[Test 4] Direct key-based encryption");
    try {
        const key = await generateKey();
        const original = "Direct key encryption";
        const encrypted = await aesEncryptWithKey(original, key);
        const decrypted = await aesDecryptWithKey(encrypted, key);
        
        if (decrypted !== original) {
            throw new Error("Decryption mismatch");
        }
        
        console.log(`✓ Generated Key: ${key.substring(0, 30)}...`);
        console.log(`✓ Original: ${original}`);
        console.log(`✓ Decrypted: ${decrypted}`);
        testsPassed++;
    } catch (e) {
        console.log(`✗ Failed: ${e.message}`);
        testsFailed++;
    }
    
    // Test 5: Long text
    console.log("\n[Test 5] Long text encryption");
    try {
        const original = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(10);
        const password = "long_text_password";
        const encrypted = await aesEncrypt(original, password);
        const decrypted = await aesDecrypt(encrypted, password);
        
        if (decrypted !== original) {
            throw new Error("Decryption mismatch");
        }
        
        console.log(`✓ Text length: ${original.length} characters`);
        console.log(`✓ Encrypted length: ${encrypted.length} characters`);
        console.log("✓ Long text encrypted and decrypted successfully");
        testsPassed++;
    } catch (e) {
        console.log(`✗ Failed: ${e.message}`);
        testsFailed++;
    }
    
    // Test 6: Empty string
    console.log("\n[Test 6] Empty string handling");
    try {
        const original = "";
        const password = "empty_test";
        const encrypted = await aesEncrypt(original, password);
        const decrypted = await aesDecrypt(encrypted, password);
        
        if (decrypted !== original) {
            throw new Error("Decryption mismatch");
        }
        
        console.log("✓ Empty string handled correctly");
        testsPassed++;
    } catch (e) {
        console.log(`✗ Failed: ${e.message}`);
        testsFailed++;
    }
    
    // Test 7: Special characters
    console.log("\n[Test 7] Special characters");
    try {
        const original = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`";
        const password = "special_chars";
        const encrypted = await aesEncrypt(original, password);
        const decrypted = await aesDecrypt(encrypted, password);
        
        if (decrypted !== original) {
            throw new Error("Decryption mismatch");
        }
        
        console.log(`✓ Original: ${original}`);
        console.log(`✓ Decrypted: ${decrypted}`);
        testsPassed++;
    } catch (e) {
        console.log(`✗ Failed: ${e.message}`);
        testsFailed++;
    }
    
    // Summary
    console.log("\n" + "=".repeat(60));
    console.log(`Tests Passed: ${testsPassed}`);
    console.log(`Tests Failed: ${testsFailed}`);
    console.log("=".repeat(60));
    
    return testsFailed === 0;
}

// Export for both Node.js and browser
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        aesEncrypt,
        aesDecrypt,
        aesEncryptWithKey,
        aesDecryptWithKey,
        generateKey,
        runTests
    };
}

// Run tests if executed directly in Node.js
if (isNode && require.main === module) {
    (async () => {
        await runTests();
        
        // Interactive example
        console.log("\n" + "=".repeat(60));
        console.log("Interactive Example");
        console.log("=".repeat(60));
        
        console.log("\nExample 1: Password-based encryption");
        const message = "This is a secret message!";
        const password = "my_secure_password";
        
        const encrypted = await aesEncrypt(message, password);
        console.log(`Original: ${message}`);
        console.log(`Password: ${password}`);
        console.log(`Encrypted: ${encrypted}`);
        
        const decrypted = await aesDecrypt(encrypted, password);
        console.log(`Decrypted: ${decrypted}`);
        
        console.log("\nExample 2: Key-based encryption");
        const key = await generateKey();
        console.log(`Generated Key: ${key}`);
        
        const encrypted2 = await aesEncryptWithKey("Another secret!", key);
        console.log(`Encrypted: ${encrypted2}`);
        
        const decrypted2 = await aesDecryptWithKey(encrypted2, key);
        console.log(`Decrypted: ${decrypted2}`);
    })();
}
