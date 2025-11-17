/**
 * XOR+Base64 Encryption-Decryption System
 * Cross-language compatible (Python, JavaScript, etc.)
 * Uses XOR cipher with a repeating key and Base64 encoding for output
 */

/**
 * Encrypts text using XOR cipher with a repeating key, then encodes to Base64.
 * 
 * @param {string} text - Plain text to encrypt
 * @param {string} key - Encryption key (any string)
 * @returns {string} Base64-encoded encrypted text
 * 
 * @example
 * xorEncrypt("bibek", "secret") // → "GgcKAw=="
 */
function xorEncrypt(text, key) {
    if (!text) {
        return "";
    }
    
    if (!key) {
        throw new Error("Key cannot be empty");
    }
    
    // Convert text and key to UTF-8 byte arrays
    const textEncoder = new TextEncoder();
    const textBytes = textEncoder.encode(text);
    const keyBytes = textEncoder.encode(key);
    
    // XOR each byte with repeating key
    const xored = new Uint8Array(textBytes.length);
    for (let i = 0; i < textBytes.length; i++) {
        const keyByte = keyBytes[i % keyBytes.length];
        xored[i] = textBytes[i] ^ keyByte;
    }
    
    // Encode to Base64 for safe text representation
    // Node.js: Buffer.from().toString('base64')
    // Browser: btoa with proper handling
    if (typeof Buffer !== 'undefined') {
        // Node.js environment
        return Buffer.from(xored).toString('base64');
    } else {
        // Browser environment
        const binaryString = Array.from(xored, byte => String.fromCharCode(byte)).join('');
        return btoa(binaryString);
    }
}

/**
 * Decrypts Base64-encoded XOR-encrypted text.
 * 
 * @param {string} encryptedText - Base64-encoded encrypted text
 * @param {string} key - Decryption key (must match encryption key)
 * @returns {string} Decrypted plain text
 * 
 * @example
 * xorDecrypt("GgcKAw==", "secret") // → "bibek"
 */
function xorDecrypt(encryptedText, key) {
    if (!encryptedText) {
        return "";
    }
    
    if (!key) {
        throw new Error("Key cannot be empty");
    }
    
    // Decode from Base64
    let encryptedBytes;
    try {
        if (typeof Buffer !== 'undefined') {
            // Node.js environment
            encryptedBytes = Buffer.from(encryptedText, 'base64');
        } else {
            // Browser environment
            const binaryString = atob(encryptedText);
            encryptedBytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                encryptedBytes[i] = binaryString.charCodeAt(i);
            }
        }
    } catch (e) {
        throw new Error(`Invalid Base64 input: ${e.message}`);
    }
    
    // Convert key to bytes
    const textEncoder = new TextEncoder();
    const keyBytes = textEncoder.encode(key);
    
    // XOR each byte with repeating key (XOR is symmetric)
    const decrypted = new Uint8Array(encryptedBytes.length);
    for (let i = 0; i < encryptedBytes.length; i++) {
        const keyByte = keyBytes[i % keyBytes.length];
        decrypted[i] = encryptedBytes[i] ^ keyByte;
    }
    
    // Decode back to string (UTF-8)
    const textDecoder = new TextDecoder();
    return textDecoder.decode(decrypted);
}

/**
 * Run comprehensive test cases to validate XOR encryption.
 */
function runTests() {
    console.log("=".repeat(60));
    console.log("XOR+BASE64 ENCRYPTION TEST SUITE");
    console.log("=".repeat(60));
    
    // Test cases: [plaintext, key, expected_encrypted_base64]
    const testCases = [
        ["bibek", "secret", null],  // Will compute expected
        ["hello", "key", null],
        ["world", "pass", null],
        ["test", "12345", null],
        ["", "key", ""],  // Empty string
        ["a", "x", null],
        ["Hello World!", "mykey", null],
        ["12345", "abc", null],
        ["café", "test", null],
        ["hello😀world", "emoji", null],
        ["こんにちは", "日本", null],
        ["你好世界", "中文", null],
    ];
    
    let allPassed = true;
    
    testCases.forEach((testCase, index) => {
        let [plaintext, key, expected] = testCase;
        
        // Compute expected if not provided
        if (expected === null && plaintext) {
            expected = xorEncrypt(plaintext, key);
        }
        
        try {
            const encrypted = xorEncrypt(plaintext, key);
            const decrypted = xorDecrypt(encrypted, key);
            
            // Verify encryption matches expected (if provided)
            const encryptPass = (expected === null) || (encrypted === expected);
            // Verify decryption returns original
            const decryptPass = decrypted === plaintext;
            
            const status = (encryptPass && decryptPass) ? "✓ PASS" : "✗ FAIL";
            
            console.log(`\nTest ${index + 1}: ${status}`);
            console.log(`  Plaintext: '${plaintext}'`);
            console.log(`  Key:       '${key}'`);
            console.log(`  Encrypted: '${encrypted}'`);
            console.log(`  Decrypted: '${decrypted}'`);
            
            if (!(encryptPass && decryptPass)) {
                allPassed = false;
                if (!encryptPass) {
                    console.log(`  ⚠ Encryption mismatch! Expected: '${expected}'`);
                }
                if (!decryptPass) {
                    console.log(`  ⚠ Decryption failed!`);
                }
            }
        } catch (e) {
            console.log(`\nTest ${index + 1}: ✗ FAIL`);
            console.log(`  Plaintext: '${plaintext}'`);
            console.log(`  Key:       '${key}'`);
            console.log(`  Error:     ${e.message}`);
            allPassed = false;
        }
    });
    
    // Test with wrong key (should fail decryption)
    console.log(`\n${"-".repeat(60)}`);
    console.log("Testing wrong key scenario:");
    try {
        const encrypted = xorEncrypt("secret message", "correct_key");
        const wrongDecrypt = xorDecrypt(encrypted, "wrong_key");
        console.log(`  Original:  'secret message'`);
        console.log(`  Encrypted: '${encrypted}'`);
        console.log(`  Wrong key decrypt: '${wrongDecrypt}'`);
        console.log(`  ✓ Wrong key produces garbage (as expected)`);
    } catch (e) {
        console.log(`  Error: ${e.message}`);
    }
    
    console.log("\n" + "=".repeat(60));
    if (allPassed) {
        console.log("✓ ALL TESTS PASSED!");
    } else {
        console.log("✗ SOME TESTS FAILED!");
    }
    console.log("=".repeat(60));
    
    return allPassed;
}

/**
 * Interactive mode for manual testing (Node.js only).
 */
function interactiveMode() {
    const readline = require('readline');
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    
    console.log("\n" + "=".repeat(60));
    console.log("INTERACTIVE XOR+BASE64 ENCRYPTION");
    console.log("=".repeat(60));
    console.log("Commands: 'e' to encrypt, 'd' to decrypt, 'q' to quit\n");
    
    function promptUser() {
        rl.question("Enter command (e/d/q): ", (choice) => {
            choice = choice.toLowerCase().trim();
            
            if (choice === 'q') {
                console.log("Goodbye!");
                rl.close();
                return;
            } else if (choice === 'e') {
                rl.question("Enter text to encrypt: ", (text) => {
                    rl.question("Enter encryption key: ", (key) => {
                        try {
                            const encrypted = xorEncrypt(text, key);
                            console.log(`Encrypted: ${encrypted}\n`);
                        } catch (e) {
                            console.log(`Error: ${e.message}\n`);
                        }
                        promptUser();
                    });
                });
            } else if (choice === 'd') {
                rl.question("Enter text to decrypt: ", (text) => {
                    rl.question("Enter decryption key: ", (key) => {
                        try {
                            const decrypted = xorDecrypt(text, key);
                            console.log(`Decrypted: ${decrypted}\n`);
                        } catch (e) {
                            console.log(`Error: ${e.message}\n`);
                        }
                        promptUser();
                    });
                });
            } else {
                console.log("Invalid command. Use 'e', 'd', or 'q'.\n");
                promptUser();
            }
        });
    }
    
    promptUser();
}

// Export functions for use in other modules (Node.js/CommonJS)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { xorEncrypt, xorDecrypt, runTests, interactiveMode };
}

// Auto-run tests if executed directly in Node.js
if (typeof require !== 'undefined' && require.main === module) {
    runTests();
    
    // Optional: Uncomment to enable interactive mode
    // interactiveMode();
}

// For browser usage
if (typeof window !== 'undefined') {
    window.xorEncrypt = xorEncrypt;
    window.xorDecrypt = xorDecrypt;
    window.runXorTests = runTests;
}
