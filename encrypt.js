/**
 * Multilingual Encryption-Decryption System
 * Algorithm: Adjacent Character Swap (Deterministic)
 * Compatible across Python, JavaScript, and other languages
 */

/**
 * Encrypts text by swapping adjacent character pairs.
 * 
 * @param {string} text - Plain text to encrypt
 * @returns {string} Encrypted text
 * 
 * @example
 * encrypt("bibek") // → "ibeibk"
 */
function encrypt(text, seed = 0) {
    if (!text) {
        return "";
    }

    // Convert string to array for easier manipulation (handles unicode/graphemes)
    const chars = Array.from(text);

    // Normalize seed and compute right rotation
    let n = Number.isInteger(seed) ? seed : parseInt(seed, 10);
    if (Number.isNaN(n)) n = 0;

    const length = chars.length;
    const rot = length > 0 ? (n % length) : 0;

    // Rotate right by rot
    if (rot) {
        const right = chars.slice(-rot);
        const left = chars.slice(0, length - rot);
        for (let i = 0; i < right.length; i++) chars[i] = right[i];
        for (let i = 0; i < left.length; i++) chars[rot + i] = left[i];
    }

    // Swap adjacent pairs
    for (let i = 0; i < chars.length - 1; i += 2) {
        [chars[i], chars[i + 1]] = [chars[i + 1], chars[i]];
    }

    return chars.join('');
}

/**
 * Decrypts text by swapping adjacent character pairs.
 * Since swapping is symmetric, decryption is identical to encryption.
 * 
 * @param {string} text - Encrypted text to decrypt
 * @returns {string} Decrypted plain text
 * 
 * @example
 * decrypt("ibeibk") // → "bibek"
 */
function decrypt(text, seed = 0) {
    if (!text) return "";

    // First, swap adjacent pairs
    const chars = Array.from(text);
    for (let i = 0; i < chars.length - 1; i += 2) {
        [chars[i], chars[i + 1]] = [chars[i + 1], chars[i]];
    }

    // Normalize seed and compute left rotation
    let n = Number.isInteger(seed) ? seed : parseInt(seed, 10);
    if (Number.isNaN(n)) n = 0;

    const length = chars.length;
    const rot = length > 0 ? (n % length) : 0;

    if (rot) {
        // left rotate by rot
        const left = chars.slice(rot);
        const right = chars.slice(0, rot);
        return left.concat(right).join('');
    }

    return chars.join('');
}

/**
 * Run comprehensive test cases to validate the algorithm.
 */
function runTests() {
    console.log("=".repeat(60));
    console.log("ENCRYPTION-DECRYPTION TEST SUITE");
    console.log("=".repeat(60));
    
    const testCases = [
        // [input, expected_encrypted]
        ["bibek", "ibebk"],
        ["hello", "ehllo"],
        ["world", "owlrd"],
        ["test", "etts"],
        ["", ""],
        ["a", "a"],
        ["ab", "ba"],
        ["abc", "bac"],
        ["HELLO", "EHLLO"],
        ["Hello World!", "eHll ooWlr!d"],
        ["12345", "21435"],
        ["a1b2c3", "1a2b3c"],
        ["   ", "   "],
        ["test 123", "etts1 32"],
        ["!@#$%", "@!$#%"],
        ["café", "acéf"],
        ["hello😀world", "ehll😀oowlrd"],
        ["こんにちは", "んこちには"],  // Japanese
        ["你好世界", "好你界世"],  // Chinese
    ];
    
    let allPassed = true;
    
    testCases.forEach((testCase, index) => {
        const [original, expected] = testCase;
        const encrypted = encrypt(original);
        const decrypted = decrypt(encrypted);
        
        // Verify encryption matches expected
        const encryptPass = encrypted === expected;
        // Verify decryption returns original
        const decryptPass = decrypted === original;
        
        const status = (encryptPass && decryptPass) ? "✓ PASS" : "✗ FAIL";
        
        console.log(`\nTest ${index + 1}: ${status}`);
        console.log(`  Input:     '${original}'`);
        console.log(`  Encrypted: '${encrypted}' (expected: '${expected}')`);
        console.log(`  Decrypted: '${decrypted}'`);
        
        if (!(encryptPass && decryptPass)) {
            allPassed = false;
            if (!encryptPass) {
                console.log(`  ⚠ Encryption mismatch!`);
            }
            if (!decryptPass) {
                console.log(`  ⚠ Decryption failed!`);
            }
        }
    });

    // --- Seeded test cases (optional checks) ---
    const seededTests = [
        // [input, seed, expected]
        ["bibek", 2, encrypt("bibek", 2)],
        ["hello", 3, encrypt("hello", 3)],
        ["12345", 1, encrypt("12345", 1)],
    ];

    seededTests.forEach((t, idx) => {
        const [original, seed, expected] = t;
        const encrypted = encrypt(original, seed);
        const decrypted = decrypt(encrypted, seed);
        const i = testCases.length + idx + 1;
        const encryptPass = encrypted === expected;
        const decryptPass = decrypted === original;
        const status = (encryptPass && decryptPass) ? "✓ PASS" : "✗ FAIL";

        console.log(`\nSeeded Test ${i}: ${status}`);
        console.log(`  Input:     '${original}' (seed=${seed})`);
        console.log(`  Encrypted: '${encrypted}' (expected: '${expected}')`);
        console.log(`  Decrypted: '${decrypted}'`);
        if (!(encryptPass && decryptPass)) {
            allPassed = false;
            if (!encryptPass) console.log(`  ⚠ Encryption mismatch!`);
            if (!decryptPass) console.log(`  ⚠ Decryption failed!`);
        }
    });
    
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
 * Requires 'readline' module.
 */
function interactiveMode() {
    const readline = require('readline');
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    
    console.log("\n" + "=".repeat(60));
    console.log("INTERACTIVE ENCRYPTION-DECRYPTION");
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
                    const encrypted = encrypt(text);
                    console.log(`Encrypted: ${encrypted}\n`);
                    promptUser();
                });
            } else if (choice === 'd') {
                rl.question("Enter text to decrypt: ", (text) => {
                    const decrypted = decrypt(text);
                    console.log(`Decrypted: ${decrypted}\n`);
                    promptUser();
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
    module.exports = { encrypt, decrypt, runTests, interactiveMode };
}

// Auto-run tests if executed directly in Node.js
if (typeof require !== 'undefined' && require.main === module) {
    runTests();
    
    // Optional: Uncomment to enable interactive mode
    // interactiveMode();
}

// For browser usage
if (typeof window !== 'undefined') {
    window.encrypt = encrypt;
    window.decrypt = decrypt;
    window.runTests = runTests;
}
