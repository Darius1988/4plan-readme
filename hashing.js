const sodium = require('sodium-native');

/**
 * Convert base64 key to Buffer
 */
const base64ToBuffer = base64 => Buffer.from(base64, 'base64');

/**
 * Hash the data using BLAKE2b (Commonly Used with Curve25519)
 */
const hashData = data => {
    const input = Buffer.from(JSON.stringify(data));
    const output = Buffer.alloc(sodium.crypto_generichash_BYTES);
    sodium.crypto_generichash(output, input);
    return output.toString('hex');
}

/**
 * Convert a 32-byte private key (seed) into a full 64-byte secret key
 */
const deriveFullSecretKey = seedBase64 => {
    const seed = base64ToBuffer(seedBase64);
    if (seed.length !== sodium.crypto_sign_SEEDBYTES) {
        throw new Error("Invalid private key seed length. Expected 32 bytes.");
    }

    const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
    const secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES);
    
    // Generate full secret key from seed
    sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed);
    
    return secretKey;
}

/**
 * Sign a payload using Ed25519 (Curve25519-related)
 */
const signPayload = (payload, privateKeySeedBase64) => {
    const privateKey = deriveFullSecretKey(privateKeySeedBase64);
    const message = Buffer.from(JSON.stringify(payload));

    const signature = Buffer.alloc(sodium.crypto_sign_BYTES);
    sodium.crypto_sign_detached(signature, message, privateKey);

    return signature.toString('base64');
}

/**
 * Main function to generate response with signed payload
 */
const generateSignedResponse = (nonce, content) => {
    const payload = { nonce, content };
    const hashedPayload = hashData(payload);

    // Sign the hashed payload using the derived full secret key
    const signature = signPayload(hashedPayload, process.env.payload_private_key);
    return { signature, payload };
}

const verifySignature = (signatureBase64, payload) => {
    const hashedPayload = hashData(payload);
    const signature = base64ToBuffer(signatureBase64);
    const message = Buffer.from(JSON.stringify(hashedPayload));
    const publicKey = base64ToBuffer(process.env.payload_public_key);

    return sodium.crypto_sign_verify_detached(signature, message, publicKey);
}

module.exports = { generateSignedResponse, verifySignature }

// // Example Usage
// const response = generateSignedResponse({ message: "Hello, this is a secure response!" });
// console.log(response);

// // Example verification
// const isValid = verifySignature(response.signature, hashData(response.payload), '9k9x5kPkDiuMGGm1YNI0oFWiuG34cOvr/PmcYyvSLtk=');
// console.log("Signature Valid:", isValid);
