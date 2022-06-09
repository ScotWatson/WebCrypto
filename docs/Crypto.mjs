/*
(c) 2022 Scot Watson  All Rights Reserved
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

if (!('crypto' in self)) {
  throw new Error("Module can not load");
}

export class Crypto {
}

// Fills the passed TypedArray with cryptographically sound random values
// typedArray: (TypedArray, but not Float32Array nor Float64Array) All elements in the array will be overwritten with random numbers
// Return: the typedArray (not a copy)
// QuotaExceededError - Thrown if the byteLength of typedArray exceeds 65,536.
function getRandomValues(typedArray) {
  return self.crypto.getRandomValues(typedArray);
}

// Returns a randomly generated, 36 character long v4 UUID.
// Return: (String) containing a randomly generated, 36 character long v4 UUID
function randomUUID() {
  return self.crypto.randomUUID();
}

// Decrypts some encrypted data using RSA-OAEP
// key: (CryptoKey)
// data: (BufferSource)
// label: (BufferSource) An array of bytes that does not itself need to be encrypted but which should be bound to the ciphertext
//   A digest of the label is part of the input to the encryption operation.
//   Unless your application calls for a label, you can just omit this argument and it will not affect the security of the encryption operation.
// To use RSA-OAEP, pass an RsaOaepParams object.
// Return: (Promise that fulfills with an ArrayBuffer) containing the plaintext.
function decrypt_RSA_OAEP(key, data, label) {
  const algorithm = {
    name: "RSA-OAEP",
    label: label,
  };
  return self.crypto.subtle.decrypt(algorithm, key, data);
}

// Decrypts some encrypted data using AES-CTR
// key: (CryptoKey)
// data: (BufferSource)
// counter: (BufferSource) the initial value of the counter block. This must be 16 bytes long (the AES block size). The rightmost length bits of this block are used for the counter, and the rest is used for the nonce. For example, if length is set to 64, then the first half of counter is the nonce and the second half is used for the counter.,
// length: (Number) the number of bits in the counter block that are used for the actual counter. The counter must be big enough that it doesn't wrap: if the message is n blocks and the counter is m bits long, then the following must be true: n <= 2^m. The NIST SP800-38A standard, which defines CTR, suggests that the counter should occupy half of the counter block (see Appendix B.2), so for AES it would be 64.
// To use AES-CTR, pass an AesCtrParams object.
// Return: (Promise that fulfills with an ArrayBuffer) containing the plaintext.
function decrypt_AES_CTR(key, data, counter, length) {
  const algorithm = {
    name: "AES-CTR",
    counter: counter,
    length: length,
  };
  return self.crypto.subtle.decrypt(algorithm, key, data);
}

// Decrypts some encrypted data using AES-CBC
// key: (CryptoKey)
// data: (BufferSource)
// iv: (BufferSource) The initialization vector. Must be 16 bytes, unpredictable, and preferably cryptographically random. However, it need not be secret (for example, it may be transmitted unencrypted along with the ciphertext)
// To use AES-CBC, pass an AesCbcParams object.
// Return: (Promise that fulfills with an ArrayBuffer) containing the plaintext.
function decrypt_AES_CBC(key, data, iv) {
  const algorithm = {
    name: "AES-CBC",
    iv: iv,
  };
  return self.crypto.subtle.decrypt(algorithm, key, data);
}

// Decrypts some encrypted data using AES-GCM
// key: (CryptoKey)
// data: (BufferSource)
// iv: (BufferSource) the initialization vector. This must be unique for every encryption operation carried out with a given key. Put another way: never reuse an IV with the same key. The AES-GCM specification recommends that the IV should be 96 bits long, and typically contains bits from a random number generator. Section 8.2 of the specification outlines methods for constructing IVs. Note that the IV does not have to be secret, just unique: so it is OK, for example, to transmit it in the clear alongside the encrypted message.
// additionalData: (Optional) (BufferSource). This contains additional data that will not be encrypted but will be authenticated along with the encrypted data. If additionalData is given here then the same data must be given in the corresponding call to decrypt(): if the data given to the decrypt() call does not match the original data, the decryption will throw an exception. This gives you a way to authenticate associated data without having to encrypt it.
//     The bit length of additionalData must be smaller than 2^64 - 1.
//     The additionalData property is optional and may be omitted without compromising the security of the encryption operation.
// tagLength: (Optional) (Number) This determines the size in bits of the authentication tag generated in the encryption operation and used for authentication in the corresponding decryption.
//     According to the Web Crypto specification this must have one of the following values: 32, 64, 96, 104, 112, 120, or 128. The AES-GCM specification recommends that it should be 96, 104, 112, 120 or 128, although 32 or 64 bits may be acceptable in some applications: Appendix C of the specification provides additional guidance here., defaults to 128 if it is not specified.
// To use AES-GCM, pass an AesGcmParams object.
// Return: (Promise that fulfills with an ArrayBuffer) containing the plaintext.
function decrypt_AES_GCM(key, data) {
  const algorithm = {
    name: "AES-GCM",
    iv: iv,
    additionalData: additionalData,
    tagLength: tagLength,
  };
  return self.crypto.subtle.decrypt(algorithm, key, data);
}

// derive an array of bits from a base key
// baseKey: (CryptoKey) representing the input to the derivation algorithm. If algorithm is ECDH, this will be the ECDH private key. Otherwise it will be the initial key material for the derivation function: for example, for PBKDF2 it might be a password, imported as a CryptoKey using SubtleCrypto.importKey().
// length: (Number) representing the number of bits to derive. To be compatible with all browsers, the number should be a multiple of 8.
// Return: (Promise that fulfills with an ArrayBuffer) containing the derived bits
function deriveBits(algorithm, baseKey, length) {
  {  
    name: "ECDH",
    public: (CryptoKey) the public key of the other entity,
  }
}

// derive an array of bits from a base key
// baseKey: (CryptoKey) representing the input to the derivation algorithm. If algorithm is ECDH, this will be the ECDH private key. Otherwise it will be the initial key material for the derivation function: for example, for PBKDF2 it might be a password, imported as a CryptoKey using SubtleCrypto.importKey().
// length: (Number) representing the number of bits to derive. To be compatible with all browsers, the number should be a multiple of 8.
// Return: (Promise that fulfills with an ArrayBuffer) containing the derived bits
function deriveBits(algorithm, baseKey, length) {
  {  
    name: "HKDF",
    hash: (String) representing the digest algorithm to use. This may be one of:
    //        SHA-1
    //        SHA-256
    //        SHA-384
    //        SHA-512
    salt: (BufferSource) The HKDF specification states that adding salt "adds significantly to the strength of HKDF". Ideally, the salt is a random or pseudo-random value with the same length as the output of the digest function. Unlike the input key material passed into deriveKey(), salt does not need to be kept secret.
    info: (BufferSource) representing application-specific contextual information. This is used to bind the derived key to an application or context, and enables you to derive different keys for different contexts while using the same input key material. It's important that this should be independent of the input key material itself. This property is required but may be an empty buffer.
  }
}

// derive an array of bits from a base key
// baseKey: (CryptoKey) representing the input to the derivation algorithm. If algorithm is ECDH, this will be the ECDH private key. Otherwise it will be the initial key material for the derivation function: for example, for PBKDF2 it might be a password, imported as a CryptoKey using SubtleCrypto.importKey().
// length: (Number) representing the number of bits to derive. To be compatible with all browsers, the number should be a multiple of 8.
// Return: (Promise that fulfills with an ArrayBuffer) containing the derived bits
function deriveBits(algorithm, baseKey, length) {
  {
    name: "PBKDF2",
    hash: (String) representing the digest algorithm to use. This may be one of:
    //        SHA-1
    //        SHA-256
    //        SHA-384
    //        SHA-512
    //    Warning: SHA-1 is considered vulnerable in most cryptographic applications, but is still considered safe in PBKDF2. However, it's advisable to transition away from it everywhere, so unless you need to use SHA-1, don't. Use a different digest algorithm instead.
    salt: (BufferSource) This should be a random or pseudo-random value of at least 16 bytes. Unlike the input key material passed into deriveKey(), salt does not need to be kept secret.
    iterations: (Number) representing the number of times the hash function will be executed in deriveKey(). This determines how computationally expensive (that is, slow) the deriveKey() operation will be. In this context, slow is good, since it makes it more expensive for an attacker to run a dictionary attack against the keys. The general guidance here is to use as many iterations as possible, subject to keeping an acceptable level of performance for your application.
  }
}

// derive a secret key from a master key
// algorithm:
// baseKey:
// derivedKeyAlgorithm:
// extractable:
// keyUsages:
function deriveKey(algorithm, baseKey, derivedKeyAlgorithm, extractable, keyUsages) {

baseKey: (CryptoKey) representing the input to the derivation algorithm. If algorithm is ECDH, then this will be the ECDH private key. Otherwise it will be the initial key material for the derivation function: for example, for PBKDF2 it might be a password, imported as a CryptoKey using SubtleCrypto.importKey().
derivedKeyAlgorithm:

    An object defining the algorithm the derived key will be used for.

        For HMAC: pass an HmacKeyGenParams object.
        For AES-CTR, AES-CBC, AES-GCM, or AES-KW: pass an AesKeyGenParams object.

extractable: (Boolean) value indicating whether it will be possible to export the key using SubtleCrypto.exportKey() or SubtleCrypto.wrapKey().
keyUsages: (Array) indicating what can be done with the derived key. Note that the key usages must be allowed by the algorithm set in derivedKeyAlgorithm. Possible values of the array are:
        encrypt: The key may be used to encrypt messages.
        decrypt: The key may be used to decrypt messages.
        sign: The key may be used to sign messages.
        verify: The key may be used to verify signatures.
        deriveKey: The key may be used in deriving a new key.
        deriveBits: The key may be used in deriving bits.
        wrapKey: The key may be used to wrap a key.
        unwrapKey: The key may be used to unwrap a key.



}

function digest() {
}

function encrypt() {
}

function exportKey() {
}

function generateKey() {
}

function importKey() {
}

function sign() {
}

function unwrapKey() {
}

function verify() {
}

function wrapKey() {
}


// Encrypts the given plaintext with the given key using the given iv, if provided
// Using AES-256 block cipher in CBC mode
// Padded with PKCS#7, (RFC2315 Section 10.3, step 2)
// Uint8Array is used, instead of ArrayBuffer, to allow a portion of a buffer to be used
// plaintext: (Uint8Array) plain (unencrypted) contents
// key: (Uint8Array) key to use to encrypt contents
// iv: (Uint8Array, optional) initialization vector
// Returns : (Promise, resolving to Object, containing members iv and ciphertext)
//   iv: (Uint8Array) initialization vector
//   ciphertext: (ArrayBuffer) encrypted contents
export function encrypt_AES256_CBC(plaintext, key, iv) {
  let retVal = {};
  if (!iv) {
    retVal.iv = new Uint8Array(randomData(16));
  }
  return window.crypto.subtle.importKey("raw", key, "AES-CBC", false, [ "encrypt", "decrypt" ]).then(function (myImportedKey) {
    let myAesCbcParams = {name: "AES-CBC", iv: retVal.iv};
    return window.crypto.subtle.encrypt(myAesCbcParams, myImportedKey, plaintext);
  }).then(function (ciphertext) {
    retVal.ciphertext = ciphertext;
    return retVal;
  });
}

// Decrypts the given ciphertext with the given key
// Using AES-256 block cipher in CBC mode
// Assumes padding of PKCS#7, (RFC2315 Section 10.3, step 2)
// Uint8Array is used, instead of ArrayBuffer, to allow a portion of a buffer to be used
// ciphertext: (Uint8Array) encrypted contents
// key: (Uint8Array) key to decrypt the contents
// iv: (Uint8Array) initialization vector
// Returns : (Promise, resolving to ArrayBuffer) plain (unencrypted) contents
export function decrypt_AES256_CBC(ciphertext, key, iv) {
  return window.crypto.subtle.importKey("raw", key, "AES-CBC", false, [ "encrypt", "decrypt" ]).then(function (myImportedKey) {
    let myAesCbcParams = {name: "AES-CBC", iv: iv};
    return window.crypto.subtle.decrypt(myAesCbcParams, myImportedKey, ciphertext);
  });
}
