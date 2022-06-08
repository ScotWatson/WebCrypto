if (!('crypto' in self)) {
  throw new Error("Module can not load");
}

export class Crypto {
  // Represents a volume root file
  // blobFile: (Blob, optional) 
  constructor(blobFile) {
    this._records = [];
  }
  // Adds a record to the file
  // numType: 
  // objData: 
  // Returns: (ArrayBuffer) The record as it will appear in the file
  addRecord(numType, objData) {
  }
  // Remove unnecessary records from the file
  purge() {
  }
  // Creates a Blob with the current records
  // Returns: (Blob) Entire file containing all records
  save() {
  }
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
