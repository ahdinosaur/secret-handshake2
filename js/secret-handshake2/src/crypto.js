const sodium = require('sodium-universal')
const b4a = require('b4a')

module.exports = {
  hash,
  auth,
  authVerify,
  diffieHellman,
  generateX25519Keypair,
  convertVerifyingEd25519ToPublicX25519,
  convertSigningEd25519ToSecretX25519,
  sign,
  signVerify,
  encrypt,
  decrypt,
}

/**
 * @typedef {Buffer | Uint8Array} B4A
 * @typedef {{ publicKey: B4A, secretKey: B4A }} X25519Keypair
 */

/**
 * @param {B4A} input
 * @returns {B4A}
 */
function hash(input) {
  const output = b4a.alloc(sodium.crypto_hash_sha256_BYTES)
  sodium.crypto_hash_sha256(output, input)
  return output
}

/**
 * @param {B4A} input
 * @param {B4A} key
 * @returns {B4A}
 */
function auth(input, key) {
  const output = b4a.alloc(sodium.crypto_auth_BYTES)
  sodium.crypto_auth(output, input, key)
  return output
}

/**
 * @param {B4A} output
 * @param {B4A} input
 * @param {B4A} key
 * @returns boolean
 */
function authVerify(output, input, key) {
  return sodium.crypto_auth_verify(output, input, key)
}

/**
 * @param {B4A} localSecretKey
 * @param {B4A} remotePublicKey
 * @returns {B4A}
 */
function diffieHellman(localSecretKey, remotePublicKey) {
  const sharedSecret = b4a.alloc(sodium.crypto_scalarmult_BYTES)
  sodium.crypto_scalarmult(sharedSecret, localSecretKey, remotePublicKey)
  return sharedSecret
}

/**
 * @returns {X25519Keypair}
 */
function generateX25519Keypair() {
  const secretKey = b4a.allocUnsafe(sodium.crypto_scalarmult_SCALARBYTES)
  sodium.randombytes_buf(secretKey)

  const publicKey = b4a.allocUnsafe(sodium.crypto_scalarmult_BYTES)
  sodium.crypto_scalarmult_base(publicKey, secretKey)

  return {
    secretKey,
    publicKey,
  }
}

/**
 * @param {B4A} verifyingEd25519Key
 * @returns {B4A | null}
 */
function convertVerifyingEd25519ToPublicX25519(verifyingEd25519Key) {
  const publicX25519Key = b4a.alloc(sodium.crypto_box_PUBLICKEYBYTES)
  try {
    sodium.crypto_sign_ed25519_pk_to_curve25519(publicX25519Key, verifyingEd25519Key)
  } catch {
    return null
  }
  return publicX25519Key
}

/**
 * @param {B4A} signingEd25519Key
 * @returns {B4A | null}
 */
function convertSigningEd25519ToSecretX25519(signingEd25519Key) {
  const secretX25519Key = b4a.alloc(sodium.crypto_box_SECRETKEYBYTES)
  try {
    sodium.crypto_sign_ed25519_sk_to_curve25519(secretX25519Key, signingEd25519Key)
  } catch {
    return null
  }
  return secretX25519Key
}

/**
 * @param {B4A} signingEd25519Key
 * @param {B4A} msg
 * @returns {B4A}
 */
function sign(signingEd25519Key, msg) {
  const sig = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(sig, msg, signingEd25519Key)
  return sig
}

/**
 * @param {B4A} verifyingEd25519Key
 * @param {B4A} msg
 * @param {B4A} sig
 * @returns {boolean}
 */
function signVerify(verifyingEd25519Key, msg, sig) {
  return sodium.crypto_sign_verify_detached(sig, msg, verifyingEd25519Key)
}


/**
 * @param {B4A} key
 * @param {B4A} nonce
 * @param {B4A} plaintext
 * @returns {B4A}
 */
function encrypt(key, nonce, plaintext) {
  const ciphertext = b4a.alloc(plaintext.length + sodium.crypto_aead_chacha20poly1305_ietf_ABYTES)
  sodium.crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, plaintext, null, null, nonce, key)
  return ciphertext
}

/**
 * @param {B4A} key
 * @param {B4A} nonce
 * @param {B4A} ciphertext
 * @returns {B4A | null}
 */
function decrypt(key, nonce, ciphertext) {
  const plaintext = b4a.alloc(ciphertext.length - sodium.crypto_aead_chacha20poly1305_ietf_ABYTES)
  const decryptedBytes = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(plaintext, null, ciphertext, null, nonce, key)
  if (decryptedBytes !== 0) return plaintext
  else return null
}
