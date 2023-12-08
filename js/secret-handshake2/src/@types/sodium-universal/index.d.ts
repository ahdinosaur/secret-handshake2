declare module "sodium-universal" {
  type B4A = Buffer | Uint8Array

  export const crypto_hash_sha256_BYTES: number
  export function crypto_hash_sha256(output: B4A, input: B4A)

  export const crypto_auth_BYTES: number
  export const crypto_auth_KEYBYTES: number
  export function crypto_auth(output: B4A, input: B4A, key: B4A)
  export function crypto_auth_verify(output: B4A, input: B4A, key: B4A): boolean

  export const crypto_scalarmult_BYTES: number
  export const crypto_scalarmult_SCALARBYTES: number
  export function crypto_scalarmult_base(q: B4A, n: B4A)
  export function crypto_scalarmult(q: B4A, n: B4A, p: B4A)

  export function randombytes_buf(buf: B4A)

  export const crypto_box_SECRETKEYBYTES: number
  export const crypto_box_PUBLICKEYBYTES: number
  export const crypto_sign_SECRETKEYBYTES: number
  export const crypto_sign_PUBLICKEYBYTES: number
  export const crypto_sign_BYTES: number
  export function crypto_sign_detached(sig: B4A, m: B4A, sk: B4A)
  export function crypto_sign_verify_detached(sig: B4A, m: B4A, sk: B4A)
  export function crypto_sign_ed25519_pk_to_curve25519(x25519_pk: B4A, ed25519_pk: B4A)
  export function crypto_sign_ed25519_sk_to_curve25519(x25519_sk: B4A, ed25519_sk: B4A)

  export const crypto_aead_chacha20poly1305_ietf_ABYTES: number
  export const crypto_aead_chacha20poly1305_ietf_KEYBYTES: number
  export const crypto_aead_chacha20poly1305_ietf_NPUBBYTES: number
  export const crypto_aead_chacha20poly1305_ietf_NSECBYTES: number
  export const crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX: number
  export function crypto_aead_chacha20poly1305_ietf_encrypt(c: B4A, m: B4A, ad: B4A | null, nsec: null, npub: B4A, k: B4A): number
  export function crypto_aead_chacha20poly1305_ietf_decrypt(m: B4A, nsec: null, c: B4A, ad: B4A | null, npub: B4A, k: B4A): number
}
