const {
  INITIATOR_HELLO_LENGTH,
  RESPONDER_HELLO_LENGTH,
  INITIATOR_AUTHENTICATE_PLAINTEXT_LENGTH,
  INITIATOR_AUTHENTICATE_CIPHERTEXT_LENGTH,
  RESPONDER_AUTHENTICATE_PLAINTEXT_LENGTH,
  RESPONDER_AUTHENTICATE_CIPHERTEXT_LENGTH,
  initiatorHello,
  responderAcknowledge,
  responderHello,
  initiatorAcknowledge,
  initiatorAuthenticate,
  responderAccept,
  responderAuthenticate,
  initiatorAccept,
  postKnowledge,
} = require('secret-handshake2')
const pull = require('pull-stream')
const pullHandshake = require('pull-handshake')

/**
 * @typedef {Buffer | Uint8Array} B4A
 * @typedef {import('pull-stream').Source<B4A>} Source
 * @typedef {import('pull-stream').Sink<B4A>} Sink
 * @typedef {(key: B4A, nonce: B4A) => Source} CreateEncrypter
 * @typedef {(key: B4A, nonce: B4A) => Sink} CreateDecrypter
 */

/**
 * @param {{
 *   createEncrypter: CreateEncrypter
 *   createDecrypter: CreateDecrypter
 * }} protocolOptions
 */

module.exports = createHandshakeProtocol

function createHandshakeProtocol(protocolOptions) {
  const { createEncrypter, createDecrypter } = protocolOptions
  return {
    createInitiator,
    createResponder,
  }
}

/**
 * @param {{
 *   initiatorStaticSigningEd25519Key: B4A,
 *   initiatorStaticVerifyingEd25519Key: B4A,
 *   networkKey: B4A,
 *   timeout: number
 * }} initiatorOptions
 */
function createInitiator(protocolOptions, initiatorOptions) {
  const { createEncrypter, createDecrypter } = protocolOptions
  const {
    initiatorStaticSigningEd25519Key,
    initiatorStaticVerifyingEd25519Key,
    networkKey,
    timeout,
  } = options

  /**
   * @param {{
   *   responderStaticVerifyingEd25519Key: B4A,
   *   initiatorAuthPayload: B4A | null
   * }} initiatorOptions
   * @returns {Promise<{
   *   responderStaticVerifyingEd25519Key: B4A,
   *   source: import('pull-stream').Source<B4A>,
   *   sink: import('pull-stream').Sink<B4A>,
   * }>}
   */
  return function initiateHandshake(protocolOptions, initiateOptions) {
    const { createEncrypter, createDecrypter } = protocolOptions
    const { responderStaticVerifyingEd25519Key, initiatorAuthPayload } = initiateOptions

    const [initiatorHelloState, initiatorHelloMsg] = initiatorHello({
      initiatorStaticSigningEd25519Key,
      initiatorStaticVerifyingEd25519Key,
      responderStaticVerifyingEd25519Key,
      initiatorAuthPayload,
    })
  }
}

function createResponder() {}
