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
 * @typedef {import('pull-stream').Through<B4A>} Through
 * @typedef {import('pull-stream').Duplex<B4A, B4A>} Duplex
 * @typedef {(key: B4A, nonce: B4A) => Through} CreateEncrypter
 * @typedef {(key: B4A, nonce: B4A) => Through} CreateDecrypter
 * @typedef {{
 *   createEncrypter: CreateEncrypter
 *   createDecrypter: CreateDecrypter
 * }} ProtocolOptions
 */

module.exports = createHandshakeProtocol

/**
 * @param {ProtocolOptions} protocolOptions
 */
function createHandshakeProtocol(protocolOptions) {
  return {
    createInitiator: createInitiator.bind(null, protocolOptions),
    createResponder: createResponder.bind(null, protocolOptions),
  }
}

/**
 * @param {ProtocolOptions} protocolOptions
 * @param {{
 *   networkKey: B4A,
 *   initiatorStaticSigningEd25519Key: B4A,
 *   initiatorStaticVerifyingEd25519Key: B4A,
 *   timeout?: number
 * }} initiatorOptions
 */
function createInitiator(protocolOptions, initiatorOptions) {
  const { createEncrypter, createDecrypter } = protocolOptions
  const {
    networkKey,
    initiatorStaticSigningEd25519Key,
    initiatorStaticVerifyingEd25519Key,
    timeout,
  } = initiatorOptions

  /**
   * @param {{
   *   responderStaticVerifyingEd25519Key: B4A,
   *   initiatorAuthPayload: B4A | null
   * }} initiateOptions
   * @returns {Promise<{
   *   stream: Duplex
   * }>}
   */
  return function initiateHandshake(initiateOptions) {
    const { responderStaticVerifyingEd25519Key, initiatorAuthPayload } = initiateOptions

    return new Promise((resolve, reject) => {
      const { handshake, source, sink } = pullHandshake({ timeout }, reject)
      const stream = { source, sink }

      const abort = createAbort(handshake.abort)

      try {
        var [initiatorHelloState, initiatorHelloMsg] = initiatorHello({
          networkKey,
          initiatorStaticSigningEd25519Key,
          initiatorStaticVerifyingEd25519Key,
          responderStaticVerifyingEd25519Key,
          initiatorAuthPayload,
        })
      } catch (err) {
        // @ts-ignore
        return abort(err, 'Initiator: Failed to create hello message.')
      }

      handshake.write(initiatorHelloMsg)

      handshake.read(RESPONDER_HELLO_LENGTH, (err, responderHelloMsg) => {
        if (err) {
          return abort(err, 'Initiator: Error when expecting responder to reply with hello.')
        }

        try {
          var initiatorAcknowledgeState = initiatorAcknowledge(
            initiatorHelloState,
            responderHelloMsg,
          )
        } catch (err) {
          // @ts-ignore
          return abort(err, 'Initiator: Failed to acknowledge responder hello message.')
        }

        try {
          var [initiatorAuthenticateState, initiatorAuthenticateMsg] =
            initiatorAuthenticate(initiatorAcknowledgeState)
        } catch (err) {
          // @ts-ignore
          return abort(err, 'Initiator: Failed to create authenticate message.')
        }

        handshake.write(initiatorAuthenticateMsg)

        handshake.read(
          RESPONDER_AUTHENTICATE_CIPHERTEXT_LENGTH,
          (err, responderAuthenticateMsg) => {
            if (err) {
              return abort(
                err,
                'Initiator: Error when expecting responder to reply with authenticate.',
              )
            }

            try {
              var initiatorAcceptState = initiatorAccept(
                initiatorAuthenticateState,
                responderAuthenticateMsg,
              )
            } catch (err) {
              // @ts-ignore
              return abort(err, 'Initiator: Failed to accept responder authenticate message.')
            }

            try {
              var postKnowledgeState = postKnowledge(initiatorAcceptState)
            } catch (err) {
              // @ts-ignore
              return abort(err, 'Initiator: Failed to create post-handshake knowledge.')
            }

            const encryptKey = postKnowledgeState.initiatorToResponderKey
            const encryptNonce = postKnowledgeState.initiatorToResponderNonce
            const encrypter = createEncrypter(encryptKey, encryptNonce)
            const decryptKey = postKnowledgeState.responderToInitiatorKey
            const decryptNonce = postKnowledgeState.responderToInitiatorNonce
            const decrypter = createDecrypter(decryptKey, decryptNonce)

            resolve({
              stream: {
                source: pull(stream.source, decrypter),
                sink: pull(encrypter, stream.sink),
              },
            })
          },
        )
      })
    })
  }
}

/**
 * @param {ProtocolOptions} protocolOptions
 * @param {{
 *   responderStaticSigningEd25519Key: B4A,
 *   responderStaticVerifyingEd25519Key: B4A,
 *   networkKey: B4A,
 *   timeout: number
 * }} responderOptions
 */
function createResponder(protocolOptions, responderOptions) {
  const { createEncrypter, createDecrypter } = protocolOptions
  const { responderStaticVerifyingEd25519Key, initiatorAuthPayload } = responderOptions

  /**
   * @returns {Promise<{
   *   initiatorStaticVerifyingEd25519Key: B4A,
   *   stream: Duplex
   * }>}
   */
  return function respondHandshake() {}
}

/**
 * @param {(err: Error) => void} onAbort
 */
function createAbort(onAbort) {
  /**
   * @param {Error | true | null} err
   * @param {string} reason
   */
  return function abort(err, reason) {
    if (err && err !== true) {
      onAbort(new Error(reason, { cause: err.message ?? err }))
    } else {
      onAbort(new Error(reason))
    }
  }
}
