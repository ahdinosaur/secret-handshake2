const {
  INITIATOR_HELLO_LENGTH,
  RESPONDER_HELLO_LENGTH,
  INITIATOR_AUTHENTICATE_CIPHERTEXT_LENGTH,
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
 * @typedef {import('pull-stream').Through<B4A, B4A>} Through
 * @typedef {import('pull-stream').Duplex<B4A, B4A>} Duplex
 * @typedef {(key: B4A, nonce: B4A) => Through} CreateEncrypterStream
 * @typedef {(key: B4A, nonce: B4A) => Through} CreateDecrypterStream
 * @typedef {{
 *   createEncrypterStream: CreateEncrypterStream
 *   createDecrypterStream: CreateDecrypterStream
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
  const { createEncrypterStream, createDecrypterStream } = protocolOptions
  const {
    networkKey,
    initiatorStaticSigningEd25519Key,
    initiatorStaticVerifyingEd25519Key,
    timeout,
  } = initiatorOptions

  /**
   * @param {{
   *   responderStaticVerifyingEd25519Key: B4A,
   *   initiatorAuthPayload: B4A | null,
   * }} initiateOptions
   * @returns {{
   *   stream: Duplex,
   *   application: Promise<{
   *     stream: Duplex
   *     encryptKey: B4A,
   *     encryptNonce: B4A,
   *     decryptKey: B4A,
   *     decryptNonce: B4A,
   *   }>
   * }}
   */
  return function initiateHandshake(initiateOptions) {
    const { responderStaticVerifyingEd25519Key, initiatorAuthPayload } = initiateOptions

    /** @type {undefined | ((err: Error | null) => void)} */
    let applicationReject
    const { handshake, source, sink } = pullHandshake({ timeout }, (err) => {
      applicationReject?.(err)
    })
    const stream = { source, sink }

    const application = new Promise((resolve, reject) => {
      applicationReject = reject

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
          return abort(
            err,
            'Initiator: Error when expecting responder to reply with hello message.',
          )
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
                'Initiator: Error when expecting responder to reply with authenticate message.',
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

            const restStream = handshake.rest()

            const encryptKey = postKnowledgeState.initiatorToResponderKey
            const encryptNonce = postKnowledgeState.initiatorToResponderNonce
            const encrypterStream = createEncrypterStream(encryptKey, encryptNonce)
            const decryptKey = postKnowledgeState.responderToInitiatorKey
            const decryptNonce = postKnowledgeState.responderToInitiatorNonce
            const decrypterStream = createDecrypterStream(decryptKey, decryptNonce)

            resolve({
              stream: {
                source: pull(restStream.source, decrypterStream),
                sink: pull(encrypterStream, restStream.sink),
              },
              encryptKey,
              encryptNonce,
              decryptKey,
              decryptNonce,
            })
          },
        )
      })
    })

    return {
      stream,
      application,
    }
  }
}

/**
 * @template Authorization
 * @param {ProtocolOptions} protocolOptions
 * @param {{
 *   responderStaticSigningEd25519Key: B4A,
 *   responderStaticVerifyingEd25519Key: B4A,
 *   authorize: (
 *     initiatorStaticVerifyingEd25519Key: B4A,
 *     initiatorAuthPlayload: B4A | null
 *   ) => Promise<Authorization | false>
 *   networkKey: B4A,
 *   timeout: number
 * }} responderOptions
 */
function createResponder(protocolOptions, responderOptions) {
  const { createEncrypterStream, createDecrypterStream } = protocolOptions
  const {
    responderStaticSigningEd25519Key,
    responderStaticVerifyingEd25519Key,
    authorize,
    networkKey,
    timeout,
  } = responderOptions

  /**
   * @returns {{
   *   stream: Duplex,
   *   application: Promise<{
   *     stream: Duplex
   *     initiatorStaticVerifyingEd25519Key: B4A,
   *     authorization: Authorization
   *     encryptKey: B4A,
   *     encryptNonce: B4A,
   *     decryptKey: B4A,
   *     decryptNonce: B4A,
   *   }>
   * }}
   */
  return function respondHandshake() {
    /** @type {undefined | ((err: Error | null) => void)} */
    let applicationReject
    const { handshake, source, sink } = pullHandshake({ timeout }, (err) => {
      applicationReject?.(err)
    })
    const stream = { source, sink }

    const application = new Promise((resolve, reject) => {
      applicationReject = reject

      const abort = createAbort(handshake.abort)

      handshake.read(INITIATOR_HELLO_LENGTH, (err, initiatorHelloMsg) => {
        if (err) {
          return abort(err, 'Responder: Error when expecting initiator to send hello message.')
        }

        try {
          var responderAcknowledgeState = responderAcknowledge(
            {
              networkKey,
              responderStaticSigningEd25519Key,
              responderStaticVerifyingEd25519Key,
            },
            initiatorHelloMsg,
          )
        } catch (err) {
          // @ts-ignore
          return abort(err, 'Responder: Failed to acknowledge initiator hello message.')
        }

        try {
          var [responderHelloState, responderHelloMsg] = responderHello(responderAcknowledgeState)
        } catch (err) {
          // @ts-ignore
          return abort(err, 'Responder: Failed to create hello message.')
        }

        handshake.write(responderHelloMsg)

        handshake.read(
          INITIATOR_AUTHENTICATE_CIPHERTEXT_LENGTH,
          (err, initiatorAuthenticateMsg) => {
            if (err) {
              return abort(
                err,
                'Responder: Error when expecting initiator to send authenticate message.',
              )
            }

            try {
              var responderAcceptState = responderAccept(
                responderHelloState,
                initiatorAuthenticateMsg,
              )
            } catch (err) {
              // @ts-ignore
              return abort(err, 'Responder: Failed to accept initiator authenticate message.')
            }

            const { initiatorStaticVerifyingEd25519Key, initiatorAuthPayload } =
              responderAcceptState
            authorize(initiatorStaticVerifyingEd25519Key, initiatorAuthPayload)
              .then((authorization) => {
                if (authorization === false) {
                  return abort(null, 'Responder: Unauthorized initiator.')
                }

                try {
                  var [responderAuthenticateState, responderAuthenticateMsg] =
                    responderAuthenticate(responderAcceptState)
                } catch (err) {
                  // @ts-ignore
                  return abort(err, 'Responder: Failed to create authenticate message.')
                }

                handshake.write(responderAuthenticateMsg)

                try {
                  var postKnowledgeState = postKnowledge(responderAuthenticateState)
                } catch (err) {
                  // @ts-ignore
                  return abort(err, 'Responder: Failed to create post-handshake knowledge.')
                }

                const restStream = handshake.rest()

                const encryptKey = postKnowledgeState.responderToInitiatorKey
                const encryptNonce = postKnowledgeState.responderToInitiatorNonce
                const encrypterStream = createEncrypterStream(encryptKey, encryptNonce)
                const decryptKey = postKnowledgeState.initiatorToResponderKey
                const decryptNonce = postKnowledgeState.initiatorToResponderNonce
                const decrypterStream = createDecrypterStream(decryptKey, decryptNonce)

                resolve({
                  stream: {
                    source: pull(restStream.source, decrypterStream),
                    sink: pull(encrypterStream, restStream.sink),
                  },
                  authorization,
                  initiatorStaticVerifyingEd25519Key,
                  encryptKey,
                  encryptNonce,
                  decryptKey,
                  decryptNonce,
                })
              })
              .catch((err) => {
                return abort(err, 'Responder: Failed to authorize initiator authenticate message.')
              })
          },
        )
      })
    })

    return {
      stream,
      application,
    }
  }
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
