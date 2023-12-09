const b4a = require('b4a')

/**
 * @typedef {import('./types').B4A} B4A
 * @typedef {import('./types').InitiatorPreKnowledgeState} InitiatorPreKnowledgeState
 * @typedef {import('./types').InitiatorHelloState} InitiatorHelloState
 * @typedef {import('./types').ResponderPreKnowledgeState} ResponderPreKnowledgeState
 * @typedef {import('./types').ResponderAcknowledgeState} ResponderAcknowledgeState
 * @typedef {import('./types').ResponderHelloState} ResponderHelloState
 * @typedef {import('./types').InitiatorAcknowledgeState} InitiatorAcknowledgeState
 * @typedef {import('./types').InitiatorAuthenticateState} InitiatorAuthenticateState
 * @typedef {import('./types').ResponderAcceptState} ResponderAcceptState
 * @typedef {import('./types').ResponderAuthenticateState} ResponderAuthenticateState
 * @typedef {import('./types').InitiatorAcceptState} InitiatorAcceptState
 * @typedef {import('./types').PostKnowledgeState} PostKnowledgeState
 *
 * @typedef {import('./crypto')} SecretHandshakeCrypto
 */

module.exports = protocol

/**
 * @param {SecretHandshakeCrypto} crypto
 */
function protocol(crypto) {
  return {
    initiatorHello: initiatorHello.bind(null, crypto),
    responderAcknowledge: responderAcknowledge.bind(null, crypto),
    responderHello: responderHello.bind(null, crypto),
    initiatorAcknowledge: initiatorAcknowledge.bind(null, crypto),
    initiatorAuthenticate: initiatorAuthenticate.bind(null, crypto),
    responderAccept: responderAccept.bind(null, crypto),
    responderAuthenticate: responderAuthenticate.bind(null, crypto),
    initiatorAccept: initiatorAccept.bind(null, crypto),
  }
}

/**
 * @param {SecretHandshakeCrypto} crypto
 * @param {InitiatorPreKnowledgeState} prevState
 * @returns {{
 *   state: InitiatorHelloState
 *   msg: B4A,
 * }}
 */
function initiatorHello(crypto, prevState) {
  const { networkKey } = prevState

  const {
    secretKey: initiatorEphemeralSecretX25519Key,
    publicKey: initiatorEphemeralPublicX25519Key,
  } = crypto.generateX25519Keypair()

  const state = {
    ...prevState,
    initiatorEphemeralSecretX25519Key,
    initiatorEphemeralPublicX25519Key,
  }

  const initiatorHelloMsgKey = networkKey
  const msg = b4a.concat([
    initiatorEphemeralPublicX25519Key,
    crypto.auth(initiatorEphemeralPublicX25519Key, initiatorHelloMsgKey),
  ])

  return { state, msg }
}

/**
 * @param {SecretHandshakeCrypto} crypto
 * @param {ResponderPreKnowledgeState} prevState
 * @param {B4A} initiatorHelloMsg
 * @returns ResponderAcknowledgeState
 */
function responderAcknowledge(crypto, prevState, initiatorHelloMsg) {
  if (initiatorHelloMsg.length !== 64) {
    throw new Error('ResponderAcknowledge: InitiatorHelloMsg.length !== 64 bytes')
  }

  const initiatorEphemeralPublicX25519Key = initiatorHelloMsg.subarray(0, 32)
  const initiatorHelloMsgAuthTag = initiatorHelloMsg.subarray(32, 64)

  const { networkKey } = prevState

  const initiatorHelloMsgKey = networkKey
  const isAuthentic = crypto.authVerify(
    initiatorEphemeralPublicX25519Key,
    initiatorHelloMsgKey,
    initiatorHelloMsgAuthTag,
  )

  if (!isAuthentic) {
    throw new Error('ResponderAcknowledge: InitiatorHelloMsg auth tag is invalid')
  }

  const state = {
    ...prevState,
    initiatorEphemeralPublicX25519Key,
  }

  return state
}

/**
 * @param {SecretHandshakeCrypto} crypto
 * @param {ResponderAcknowledgeState} prevState
 * @returns {{
 *   state: ResponderHelloState
 *   msg: B4A
 * }}
 */
function responderHello(crypto, prevState) {
  const { networkKey, initiatorEphemeralPublicX25519Key } = prevState

  const {
    secretKey: responderEphemeralSecretX25519Key,
    publicKey: responderEphemeralPublicX25519Key,
  } = crypto.generateX25519Keypair()

  const sharedSecretInitiatorEphemeralResponderEphemeral = crypto.diffieHellman(
    responderEphemeralSecretX25519Key,
    initiatorEphemeralPublicX25519Key,
  )

  const state = {
    ...prevState,
    responderEphemeralSecretX25519Key,
    responderEphemeralPublicX25519Key,
    sharedSecretInitiatorEphemeralResponderEphemeral,
  }

  const responderHelloMsgKey = crypto.hash(
    b4a.concat([networkKey, sharedSecretInitiatorEphemeralResponderEphemeral]),
  )
  const msg = b4a.concat([
    responderEphemeralPublicX25519Key,
    crypto.auth(responderEphemeralPublicX25519Key, responderHelloMsgKey),
  ])

  return { state, msg }
}

/**
 * @param {SecretHandshakeCrypto} crypto
 * @param {InitiatorHelloState} prevState
 * @param {B4A} responderHelloMsg
 * @returns InitiatorAcknowledgeState
 */
function initiatorAcknowledge(crypto, prevState, responderHelloMsg) {
  if (responderHelloMsg.length !== 64) {
    throw new Error('InitiatorAcknowledge: ResponderHelloMsg.length !== 64 bytes')
  }

  const responderEphemeralPublicX25519Key = responderHelloMsg.subarray(0, 32)
  const responderHelloMsgAuthTag = responderHelloMsg.subarray(32, 64)

  const { networkKey, initiatorEphemeralSecretX25519Key } = prevState

  const sharedSecretInitiatorEphemeralResponderEphemeral = crypto.diffieHellman(
    initiatorEphemeralSecretX25519Key,
    responderEphemeralPublicX25519Key,
  )

  const responderHelloMsgKey = crypto.hash(
    b4a.concat([networkKey, sharedSecretInitiatorEphemeralResponderEphemeral]),
  )

  const isAuthentic = crypto.authVerify(
    responderEphemeralPublicX25519Key,
    responderHelloMsgKey,
    responderHelloMsgAuthTag,
  )

  if (!isAuthentic) {
    throw new Error('InitiatorAcknowledge: ResponderHelloMsg auth tag is invalid')
  }

  const state = {
    ...prevState,
    responderEphemeralPublicX25519Key,
    sharedSecretInitiatorEphemeralResponderEphemeral,
  }

  return state
}
