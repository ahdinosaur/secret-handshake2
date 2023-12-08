const b4a = require('b4a')

/**
 * @typedef {import('./types').B4A} B4A
 * @typedef {import('./crypto')} SecretHandshakeCrypto
 */

module.exports = protocol

/**
 * @param {SecretHandshakeCrypto} crypto
 */
function protocol(crypto) {
  return {
    initiatorHello: initiatorHello.bind(null, crypto),
  }
}

/**
 * @typedef {{
 *   networkKey: B4A,
 *   initiatorStaticSecretEd25519Key: B4A,
 *   initiatorStaticPublicEd25519Key: B4A,
 *   responderStaticPublicEd25519Key: B4A,
 * }} InitiatorPreKnowledge
 */

/**
 * @typedef {InitiatorPreKnowledge & {
 *   initiatorEphemeralSecretX25519Key: B4A,
 *   initiatorEphemeralPublicX25519Key: B4A,
 * }} InitiatorHelloState
 */

/**
 * @param {SecretHandshakeCrypto} crypto
 * @param {InitiatorPreKnowledge} prevState
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

  const msg = b4a.concat([
    initiatorEphemeralPublicX25519Key,
    crypto.auth(
      networkKey,
      initiatorEphemeralPublicX25519Key,
    )
  ])

  return { state, msg }
}


/**
 * @typedef {{
 *   networkKey: B4A,
 *   responderStaticSecretEd25519Key: B4A,
 *   responderStaticPublicEd25519Key: B4A,
 * }} ResponderPreKnowledge
 */

/**
 * @typedef {ResponderPreKnowledge & {
 *   initiatorEphemeralPublicX25519Key: B4A,
 * }} ResponderAcknowledgeState
 */

/**
 * @param {SecretHandshakeCrypto} crypto
 * @param {ResponderPreKnowledge} prevState
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

  const isAuthentic = crypto.authVerify(
    networkKey,
    initiatorEphemeralPublicX25519Key,
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
 * @typedef {ResponderAcknowledgeState & {
 *   responderEphemeralSecretX25519Key: B4A,
 *   responderEphemeralPublicX25519Key: B4A,
 *   sharedSecretInitiatorEphemeralResponderEphemeral: B4A
 * }} ResponderHelloState
 */

/**
 * @param {SecretHandshakeCrypto} crypto
 * @param {ResponderAcknowledgeState} prevState
 * @returns {{
 *   state: ResponderHelloState
 *   msg: B4A
 * }}
 */
function responderHello(crypto, prevState) {
  const { initiatorEphemeralPublicX25519Key } = prevState

  const {
    secretKey: responderEphemeralSecretX25519Key,
    publicKey: responderEphemeralPublicX25519Key,
  } = crypto.generateX25519Keypair()

  const sharedSecretInitiatorEphemeralResponderEphemeral = crypto.diffieHellman(
    responderEphemeralSecretX25519Key,
    initiatorEphemeralPublicX25519Key,
  )

  return { state, msg }
}
