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

  const initiatorHelloMsgKey = networkKey
  const initiatorHelloMsg = b4a.concat([
    initiatorEphemeralPublicX25519Key,
    crypto.auth(initiatorEphemeralPublicX25519Key, initiatorHelloMsgKey),
  ])

  return {
    state: {
      ...prevState,
      initiatorEphemeralSecretX25519Key,
      initiatorEphemeralPublicX25519Key,
    },
    msg: initiatorHelloMsg,
  }
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

  return {
    ...prevState,
    initiatorEphemeralPublicX25519Key,
  }
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

  const responderHelloMsgKey = crypto.hash(
    b4a.concat([networkKey, sharedSecretInitiatorEphemeralResponderEphemeral]),
  )
  const responderHelloMsg = b4a.concat([
    responderEphemeralPublicX25519Key,
    crypto.auth(responderEphemeralPublicX25519Key, responderHelloMsgKey),
  ])

  return {
    state: {
      ...prevState,
      responderEphemeralSecretX25519Key,
      responderEphemeralPublicX25519Key,
      sharedSecretInitiatorEphemeralResponderEphemeral,
    },
    msg: responderHelloMsg,
  }
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

/**
 * @param {SecretHandshakeCrypto} crypto
 * @param {InitiatorAcknowledgeState} prevState
 * @returns {{
 *   state: InitiatorAuthenticateState,
 *   msg: B4A,
 * }}
 */
function initiatorAuthenticate(crypto, prevState) {
  const {
    sharedSecretInitiatorEphemeralResponderEphemeral,
    initiatorEphemeralPublicX25519Key,
    responderEphemeralPublicX25519Key,
    networkKey,
    responderStaticVerifyingEd25519Key,
    initiatorStaticSigningEd25519Key,
    initiatorStaticVerifyingEd25519Key,
    initiatorAuthenticationPayload,
    initiatorEphemeralSecretX25519Key,
  } = prevState

  const handshakeId = crypto.hash(
    b4a.concat([
      sharedSecretInitiatorEphemeralResponderEphemeral,
      initiatorEphemeralPublicX25519Key,
      responderEphemeralPublicX25519Key,
    ]),
  )

  const initiatorAuthProof = b4a.concat([
    networkKey,
    responderStaticVerifyingEd25519Key,
    handshakeId,
  ])

  const initiatorAuthProofSig = crypto.sign(initiatorStaticSigningEd25519Key, initiatorAuthProof)

  const initiatorAuthMsgPlaintext = b4a.concat([
    initiatorAuthProofSig,
    initiatorStaticVerifyingEd25519Key,
    initiatorAuthenticationPayload ?? b4a.alloc(32, 0),
  ])

  const responderStaticPublicX25519Key = crypto.convertVerifyingEd25519ToPublicX25519(
    responderStaticVerifyingEd25519Key,
  )
  if (responderStaticPublicX25519Key == null) {
    throw new Error(
      'InitiatorAuthenticate: Responder static verifying ed25519 key failed to convert to public x25519 key',
    )
  }
  const sharedSecretInitiatorEphemeralResponderStatic = crypto.diffieHellman(
    initiatorEphemeralSecretX25519Key,
    responderStaticPublicX25519Key,
  )

  const initiatorAuthMsgKey = crypto.hash(
    b4a.concat([
      networkKey,
      sharedSecretInitiatorEphemeralResponderEphemeral,
      sharedSecretInitiatorEphemeralResponderStatic,
      initiatorEphemeralPublicX25519Key,
      responderEphemeralPublicX25519Key,
    ]),
  )

  const initiatorAuthMsgCiphertext = crypto.encrypt(
    initiatorAuthMsgKey,
    b4a.alloc(24, 0),
    initiatorAuthMsgPlaintext,
  )

  return {
    state: {
      ...prevState,
      handshakeId,
      sharedSecretInitiatorEphemeralResponderStatic,
    },
    msg: initiatorAuthMsgCiphertext,
  }
}

/**
 * @param {SecretHandshakeCrypto} crypto
 * @param {ResponderHelloState} prevState
 * @param {B4A} initiatorAuthMsgCiphertext
 * @returns ResponderAcceptState
 */
function responderAccept(crypto, prevState, initiatorAuthMsgCiphertext) {
  if (initiatorAuthMsgCiphertext.length !== 144) {
    throw new Error('ResponderAccept: InitaitorAuthenticateMsgCiphertext.length !== 144 bytes')
  }

  const {
    responderStaticSigningEd25519Key,
    networkKey,
    sharedSecretInitiatorEphemeralResponderEphemeral,
    initiatorEphemeralPublicX25519Key,
    responderEphemeralPublicX25519Key,
    responderStaticVerifyingEd25519Key,
  } = prevState

  const responderStaticSecretX25519Key = crypto.convertSigningEd25519ToSecretX25519(
    responderStaticSigningEd25519Key,
  )
  if (responderStaticSecretX25519Key == null) {
    throw new Error(
      'ResponderAccept: Responder static signing ed25519 key failed to convert to secret x25519 key',
    )
  }
  const sharedSecretInitiatorEphemeralResponderStatic = crypto.diffieHellman(
    responderStaticSecretX25519Key,
    initiatorEphemeralPublicX25519Key,
  )

  const initiatorAuthMsgKey = crypto.hash(
    b4a.concat([
      networkKey,
      sharedSecretInitiatorEphemeralResponderEphemeral,
      sharedSecretInitiatorEphemeralResponderStatic,
      initiatorEphemeralPublicX25519Key,
      responderEphemeralPublicX25519Key,
    ]),
  )

  const initiatorAuthMsgPlaintext = crypto.decrypt(
    initiatorAuthMsgKey,
    b4a.alloc(24, 0),
    initiatorAuthMsgCiphertext,
  )
  if (initiatorAuthMsgPlaintext == null) {
    throw new Error('ResponderAccept: InitiatorAuthMsg failed to decrypt')
  }
  if (initiatorAuthMsgPlaintext.length !== 128) {
    throw new Error('ResponderAccept: InitaitorAuthenticateMsgPlaintext.length !== 128 bytes')
  }

  const initiatorAuthProofSig = initiatorAuthMsgPlaintext.subarray(0, 64)
  const initiatorStaticVerifyingEd25519Key = initiatorAuthMsgPlaintext.subarray(64, 96)
  const initiatorAuthenticationPayload = initiatorAuthMsgPlaintext.subarray(96, 128)

  const handshakeId = crypto.hash(
    b4a.concat([
      sharedSecretInitiatorEphemeralResponderEphemeral,
      initiatorEphemeralPublicX25519Key,
      responderEphemeralPublicX25519Key,
    ]),
  )

  const initiatorAuthProof = b4a.concat([
    networkKey,
    responderStaticVerifyingEd25519Key,
    handshakeId,
  ])

  const isValidSignature = crypto.signVerify(
    responderStaticVerifyingEd25519Key,
    initiatorAuthProof,
    initiatorAuthProofSig,
  )
  if (!isValidSignature) {
    throw new Error('ResponderAccept: InitiatorAUthMsg signature is invalid')
  }

  return {
    ...prevState,
    sharedSecretInitiatorEphemeralResponderStatic,
    handshakeId,
    initiatorStaticVerifyingEd25519Key,
    initiatorAuthenticationPayload,
  }
}
