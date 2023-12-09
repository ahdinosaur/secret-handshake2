export type B4A = Buffer | Uint8Array

export type InitiatorPreKnowledgeState = {
  networkKey: B4A,
  initiatorStaticSigningEd25519Key: B4A,
  initiatorStaticVerifyingEd25519Key: B4A,
  responderStaticVerifyingEd25519Key: B4A,
  initiatorAuthenticationPayload: B4A | null
}

export type InitiatorHelloState = InitiatorPreKnowledgeState & {
  initiatorEphemeralSecretX25519Key: B4A,
  initiatorEphemeralPublicX25519Key: B4A,
}

export type ResponderPreKnowledgeState = {
  networkKey: B4A,
  responderStaticSigningEd25519Key: B4A,
  responderStaticVerifyingEd25519Key: B4A,
}

export type ResponderAcknowledgeState = ResponderPreKnowledgeState & {
  initiatorEphemeralPublicX25519Key: B4A,
}

export type ResponderHelloState = ResponderAcknowledgeState & {
  responderEphemeralSecretX25519Key: B4A,
  responderEphemeralPublicX25519Key: B4A,
  sharedSecretInitiatorEphemeralResponderEphemeral: B4A
}

export type InitiatorAcknowledgeState = InitiatorHelloState & {
  responderEphemeralPublicX25519Key: B4A,
  sharedSecretInitiatorEphemeralResponderEphemeral: B4A
}

export type InitiatorAuthenticateState = InitiatorAcknowledgeState & {
  handshakeId: B4A
  sharedSecretInitiatorEphemeralResponderStatic: B4A
}

export type ResponderAcceptState = ResponderAcknowledgeState & {
  handshakeId: B4A
  sharedSecretInitiatorEphemeralResponderStatic: B4A
  initiatorStaticVerifyingEd25519Key: B4A
  initiatorAuthenticationPayload: B4A | null
}

export type ResponderAuthenticateState = ResponderAcceptState & {
  sharedSecretInitiatorStaticResponderEphemeral: B4A
}

export type InitiatorAcceptState = InitiatorAuthenticateState & {
  sharedSecretInitiatorStaticResponderEphemeral: B4A
}

export type PostKnowledgeState = {
  networkKey: B4A,
  initiatorStaticVerifyingEd25519Key: B4A,
  responderStaticVerifyingEd25519Key: B4A,
  initiatorAuthenticationPayload: B4A | null
  initiatorToResponderKey: B4A
  initiatorToResponderNonce: B4A
  responderToInitiatorKey: B4A
  responderToInitiatorNonce: B4A
}
