declare module 'pull-handshake' {
  type B4A = Buffer | Uint8Array
  type Shake = {
    write: (buf: B4A) => void
    read: (len: number, cb: (error: Error | null, data?: B4A) => void) => void
    abort: (err: Error) => void
    rest: () => any
  }
  type HandshakeOptions = {
    timeout: number
  }
  type CreateHandshake = (options: HandshakeOptions) => Shake
  export = CreateHandshake
}
