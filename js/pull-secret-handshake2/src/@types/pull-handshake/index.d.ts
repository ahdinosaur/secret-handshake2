declare module 'pull-handshake' {
  import { Sink, Source } from 'pull-stream'

  type B4A = Buffer | Uint8Array

  type Handshake = {
    write: (buf: B4A) => void
    read: (len: number, cb: (error: Error | null, data: B4A) => void) => void
    abort: (err: Error) => void
    rest: () => any
  }

  type CreateHandshakeOptions = {
    timeout: number | undefined
  }
  type CreateHandshakeReturn = {
    handshake: Handshake
    sink: Sink<B4A>
    source: Source<B4A>
  }

  function createHandshake(
    options?: CreateHandshakeOptions,
    cb?: (err: Error | null) => void,
  ): CreateHandshakeReturn

  export = createHandshake
}
