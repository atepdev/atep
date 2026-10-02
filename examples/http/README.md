# ATEP as an HTTP body

`http.mjs` serves envelope bytes at `GET /envelope` with `Content-Type: application/atep+cbor` and fetches them back (refusing any other media type). There is no ATEP specific framing: the body is the envelope. `http.test.mjs` asserts the media type, equal SHA-256 and successful verification. `postEnvelope` is provided for the reverse direction.

`node --test http/http.test.mjs`. The cross-carrier script is in `../transport/`.
