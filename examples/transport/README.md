# Same bytes on every carrier

`same-bytes.mjs` creates one request envelope, then: verifies it directly; writes it to a file and reads it back; serves it over HTTP (`application/atep+cbor`) and fetches it; delivers it as an MCP tool argument (spawned stdio server); delivers it in an A2A `message/send` data part. The test asserts:

* the SHA-256 of the bytes is identical at every hop (for MCP and A2A the receiver hashes the bytes it decoded and reports it in its signed reply);
* verification is identical everywhere: same signer, same nonce, same verified claims, same payload text hash;
* hostile payload text caused no side effects.

Each hop uses a fresh replay set, otherwise replay protection (step 6) would correctly reject the second delivery of the same envelope.

```
node --test transport/same-bytes.test.mjs
node transport/demo.mjs
```
