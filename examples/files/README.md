# ATEP as a file

An envelope is a byte string, so a file holding exactly those bytes is a valid carrier (suggested extension `.atep`; a convention of these examples, not a registered one). `files.mjs` is two functions, `writeEnvelopeFile` and `readEnvelopeFile`. `files.test.mjs` writes a sign-then-encrypt envelope, reads it back, asserts equal SHA-256 and verifies it with a trust policy.

`node --test files/files.test.mjs`. The cross-carrier script is in `../transport/`.
