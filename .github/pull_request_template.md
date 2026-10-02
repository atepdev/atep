## What and why

## Checklist

- [ ] Vectors are unchanged, or the spec change that requires a vector change is linked (never edit a vector to make a test pass)
- [ ] Rust, JS and Python still agree if `rust/atep-core` changed (`cargo test`, `npm test` in `js/`, `python -m unittest` in `python/`)
- [ ] No em dashes in any file (`scripts/ci/no-em-dashes.sh`)
- [ ] No chain, token or wallet dependency added to core or clients
- [ ] Claims in docs are honest (nothing described as published, audited or deployed unless it is)
- [ ] `python/` was not informed by reading `rust/` (independent implementation)
