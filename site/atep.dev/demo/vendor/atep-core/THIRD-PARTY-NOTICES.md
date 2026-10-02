# Third-party notices

ATEP itself is licensed under Apache-2.0 (see `LICENSE`); the specification is CC BY 4.0 (see `LICENSE-SPEC.md`). This file lists the third-party software that is statically linked into the artifacts this repository builds, as required by the licenses of that software. Where a crate offers a choice of licenses ("MIT OR Apache-2.0"), ATEP uses it under the MIT license, whose text and copyright notices are reproduced below. No dependency ships a NOTICE file, so the repository has no NOTICE file.

## Scope

* **Rust (compiled into the WebAssembly module and the `atep` CLI).** The crates below are the normal (non-dev, non-build) dependencies of `atep-wasm` (target `wasm32-unknown-unknown`) and `atep-cli` (target `x86_64-unknown-linux-gnu`), taken from `cargo metadata --locked --filter-platform <target>` over `rust/Cargo.lock`, without procedural-macro crates and their build-time dependencies (those run at compile time and are not part of the output). The `atep-logd` and `atep-monitor` programs are built from the same dependency set plus the standard library.
* **npm.** The npm package `@atep/core` bundles only the WebAssembly module built from the Rust crates above (plus ATEP's own JavaScript); it has no npm runtime dependencies, so its third-party notices are the Rust section of this file. The `@atep/mcp` package and the `examples/` have npm runtime dependencies, listed at the end.
* **Python.** `python/atep_py` uses only the Python standard library.
* This file was generated from the dependency metadata on 2026-10-02 and should be regenerated when `rust/Cargo.lock` changes.

## Rust crates

| Crate | Version | License (SPDX) | In wasm | In CLI |
| --- | --- | --- | --- | --- |
| aead | 0.6.1 | MIT OR Apache-2.0 | yes | yes |
| aes | 0.9.3 | MIT OR Apache-2.0 | yes | yes |
| aes-gcm | 0.11.1 | Apache-2.0 OR MIT | yes | yes |
| anstream | 1.0.0 | MIT OR Apache-2.0 | no | yes |
| anstyle | 1.0.14 | MIT OR Apache-2.0 | no | yes |
| anstyle-parse | 1.0.0 | MIT OR Apache-2.0 | no | yes |
| anstyle-query | 1.1.5 | MIT OR Apache-2.0 | no | yes |
| base32 | 1.0.0-rc.1 | MIT OR Apache-2.0 | yes | yes |
| base64 | 0.23.1 | MIT OR Apache-2.0 | yes | yes |
| base64ct | 1.8.3 | Apache-2.0 OR MIT | yes | yes |
| block-buffer | 0.12.1 | MIT OR Apache-2.0 | yes | yes |
| cfg-if | 1.0.5 | MIT OR Apache-2.0 | yes | yes |
| cipher | 0.5.2 | MIT OR Apache-2.0 | yes | yes |
| clap | 4.6.7 | MIT OR Apache-2.0 | no | yes |
| clap_builder | 4.6.7 | MIT OR Apache-2.0 | no | yes |
| clap_lex | 1.1.1 | MIT OR Apache-2.0 | no | yes |
| cmov | 0.5.4 | Apache-2.0 OR MIT | yes | yes |
| colorchoice | 1.0.5 | MIT OR Apache-2.0 | no | yes |
| const-oid | 0.10.2 | Apache-2.0 OR MIT | yes | yes |
| cpubits | 0.1.1 | MIT OR Apache-2.0 | yes | yes |
| cpufeatures | 0.3.1 | MIT OR Apache-2.0 | no | yes |
| crypto-common | 0.2.2 | MIT OR Apache-2.0 | yes | yes |
| ctr | 0.10.1 | MIT OR Apache-2.0 | yes | yes |
| ctutils | 0.4.2 | Apache-2.0 OR MIT | yes | yes |
| curve25519-dalek | 5.0.0 | BSD-3-Clause | yes | yes |
| der | 0.8.2 | Apache-2.0 OR MIT | yes | yes |
| digest | 0.11.3 | MIT OR Apache-2.0 | yes | yes |
| ed25519 | 3.0.0 | Apache-2.0 OR MIT | yes | yes |
| ed25519-dalek | 3.0.0 | BSD-3-Clause | yes | yes |
| equivalent | 1.0.2 | Apache-2.0 OR MIT | yes | yes |
| getrandom | 0.4.3 | MIT OR Apache-2.0 | yes | yes |
| ghash | 0.6.0 | Apache-2.0 OR MIT | yes | yes |
| hashbrown | 0.17.1 | MIT OR Apache-2.0 | yes | yes |
| hex | 0.4.3 | MIT OR Apache-2.0 | yes | yes |
| hkdf | 0.13.0 | MIT OR Apache-2.0 | yes | yes |
| hmac | 0.13.0 | MIT OR Apache-2.0 | yes | yes |
| hybrid-array | 0.4.15 | MIT OR Apache-2.0 | yes | yes |
| indexmap | 2.14.2 | Apache-2.0 OR MIT | yes | yes |
| inout | 0.2.2 | MIT OR Apache-2.0 | yes | yes |
| is_terminal_polyfill | 1.70.2 | MIT OR Apache-2.0 | no | yes |
| itoa | 1.0.18 | MIT OR Apache-2.0 | yes | yes |
| keccak | 0.2.2 | Apache-2.0 OR MIT | yes | yes |
| kem | 0.3.0 | Apache-2.0 OR MIT | yes | yes |
| libc | 0.2.189 | MIT OR Apache-2.0 | no | yes |
| memchr | 2.8.3 | Unlicense OR MIT | yes | yes |
| ml-dsa | 0.1.1 | Apache-2.0 OR MIT | yes | yes |
| ml-kem | 0.3.2 | Apache-2.0 OR MIT | yes | yes |
| module-lattice | 0.2.3 | Apache-2.0 OR MIT | yes | yes |
| num-traits | 0.2.19 | MIT OR Apache-2.0 | yes | yes |
| once_cell | 1.21.4 | MIT OR Apache-2.0 | yes | no |
| pkcs8 | 0.11.0 | Apache-2.0 OR MIT | yes | yes |
| polyval | 0.7.3 | Apache-2.0 OR MIT | yes | yes |
| rand_core | 0.10.1 | MIT OR Apache-2.0 | yes | yes |
| serde_core | 1.0.229 | MIT OR Apache-2.0 | yes | yes |
| serde_json | 1.0.151 | MIT OR Apache-2.0 | yes | yes |
| sha2 | 0.11.0 | MIT OR Apache-2.0 | yes | yes |
| sha3 | 0.11.0 | MIT OR Apache-2.0 | yes | yes |
| shake | 0.1.0 | MIT OR Apache-2.0 | yes | yes |
| signature | 3.0.0 | Apache-2.0 OR MIT | yes | yes |
| spki | 0.8.0 | Apache-2.0 OR MIT | yes | yes |
| sponge-cursor | 0.1.0 | MIT OR Apache-2.0 | yes | yes |
| strsim | 0.11.1 | MIT | no | yes |
| subtle | 2.6.1 | BSD-3-Clause | yes | yes |
| typenum | 1.20.1 | MIT OR Apache-2.0 | yes | yes |
| unicode-ident | 1.0.26 | (MIT OR Apache-2.0) AND Unicode-3.0 | yes | no |
| universal-hash | 0.6.1 | MIT OR Apache-2.0 | yes | yes |
| utf8parse | 0.2.2 | Apache-2.0 OR MIT | no | yes |
| wasm-bindgen | 0.2.129 | MIT OR Apache-2.0 | yes | no |
| wasm-bindgen-shared | 0.2.129 | MIT OR Apache-2.0 | yes | no |
| x25519-dalek | 3.0.0 | BSD-3-Clause | yes | yes |
| zeroize | 1.9.0 | Apache-2.0 OR MIT | yes | yes |
| zmij | 1.0.23 | MIT | yes | yes |

72 crates. License texts follow.

## BSD-3-Clause crates

The following four crates are in the wasm module and the CLI and are licensed under the 3-clause BSD license. Their copyright notices, conditions and disclaimers are reproduced as required for binary redistribution.

### curve25519-dalek 5.0.0

```text
Copyright (c) 2016-2021 isis agora lovecruft. All rights reserved.
Copyright (c) 2016-2021 Henry de Valence. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### ed25519-dalek 3.0.0

```text
Copyright (c) 2017-2019 isis agora lovecruft. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### subtle 2.6.1

```text
Copyright (c) 2016-2017 Isis Agora Lovecruft, Henry de Valence. All rights reserved.
Copyright (c) 2016-2024 Isis Agora Lovecruft. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### x25519-dalek 3.0.0

```text
Copyright (c) 2017-2021 isis agora lovecruft. All rights reserved.
Copyright (c) 2019-2021 DebugSteven. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## Unicode license (unicode-ident 1.0.26)

The `unicode-ident` crate is licensed "(MIT OR Apache-2.0) AND Unicode-3.0". It appears in the wasm dependency graph; the Unicode data license is reproduced here for completeness.

```text
UNICODE LICENSE V3

COPYRIGHT AND PERMISSION NOTICE

Copyright © 1991-2023 Unicode, Inc.

NOTICE TO USER: Carefully read the following legal agreement. BY
DOWNLOADING, INSTALLING, COPYING OR OTHERWISE USING DATA FILES, AND/OR
SOFTWARE, YOU UNEQUIVOCALLY ACCEPT, AND AGREE TO BE BOUND BY, ALL OF THE
TERMS AND CONDITIONS OF THIS AGREEMENT. IF YOU DO NOT AGREE, DO NOT
DOWNLOAD, INSTALL, COPY, DISTRIBUTE OR USE THE DATA FILES OR SOFTWARE.

Permission is hereby granted, free of charge, to any person obtaining a
copy of data files and any associated documentation (the "Data Files") or
software and any associated documentation (the "Software") to deal in the
Data Files or Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, and/or sell
copies of the Data Files or Software, and to permit persons to whom the
Data Files or Software are furnished to do so, provided that either (a)
this copyright and permission notice appear with all copies of the Data
Files or Software, or (b) this copyright and permission notice appear in
associated Documentation.

THE DATA FILES AND SOFTWARE ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF
THIRD PARTY RIGHTS.

IN NO EVENT SHALL THE COPYRIGHT HOLDER OR HOLDERS INCLUDED IN THIS NOTICE
BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES,
OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THE DATA
FILES OR SOFTWARE.

Except as contained in this notice, the name of a copyright holder shall
not be used in advertising or otherwise to promote the sale, use or other
dealings in these Data Files or Software without prior written
authorization of the copyright holder.
```

## MIT license and copyright notices

Crates licensed under the MIT license, or under MIT OR another license and used here under MIT, with the copyright line(s) from each crate's license file:

* **aead 0.6.1**: Copyright (c) 2019-2026 The RustCrypto Project Developers; Copyright (c) 2019 MobileCoin, LLC
* **aes 0.9.3**: Copyright (c) 2018-2024 The RustCrypto Project Developers; Copyright (c) 2018 Artyom Pavlov
* **aes-gcm 0.11.1**: Copyright (c) 2019-2026 The RustCrypto Project Developers
* **anstream 1.0.0**: Copyright (c) Individual contributors
* **anstyle 1.0.14**: Copyright (c) Individual contributors
* **anstyle-parse 1.0.0**: Copyright (c) Individual contributors
* **anstyle-query 1.1.5**: Copyright (c) Individual contributors
* **base32 1.0.0-rc.1**: Copyright (c) 2015 The base32 Developers
* **base64 0.23.1**: Copyright (c) 2025 Alice Maz, Marshall Pierce
* **base64ct 1.8.3**: Copyright (c) 2014 Steve "Sc00bz" Thomas (steve at tobtu dot com); Copyright (c) 2021-2025 The RustCrypto Project Developers
* **block-buffer 0.12.1**: Copyright (c) 2018-2025 The RustCrypto Project Developers
* **cfg-if 1.0.5**: Copyright (c) 2014 Alex Crichton
* **cipher 0.5.2**: Copyright (c) 2016-2025 RustCrypto Developers
* **clap 4.6.7**: Copyright (c) Individual contributors
* **clap_builder 4.6.7**: Copyright (c) Individual contributors
* **clap_lex 1.1.1**: Copyright (c) Individual contributors
* **cmov 0.5.4**: Copyright (c) 2022-2026 The RustCrypto Project Developers
* **colorchoice 1.0.5**: Copyright (c) Individual contributors
* **const-oid 0.10.2**: Copyright (c) 2020-2026 The RustCrypto Project Developers
* **cpubits 0.1.1**: Copyright (c) 2023-2026 The RustCrypto Project Developers
* **cpufeatures 0.3.1**: Copyright (c) 2020-2026 The RustCrypto Project Developers
* **crypto-common 0.2.2**: Copyright (c) 2021-2026 RustCrypto Developers
* **ctr 0.10.1**: Copyright (c) 2018-2022 RustCrypto Developers; Copyright (c) 2018 Artyom Pavlov
* **ctutils 0.4.2**: Copyright (c) 2025-2026 The RustCrypto Project Developers
* **der 0.8.2**: Copyright (c) 2020-2026 The RustCrypto Project Developers
* **digest 0.11.3**: Copyright (c) 2017-2025 RustCrypto Developers; Copyright (c) 2017 Artyom Pavlov
* **ed25519 3.0.0**: Copyright (c) 2018-2026 RustCrypto Developers
* **equivalent 1.0.2**: Copyright (c) 2016--2023
* **getrandom 0.4.3**: Copyright (c) 2018-2026 The rust-random Project Developers; Copyright (c) 2014 The Rust Project Developers
* **ghash 0.6.0**: Copyright (c) 2019-2026 The RustCrypto Project Developers
* **hashbrown 0.17.1**: Copyright (c) 2016 Amanieu d'Antras
* **hex 0.4.3**: Copyright (c) 2013-2014 The Rust Project Developers.; Copyright (c) 2015-2020 The rust-hex Developers
* **hkdf 0.13.0**: Copyright (c) 2015-2018 Vlad Filippov; Copyright (c) 2018-2021 RustCrypto Developers
* **hmac 0.13.0**: Copyright (c) 2017 Artyom Pavlov
* **hybrid-array 0.4.15**: Copyright (c) 2022-2026 The RustCrypto Project Developers
* **indexmap 2.14.2**: Copyright (c) 2016--2017
* **inout 0.2.2**: Copyright (c) 2022-2025 The RustCrypto Project Developers; Copyright (c) 2022 Artyom Pavlov
* **is_terminal_polyfill 1.70.2**: Copyright (c) Individual contributors
* **itoa 1.0.18**: (no copyright line in the license file)
* **keccak 0.2.2**: Copyright (c) 2018-2026 The RustCrypto Project Developers
* **kem 0.3.0**: Copyright (c) 2021-2026 RustCrypto Developers
* **libc 0.2.189**: Copyright (c) The Rust Project Developers
* **memchr 2.8.3**: Copyright (c) 2015 Andrew Gallant
* **ml-dsa 0.1.1**: Copyright (c) 2024-2026 RustCrypto Developers
* **ml-kem 0.3.2**: Copyright (c) 2024-2026 RustCrypto Developers
* **module-lattice 0.2.3**: Copyright (c) 2024-2026 RustCrypto Developers
* **num-traits 0.2.19**: Copyright (c) 2014 The Rust Project Developers
* **once_cell 1.21.4**: (no copyright line in the license file)
* **pkcs8 0.11.0**: Copyright (c) 2020-2026 The RustCrypto Project Developers
* **polyval 0.7.3**: Copyright (c) 2019-2026 The RustCrypto Project Developers
* **rand_core 0.10.1**: Copyright (c) 2018-2026 The Rand Project Developers
* **serde_core 1.0.229**: (no copyright line in the license file)
* **serde_json 1.0.151**: (no copyright line in the license file)
* **sha2 0.11.0**: Copyright (c) 2016-2026 The RustCrypto Project Developers; Copyright (c) 2016 Artyom Pavlov; Copyright (c) 2009-2013 Mozilla Foundation; Copyright (c) 2006-2009 Graydon Hoare
* **sha3 0.11.0**: Copyright (c) 2020-2026 The RustCrypto Project Developers; Copyright (c) 2016-2023 Artyom Pavlov, Marek Kotewicz; Copyright (c) 2014 Sébastien Martini; Copyright (c) 2009-2013 Mozilla Foundation; Copyright (c) 2006-2009 Graydon Hoare
* **shake 0.1.0**: Copyright (c) 2026 The RustCrypto Project Developers
* **signature 3.0.0**: Copyright (c) 2018-2026 RustCrypto Developers
* **spki 0.8.0**: Copyright (c) 2021-2026 The RustCrypto Project Developers
* **sponge-cursor 0.1.0**: Copyright (c) 2026 The RustCrypto Project Developers
* **strsim 0.11.1**: Copyright (c) 2015 Danny Guo; Copyright (c) 2016 Titus Wormer <tituswormer@gmail.com>; Copyright (c) 2018 Akash Kurdekar
* **typenum 1.20.1**: Copyright (c) 2014 Paho Lurie-Gregg
* **unicode-ident 1.0.26**: (no copyright line in the license file)
* **universal-hash 0.6.1**: Copyright (c) 2019-2025 RustCrypto Developers
* **utf8parse 0.2.2**: Copyright (c) 2016 Joe Wilm
* **wasm-bindgen 0.2.129**: Copyright (c) 2014 Alex Crichton
* **wasm-bindgen-shared 0.2.129**: Copyright (c) 2014 Alex Crichton
* **zeroize 1.9.0**: Copyright (c) 2018-2026 The RustCrypto Project Developers
* **zmij 1.0.23**: (no copyright line in the license file)

The license text (MIT):

```text
Copyright (c) <year> <copyright holders, as listed above>
Copyright (c) 2019 MobileCoin, LLC

Permission is hereby granted, free of charge, to any
person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without
limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software
is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice
shall be included in all copies or substantial portions
of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
```

The license file of base64, memchr, strsim, typenum differs in wording and is reproduced in full:

```text
The MIT License (MIT)

Copyright (c) 2025 Alice Maz, Marshall Pierce

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

## npm runtime dependencies (not bundled)

These are the production dependencies recorded in the lockfiles of the packages that have any. They are installed by npm with their own license files and are not copied into this repository or into the `@atep/core` package. `@atep/core` (in `js/`) has no runtime dependencies; `demo/` has none. Licenses are taken from each lockfile's `license` field. There is no copyleft or unlicensed package in these sets.

### `mcp/` (`@atep/mcp`) and `examples/` (identical set, `94` packages)

| Package | Version | License |
| --- | --- | --- |
| @hono/node-server | 2.1.3 | MIT |
| @modelcontextprotocol/sdk | 1.31.0 | MIT |
| accepts | 2.0.0 | MIT |
| ajv | 8.20.0 | MIT |
| ajv-formats | 3.0.1 | MIT |
| body-parser | 2.3.0 | MIT |
| bytes | 3.1.2 | MIT |
| call-bind-apply-helpers | 1.0.2 | MIT |
| call-bound | 1.0.4 | MIT |
| content-disposition | 1.1.0 | MIT |
| content-type | 2.1.0 | MIT |
| content-type | 1.0.5 | MIT |
| content-type | 2.1.0 | MIT |
| content-type | 2.1.0 | MIT |
| cookie | 0.7.2 | MIT |
| cookie-signature | 1.2.2 | MIT |
| cors | 2.8.6 | MIT |
| cross-spawn | 7.0.6 | MIT |
| debug | 4.4.3 | MIT |
| depd | 2.0.0 | MIT |
| dunder-proto | 1.0.1 | MIT |
| ee-first | 1.1.1 | MIT |
| encodeurl | 2.0.0 | MIT |
| es-define-property | 1.0.1 | MIT |
| es-errors | 1.3.0 | MIT |
| es-object-atoms | 1.1.2 | MIT |
| escape-html | 1.0.3 | MIT |
| etag | 1.8.1 | MIT |
| eventsource | 3.0.7 | MIT |
| eventsource-parser | 3.1.1 | MIT |
| express | 5.2.1 | MIT |
| express-rate-limit | 8.7.0 | MIT |
| fast-deep-equal | 3.1.3 | MIT |
| fast-uri | 3.1.8 | BSD-3-Clause |
| finalhandler | 2.1.1 | MIT |
| forwarded | 0.2.0 | MIT |
| fresh | 2.0.0 | MIT |
| function-bind | 1.1.2 | MIT |
| get-intrinsic | 1.3.0 | MIT |
| get-proto | 1.0.1 | MIT |
| gopd | 1.2.0 | MIT |
| has-symbols | 1.1.0 | MIT |
| hasown | 2.0.4 | MIT |
| hono | 4.13.12 | MIT |
| http-errors | 2.0.1 | MIT |
| iconv-lite | 0.7.3 | MIT |
| inherits | 2.0.4 | ISC |
| ip-address | 10.7.2 | MIT |
| ipaddr.js | 1.9.1 | MIT |
| is-promise | 4.0.0 | MIT |
| isexe | 2.0.0 | ISC |
| jose | 6.2.12 | MIT |
| json-schema-traverse | 1.0.0 | MIT |
| json-schema-typed | 8.0.2 | BSD-2-Clause |
| math-intrinsics | 1.1.0 | MIT |
| media-typer | 1.1.1 | MIT |
| merge-descriptors | 2.0.0 | MIT |
| mime-db | 1.54.0 | MIT |
| mime-types | 3.0.2 | MIT |
| ms | 2.1.3 | MIT |
| negotiator | 1.1.0 | MIT |
| object-assign | 4.1.1 | MIT |
| object-inspect | 1.13.4 | MIT |
| on-finished | 2.4.1 | MIT |
| once | 1.4.0 | ISC |
| parseurl | 1.3.3 | MIT |
| path-key | 3.1.1 | MIT |
| path-to-regexp | 8.4.2 | MIT |
| pkce-challenge | 5.0.1 | MIT |
| proxy-addr | 2.0.8 | MIT |
| qs | 6.16.0 | BSD-3-Clause |
| range-parser | 1.3.0 | MIT |
| raw-body | 3.0.2 | MIT |
| require-from-string | 2.0.2 | MIT |
| router | 2.2.0 | MIT |
| safer-buffer | 2.1.2 | MIT |
| send | 1.2.1 | MIT |
| serve-static | 2.2.1 | MIT |
| setprototypeof | 1.2.0 | ISC |
| shebang-command | 2.0.0 | MIT |
| shebang-regex | 3.0.0 | MIT |
| side-channel | 1.1.1 | MIT |
| side-channel-list | 1.0.1 | MIT |
| side-channel-map | 1.0.1 | MIT |
| side-channel-weakmap | 1.0.2 | MIT |
| statuses | 2.0.2 | MIT |
| toidentifier | 1.0.1 | MIT |
| type-is | 2.1.0 | MIT |
| unpipe | 1.0.0 | MIT |
| vary | 1.1.2 | MIT |
| which | 2.0.2 | ISC |
| wrappy | 1.0.2 | ISC |
| zod | 3.25.76 | MIT |
| zod-to-json-schema | 3.25.2 | ISC |

### `examples/mqtt/` (`45` packages)

| Package | Version | License |
| --- | --- | --- |
| @babel/runtime | 7.29.7 | MIT |
| @types/node | 26.6.3 | MIT |
| @types/readable-stream | 4.0.25 | MIT |
| @types/ws | 8.18.2 | MIT |
| abort-controller | 3.0.0 | MIT |
| base64-js | 1.5.1 | MIT |
| bl | 6.1.6 | MIT |
| broker-factory | 3.1.15 | MIT |
| buffer | 6.0.3 | MIT |
| buffer | 6.0.3 | MIT |
| buffer-from | 1.1.2 | MIT |
| commist | 3.2.0 | MIT |
| concat-stream | 2.0.0 | MIT |
| debug | 4.4.3 | MIT |
| event-target-shim | 5.0.1 | MIT |
| events | 3.3.0 | MIT |
| fast-unique-numbers | 9.0.27 | MIT |
| help-me | 5.0.0 | MIT |
| ieee754 | 1.2.1 | BSD-3-Clause |
| inherits | 2.0.4 | ISC |
| ip-address | 10.7.2 | MIT |
| lru-cache | 10.4.3 | ISC |
| minimist | 1.2.8 | MIT |
| mqtt | 5.16.0 | MIT |
| mqtt-packet | 9.0.2 | MIT |
| ms | 2.1.3 | MIT |
| process | 0.11.10 | MIT |
| process-nextick-args | 2.0.1 | MIT |
| readable-stream | 3.6.2 | MIT |
| readable-stream | 4.7.0 | MIT |
| rfdc | 1.4.1 | MIT |
| safe-buffer | 5.2.1 | MIT |
| smart-buffer | 4.2.0 | MIT |
| socks | 2.8.10 | MIT |
| split2 | 4.2.0 | ISC |
| string_decoder | 1.3.0 | MIT |
| tslib | 2.8.1 | 0BSD |
| typedarray | 0.0.6 | MIT |
| undici-types | 8.9.0 | MIT |
| util-deprecate | 1.0.2 | MIT |
| worker-factory | 7.0.50 | MIT |
| worker-timers | 8.0.34 | MIT |
| worker-timers-broker | 8.0.18 | MIT |
| worker-timers-worker | 9.0.15 | MIT |
| ws | 8.22.0 | MIT |
