# Implementation findings

Findings from implementing the ATEP specification. Each file is a numbered log of places where the specification text was ambiguous, incomplete or in conflict with the test vectors, with a proposed fix and the resolution that the specification adopted.

| File | Source of the findings |
| --- | --- |
| [rust-findings.md](rust-findings.md) | The Rust reference implementation (`rust/`), which also generates the vectors. Entries 1 to 56. |
| [python-findings.md](python-findings.md) | The independent Python implementation (`python/`), written from the spec and the vectors only, as an interoperability test. Entries 1 to 44. |

"Draft N" in these files names an internal working draft (Drafts 00 to 06 were not published). [Draft 07](../../spec/ATEP-Specification-Draft-07.md) is the first public draft and carries all resolutions; see its Appendix A for the numbering.

New findings go at the end of the matching file, numbered in sequence, in the same format (section, problem, proposed fix, what the implementation does, resolution). Report one by opening an issue (see [CONTRIBUTING.md](../../CONTRIBUTING.md)).
