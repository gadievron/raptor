# C/C++ sanitizer value binding

Character escaping does not establish the surrounding HTML context.
The straight-line and symmetric-branch fixtures retain value-bound
`g_markup_escape_text` candidates while their output policy is unverified.

The wrong-variable fixture keeps the raw sink value separate from the
encoded value. The bypass fixture retains a path around encoding, and
the escaping-storage fixture retains its storage-lifetime refusal.
Callgraph-only recognition carries no input or output symbol authority.
