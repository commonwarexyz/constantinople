# `constantinople-auth`

MAC authentication of transactions, after "Short Signature-Free Transactions in
Byzantine Consensus" (Sections 3 and 4).

A user shares a key with every validator. Instead of signing a transaction, it
sends one validator, its _proposer_, the transaction with a short _tag_ for each
validator (the _authenticator_). The proposer puts the transaction in a block
and sends every validator the tags meant for it (a _column_). A validator's
vote for the block carries a _report_ that says, for each such transaction,
whether its tag was correct. The notarization of a block, carried by the next
block, fixes the _status_ of each transaction: it is authentic if at least
`2f + 1` of the reports in the notarization say so.

| Paper | Here |
| --- | --- |
| `K_{u,i}` | [`SharedKey`], from X25519 between a user and a validator |
| `Tag_K(k, tr)` | [`TagKey::tag`] |
| authenticator, column | [`Tags`] |
| submission | [`Submission`] |
| report | [`Report`] |
| status given a notarization | [`status`] |
| vote with report | [`Scheme`], whose attestation is a [`Vote`] |
| `Chk` | [`Verdicts`] |
| `t` | [`tag_bits`] |
