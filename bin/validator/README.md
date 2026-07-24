# `constantinople-validator`

Validator binary for the constantinople blockchain.

The current validator wiring stores DKG shares, dealer seeds, and private dealings
in a local `dkg-secrets` directory using `FileSecretStore`. Those files are plaintext
and protected only by local filesystem permissions. This is bootstrap infrastructure,
not production-grade secret management; real-value deployments should replace it with
encrypted or hardware-isolated storage that supports backup and rotation.
