# Noise Implementation Audit Reference

Use this reference when checking whether an implementation matches the Noise specification.

Primary sources:

- Noise Protocol Framework: https://noiseprotocol.org/noise.html
- Noise Explorer pattern catalog: https://noiseexplorer.com/patterns/

## 1. Construction string parsing

A Noise construction string has the form:

```text
Noise_<pattern>_<dh>_<cipher>_<hash>
```

Examples:

- `Noise_IKpsk2_secp256k1_AEGIS128L_BLAKE3`
- `Noise_XX_25519_ChaChaPoly_BLAKE2s`

When auditing:

- verify the code's claimed pattern matches the real handshake flow
- verify the PSK modifier in the name matches actual PSK mixing in code
- verify DH, cipher, and hash choices are not just labels but are actually wired into the implementation

## 2. Noise token semantics

Noise token names are based on initiator and responder roles, not on "the side currently sending a message".

That matters when auditing `es` and `se`.

Role key names:

- `e` = initiator ephemeral
- `s` = initiator static
- `re` = responder ephemeral
- `rs` = responder static

The important DH lanes are:

- `ee` = `DH(e, re)`
- `es` = initiator uses `DH(e, rs)` and responder uses `DH(s, re)`
- `se` = initiator uses `DH(s, re)` and responder uses `DH(e, rs)`
- `ss` = `DH(s, rs)`

Implications:

- do not flag a DH as wrong only because the operands are reversed
- do not interpret `se` as "sender static with recipient ephemeral"
- on the responder side, the `se` token can legitimately look like `DH(resp_eph, init_static)`

Only flag a mismatch if the key lanes do not match the token meaning after accounting for role and message direction.

## 3. Audit checklist

### Pattern correctness

Check:

- does the code expose a `Noise_...` string
- does the actual message flow match that named pattern
- are pre-messages handled consistently with the pattern name
- are static keys pre-known or transmitted at the correct step

### Handshake flow

Locate:

- initiator send-init function
- responder accept/respond function
- initiator accept-response function
- handshake state struct
- functions or helpers that mix keys or hashes

Check:

- which keys are created or loaded at each step
- which remote keys are stored for later token processing
- whether each expected token in the transcript has a corresponding implementation step

### PSK handling

Check:

- whether the pattern name includes `psk`
- whether the PSK is actually mixed in
- whether the PSK is fixed, zeroed, test-only, or public
- whether production defaults silently inherit test vectors

### DH call sites

For every `ecdh`, `dh`, `x25519`, or similar call:

1. identify the local private key
2. identify the remote public key
3. identify which handshake step this belongs to
4. map it to the expected token from the transcript
5. confirm both sides implement the same intended lane

### State tracking

Common bugs:

- remote static never stored, so later `es` or `ss` processing is impossible
- remote ephemeral never stored, so later `ee` or `se` processing is impossible
- the code claims a lane exists but never mixes it
- the code mixes a lane twice or in the wrong position

## 4. Mapping implementation findings to the CLI

The CLI is a qualitative visualization tool, not a verifier.

Safe mappings:

- fixed zero-style PSK -> `--zero-psk`
- truly wrong or misbound `se` -> `--wrong-se`
- a missing DH lane -> matching `--omit-*`
- deployment compromise assumption -> `--scenario ...`

Approximation rule:

If a bug does not cleanly map to one CLI flag, report the implementation finding directly and say the CLI visualization is only an approximate projection of that finding.

## 5. Reporting standard

Prefer this structure:

1. Findings
2. Observed implementation facts
3. Spec mapping
4. CLI visualization
5. Residual uncertainty

Always separate:

- what the code definitely does
- what the Noise spec expects
- what the heuristic model suggests that means for protocol properties
