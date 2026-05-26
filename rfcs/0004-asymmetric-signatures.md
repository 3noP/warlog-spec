---
RFC: 0004
Title: Asymmetric signatures (Ed25519, RSASSA-PSS) for AuditAttestation
Author: Warlog Spec maintainers
Status: Accepted, Schema Implemented
Created: 2026-05-20
Requires: 0001
Supersedes:
Superseded-By:
---

# RFC-0004 — Asymmetric signatures for AuditAttestation

## Abstract

`AuditAttestation` v1 (RFC 0001) supports a single algorithm :
HMAC-SHA256 with a shared secret. That model collapses signer and
verifier custody onto the same party. This RFC extends the
`algorithm` enum to also accept `Ed25519` and `RSASSA-PSS-SHA256`,
so an organization that needs to separate the signing key custody
from the verifier audience (third-party auditor, regulator, customer
of an MSSP) can use a public-key signature scheme without leaving
the contract.

The schema change is implemented in this RFC ; the crypto code paths
(actual signing + verification for the asymmetric algorithms) land
with the first operator that needs them.

## Motivation

HMAC-SHA256 is correct for the common warlog deployment : a single
tenant, with a single secret stored in Vault, signing rows that the
same tenant verifies. The verifier holds the secret ; the chain is
tamper-evident under the assumption that the secret stays
tenant-side.

Three scenarios break that assumption :

1. **MSSP customer audits.** An MSSP signs rows for a customer's
   tenant. The customer, post-engagement, wants to verify the chain
   without trusting the MSSP's ongoing access. With HMAC, handing
   the secret to the customer means the customer can forge new
   rows ; not handing it means the customer can't verify.

2. **Third-party regulator audits.** A DORA or NIS2 auditor demands
   to verify a chain spanning months of activity, from a tenant
   they have no shared-secret relationship with. HMAC requires the
   tenant to expose its signing secret to the auditor, which is
   itself a compliance violation.

3. **Long-term forensic preservation.** Storing a chain for 7 years
   for a closed compliance case means the signing secret must be
   preserved (and rotated, and re-bound) for 7 years. Public-key
   schemes only require preserving the public key — the private
   signing key can be destroyed once the case is closed.

The common shape across all three : **the signer and the verifier
are different parties, and the signer's signing material MUST NOT
be shareable with the verifier**. That's the textbook definition of
asymmetric signature.

## Specification

### Extended `algorithm` enum

`AuditAttestation.algorithm` becomes a closed enum of three values :

| Value | Family | Signing material | Verifying material |
|---|---|---|---|
| `HMAC-SHA256` | symmetric | shared secret (32+ bytes random) | same shared secret |
| `Ed25519` | asymmetric | Ed25519 private key (32 bytes) | Ed25519 public key (32 bytes) |
| `RSASSA-PSS-SHA256` | asymmetric | RSA private key (≥3072 bit) | RSA public key |

`HMAC-SHA256` remains the default for new attestations. The two
asymmetric values land as additive enum values — existing
attestations are unaffected.

### Signature encoding

For both asymmetric algorithms, `signatureValue` carries the raw
signature as lowercase-hex :

- `Ed25519` : 64-byte signature → 128 hex chars
- `RSASSA-PSS-SHA256` : signature length = RSA key length / 8
  (typically 384 hex chars for 3072-bit, 512 for 4096-bit)

This **changes the length of `signatureValue`** from the v1 fixed
64-char constraint. The schema constraint relaxes from
`length=64` to `minLength=64, maxLength=4096`. The exact length
is now derived from `algorithm` at validation time, not from the
schema.

### `keyId` semantics by algorithm

| Algorithm | `keyId` interpretation |
|---|---|
| `HMAC-SHA256` | Operator-defined reference to a shared secret (typically `tenant:<id>:hmac:v<N>`) |
| `Ed25519` | URI or DID resolving to the Ed25519 **public** key. Common patterns : `did:web:auditor.example.org#key-ed25519-1`, `https://keys.example.org/ed25519/v3.pem` |
| `RSASSA-PSS-SHA256` | Same as Ed25519, resolving to the RSA public key |

Verifiers MUST fetch the public key from `keyId` and check the
signature against it. The fetch protocol is out of scope for the
spec — operators choose between DID resolution, JWKS, file URLs,
HKP, etc.

### Genesis hash for asymmetric chains

The genesis hash (the `prevRowHash` of the chain's first row) is
derived differently per algorithm :

- `HMAC-SHA256` : `HMAC(secret, "warlog-spec/v1/genesis|" || tenant_id)` (unchanged from v1)
- `Ed25519` / `RSASSA-PSS-SHA256` : `sha256("warlog-spec/v1/genesis|" || tenant_id)` (public-derivable, no secret)

For asymmetric chains, the genesis is publicly recomputable — anyone
who knows the tenant id can derive the first `prevRowHash`. This is
intentional : the chain's integrity comes from the per-row
signatures, not from the secret-derived genesis.

### Canonicalization is unchanged

`canonicalize_v1` produces the exact same bytes regardless of
algorithm. The asymmetric algorithms sign the same canonical bytes
the HMAC variant signs.

## Design rationale

**Why two asymmetric algorithms instead of one ?** Ed25519 is the
modern default — fast, short, no parameter choices to get wrong.
RSASSA-PSS-SHA256 is the conservative choice for organizations
whose compliance regime mandates RSA (some banking and regulated
environments still standardize on it). Supporting both lets
adopters pick by policy, not by spec dictate.

**Why hex-encoded signatures rather than base64 ?** Consistency with
the v1 HMAC encoding. The audit chain is meant for forensic
inspection by humans as well as machines ; hex stays grep-friendly.

**Why publicly-derivable genesis for asymmetric ?** With a shared
secret, the genesis itself acts as a tenant-bound MAC seed that an
attacker without the secret cannot replicate. With asymmetric, the
genesis is just the start-of-chain anchor — its uniqueness is
guaranteed by including the tenant id, and its integrity is
guaranteed by the first signed row's signature. No need to mix in
a secret.

**Why not also support ECDSA P-256 / P-384 ?** Ed25519 dominates
the modern asymmetric signing surface, and RSA-PSS covers the
conservative tail. ECDSA adds complexity (random-k requirements,
deterministic variants RFC 6979, curve choices) without serving a
constituency that neither Ed25519 nor RSA-PSS already covers. A
future RFC can add it if a real adopter requests.

## Alternatives considered

### A. Detached signatures published to a transparency log

Pros : audit-chain immutability via a third-party log
(certificate-transparency-style). Cons : (1) requires a hosted
transparency-log infrastructure that doesn't yet exist for SOC
operations ; (2) introduces a runtime dependency on a third-party
service for every signed row ; (3) the spec stays implementable
standalone today.

### B. JWS / COSE structured envelope around `SignedAuditRow`

Pros : standard signature envelope formats (JWS for JSON, COSE for
CBOR) widely supported by crypto libraries. Cons : (1) JWS / COSE
add their own canonicalization layer that interferes with our
`canonicalize_v1` ; (2) verifiers would need to crack both the
warlog envelope and the JWS envelope ; (3) audit-chain consumers
already implement `canonicalize_v1` (it's tiny) — adding JWS just
to wrap it is layering for the sake of layering. Stay flat.

### C. Per-row key (ephemeral signing keys with attestation chain)

Pros : compromised long-term key cannot retroactively forge old
rows. Cons : (1) needs a separate attestation chain for the
ephemeral keys, doubling the audit surface ; (2) violates the
"flat chain, easy to verify" doctrine ; (3) most regulators
explicitly require long-term verifiability with a stable signing
identity — ephemeral keys make that harder. Defer to a future RFC
if real demand surfaces.

## Backward compatibility

Fully additive at the schema level. v1 HMAC-SHA256 rows continue
to validate. `signatureValue` length constraint relaxes from
`length=64` to `minLength=64, maxLength=4096` ; v1 producers that
emit exactly 64-char signatures remain conformant.

Implementations that today only handle HMAC-SHA256 :

- MUST continue to accept the v1 shape unchanged.
- MAY reject rows with `algorithm != "HMAC-SHA256"` with a clear
  error (e.g. "Algorithm X not supported by this verifier") rather
  than silently passing.
- SHOULD declare their supported algorithms in their conformance
  claim (a `signatureAlgorithms: [...]` row in `COMPAT.md`).

## Reference implementation

- `warlog-spec-py` : schema change in
  `packages/warlog-spec-py/src/warlog_spec/provider_abi.py`
  (`AuditAttestation.algorithm` enum extended,
  `signatureValue` length constraint relaxed).
- `@warlog/spec` : equivalent Zod schema change in
  `packages/warlog-spec-ts/src/provider-abi.ts`.
- Crypto code paths (actual Ed25519 + RSA-PSS signing/verification)
  are NOT implemented in this RFC. The first operator that needs an
  asymmetric chain implements them ; the schema change is the
  enabling contract.

## Open questions

- **Key rotation semantics for asymmetric chains.** When the
  signing key rotates, the verifier needs to know which `keyId`
  was active at write time. v1 already supports this via `keyId`
  on every row ; the question is whether the spec should formalize
  a key-history endpoint or leave it to operator-defined `keyId`
  resolution. Tracked as a future RFC.
- **Hybrid chains (HMAC initial + asymmetric counter-signatures).**
  Some operators may want HMAC for runtime speed and asymmetric
  counter-signatures emitted periodically for external auditability.
  Out of scope for this RFC ; possible follow-up.
- **Post-quantum signatures.** ML-DSA (formerly Dilithium) and
  SLH-DSA are NIST PQC finalists. Adding them to the `algorithm`
  enum is straightforward once a stable interop profile crystallizes.

## References

- RFC-0001 — `AuditAttestation` v1 shape this RFC extends.
- [Ed25519 — RFC 8032](https://www.rfc-editor.org/rfc/rfc8032).
- [RSASSA-PSS — RFC 8017 §8.1](https://www.rfc-editor.org/rfc/rfc8017#section-8.1).
- [JWS — RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) (considered, not adopted).
- [DORA Art. 11](https://eur-lex.europa.eu/eli/reg/2022/2554/oj).
- [NIS2 Annex II](https://eur-lex.europa.eu/eli/dir/2022/2555/oj).
