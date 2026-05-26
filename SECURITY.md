# Security Policy

Warlog Spec is a public contract for schemas, provider ABI primitives,
action catalog entries, conformance fixtures, and audit-chain verification.
It is not the Warlog product runtime, SOC UI, policy engine, credential
store, or deployment stack.

## Supported Versions

Security fixes are applied on a best-effort basis to the active main
branch and the latest published pre-1.0 package line.

Because the spec is still pre-1.0, maintainers may ship security fixes as
patch releases or as documented breaking changes when the safer contract
requires it.

## Reporting A Vulnerability

Do not open a public issue for suspected vulnerabilities that include
exploit details, secrets, credentials, tokens, private tenant data, or a
step-by-step attack path.

Use GitHub private vulnerability reporting if it is enabled for the
repository. If it is not enabled, contact the maintainers privately using
the channels listed in `GOVERNANCE.md`.

Please include:

- affected package, schema, or document path
- affected version or commit if known
- impact and threat model
- reproduction steps or a minimal proof of concept
- suggested mitigation if you have one

## Response Targets

These are targets, not contractual SLAs:

- acknowledge receipt within 5 business days
- provide an initial severity/scope assessment within 10 business days
- coordinate a fix, mitigation, or public note before publishing details
- credit reporters unless they ask to remain anonymous

Complex reports involving cryptography, conformance bypass, or ecosystem
compatibility may take longer because fixes can affect the public contract.

## In Scope

- audit-chain canonicalization or signature verification flaws
- schema rules that allow ambiguous or misleading audit evidence
- conformance runner bypasses that create false compatibility claims
- reference package vulnerabilities that affect consumers of the spec
- examples or docs that would cause unsafe key, secret, or PII handling
- supply-chain risks in the published Python, TypeScript, or MCP packages

## Out Of Scope

- vulnerabilities in private Warlog product deployments
- tenant-specific operational misconfiguration
- social engineering, spam, or denial-of-service against project services
- reports that depend on publishing secrets or private data publicly
- speculative issues without a reproducible impact path

## Disclosure

Maintainers prefer coordinated disclosure. Public advisories should be
published only after a fix, mitigation, or explicit maintainer note is
available.