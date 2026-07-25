# Security Policy

Limonata is a Cosmos SDK + cosmos/evm Layer 1. The public network today is the testnet
`limonata_10777-1` (EVM chain id 10777). Mainnet has not launched.

> Do NOT open a public issue, pull request, Discord message, or social post for a security
> vulnerability.

## Supported versions

| Scope | Supported |
|---|---|
| Latest tagged release (currently `limonata-v0.3.4`) | yes |
| `main` branch | yes |
| Older tags | no |

A report is in scope if it reproduces against the latest tagged release or `main`. Findings in
inherited upstream `cosmos/evm` or Cosmos SDK code that Limonata does not modify should also go
upstream. Tell us and we will coordinate.

## How to report

Preferred: open a private security advisory on GitHub.

https://github.com/Limonata-Blockchain/limonata/security/advisories/new

This gives us a private thread, file attachments, a private fork to develop the fix in, and a
coordinated publication and CVE path.

Alternative: email security@limonata.xyz.

If you need end to end encryption and neither route works for you, send a first contact message
with no technical detail and we will arrange a key.

Please include: affected version or commit, component (module, precompile, or binary), reproduction
steps, observed and expected behaviour, and your assessment of impact. A proof of concept against a
local devnet is welcome. See `contrib/dkg-devnet/` for an isolated devnet kit. Say up front whether
you want public credit.

## What we commit to

- Acknowledge your report within 48 hours.
- Give you an initial triage and severity assessment within 5 business days.
- Keep you updated at least every 7 days while the issue is open.
- Agree an embargo period and a public disclosure date with you in writing, rather than leaving it
  open ended.
- Credit you by name or handle in the advisory and the release notes, unless you ask us not to.
- Not pursue or support legal action against you for research conducted under this policy.

Because consensus level fixes on a live network require a coordinated validator upgrade, embargo
windows for consensus bugs are typically measured in weeks, not days. We will tell you the expected
timeline as soon as we have triaged.

We score severity by impact on the mainnet genesis binary, not by "it is only a testnet". The
mainnet binary is built from this code.

## Rules of engagement

We ask that you:

- Test against a local devnet or your own isolated network.
- Do not run exploit attempts, denial of service, spam, resource exhaustion, or Byzantine validator
  behaviour against the public testnet without prior written approval from us, per test.
- Do not access, modify, or exfiltrate data belonging to other users.
- Do not use social engineering, phishing, or physical attacks against contributors or
  infrastructure providers.
- Give us reasonable time to ship a fix before publishing.

Read only observation of the public testnet, running your own node, and testing on your own
isolated network are always in scope and need no approval.

## Bounty

There is no bug bounty program yet. An independent security audit and a public bug bounty are
committed before mainnet launch. Reporters who help us before then will be credited publicly and
invited to the bounty program when it opens.

## Scope

In scope: consensus and state machine bugs, DKG and encrypted mempool (`x/encmempool`), the gas
sponsorship modules (`x/gassponsor`, `x/sponsorpool`), custom precompiles, the passkey account
system, key handling, and anything that can halt the chain, fork it, mint tokens, steal funds, or
break the confidentiality guarantees of the encrypted mempool.

Out of scope: findings that require a validator to already control more than one third of stake,
issues in third party infrastructure we do not run, and best practice recommendations with no
demonstrated impact. Report them anyway if you think they matter, but expect them to be triaged as
hardening rather than as vulnerabilities.
