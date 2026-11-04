# Security policy

Mandat is security software. If you find a vulnerability, please tell us privately first.

## Reporting a vulnerability

Use **GitHub's private vulnerability reporting**: [Report a vulnerability](https://github.com/vosidov-msaid/Mandat/security/advisories/new) (repository → *Security* → *Advisories*). Please don't open a public issue for security problems.

Include what you found, how to reproduce it, and the version (`mandat --version`, or `pip show mandat`). We aim to acknowledge reports within 3 working days and to agree on a disclosure date with you.

## In scope

- **Tokens:** bypassing token verification, audience binding, revocation or delegation limits.
- **Policy:** policy decisions that allow what the policy denies, including fail-open behaviour.
- **Approvals:** forging, replaying or self-approving them.
- **Audit ledger:** tampering that `mandat ledger verify` doesn't detect, and secrets or personal data written despite redaction.
- **Scanner page:** SSRF or injection, including reaching private addresses from a hosted `mandat web`.
- **Supply chain:** issues in the published npm and PyPI packages.

## Supported versions

Security fixes go into the latest release of each package (npm `mandat` and PyPI `mandat`).

## Verifying releases

npm and PyPI releases are built by GitHub Actions from tagged commits, published through Trusted Publishing, and carry provenance and attestations:

```bash
npm audit signatures            # in a project that depends on mandat
```

You can also check the provenance on [npmjs.com/package/mandat](https://www.npmjs.com/package/mandat) and the attestations on [pypi.org/project/mandat](https://pypi.org/project/mandat/).
