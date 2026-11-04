# Contributing

Thanks for helping. Bug reports, scanner false positives and false negatives, and pull requests are all welcome.

## Development setup

```bash
git clone https://github.com/vosidov-msaid/Mandat.git && cd Mandat
npm ci                    # dev dependencies only: TypeScript, the MCP SDK used in tests
npm test                  # all TypeScript tests
npm run typecheck         # tsc --strict
npm run demo              # the end-to-end scenario
```

Node ≥ 23.6 runs the TypeScript sources directly; there is no build step for development. `npm run build` produces `dist/` for the npm package.

**Python SDK** (needs Node too, for the end-to-end tests):

```bash
cd python
uv venv && uv pip install -r requirements-dev.txt -e .
python -m unittest discover -s tests -v
```

## Repository layout

| Folder | What | Tests |
|---|---|---|
| `src/`, `test/` | TypeScript: control plane, CLI, guard, scanner | `npm test` |
| `python/` | Python guard and MCP integration | `python -m unittest discover -s tests` |
| `spec/conformance/` | Decisions both SDKs must reproduce | replayed by both suites |
| `docs/` | User guides | — |
| `examples/` | Demo and example MCP servers | used by the tests |

## Guidelines

- **Runtime code stays dependency-free.** Please discuss new runtime dependencies in an issue first.
- **The SDKs must stay identical.** If you change the policy language or the decision engine, run `node scripts/gen-conformance.ts` and make both test suites pass.
- **Security-relevant changes need a test** that fails without the fix.
- **Scanner rules:** include the evidence (a request and response, or a config) for the behaviour you detect, and keep false positives low. Findings are only useful if people trust them.

## Releasing (maintainers)

```bash
npm version patch && git push --follow-tags     # npm: CI stages the release; approve it on npmjs.com (Staged Packages)
git tag py-vX.Y.Z && git push origin py-vX.Y.Z  # PyPI: bump python/pyproject.toml first; approve the "pypi" environment
```

Both workflows build from the tagged commit with Trusted Publishing; no registry tokens are stored. Update [CHANGELOG.md](CHANGELOG.md) before tagging.
