# cvss31

cvss31 computes the CVSS v3.1 base score and severity from vector strings, following the FIRST specification (including its Roundup function), for one vector or a whole file of findings. It is a single static binary with no runtime, handy in pipelines where you only want numbers you can verify against the spec.

**Live demo:** https://jvch0512.github.io/cvss31/ (Fictional finding IDs with real CVSS vectors from public CVEs.)

Fortran 2008 (gfortran), no libraries. The demo page is rendered from the tool's `--tsv` output by `scripts/site.py` (Python 3, only needed to regenerate the page).

## Use

```bash
make build
./bin/cvss31 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
./bin/cvss31 --file examples/vectors.txt           # lines: ID<space>VECTOR (the ID is optional)
./bin/cvss31 --file examples/vectors.txt --tsv
./bin/cvss31 --file scan.txt --min 7.0              # exit 1 if any score is 7.0 or above
```

Output per vector: base score, severity (none, low, medium, high, critical) and the sub-scores (impact and exploitability). `--tsv` emits one row per vector for dashboards.

See [examples](examples) and [docs/sample-output.txt](docs/sample-output.txt).

## Limits

- Base metrics only. Temporal and environmental scores are not computed.
- CVSS 3.1 vectors only (`CVSS:3.1/...`). CVSS 3.0 uses a slightly different rounding, v4.0 is a different model.
- A vector with a missing or unknown metric is reported as invalid, never guessed.

## Where it fits

A triage step that must be reproducible: scoring scanner output offline, checking a vendor's published score, or feeding [vuln-prioritizer](https://github.com/jvch0512/vuln-prioritizer) with verified base scores.

## Tests

```bash
make test    # 45 checks
```

MIT.
