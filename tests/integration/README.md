# Integration harness (Mishaal, shared cases)

`test_targets.py` runs each lab target's authored `snapshot.json` through the real
analyzer and planner and checks it against `targets/<name>/expected.yaml` — **offline,
no Docker, no SSH**. It covers recall of the planted paths, precision on High paths,
the weak2 entry-point requirement (AG-02), weak1's unknown-sudo check, the hardened
zero-paths guarantee, and a break-a-rule meta-check proving the test is real (TE-03).

```sh
python -m pytest -q tests/integration      # or: make integration
```

The live variant — scanning the running containers over SSH and comparing a freshly
collected snapshot — is added once `make targets-up` brings the Docker lab up; the
authored snapshots are stand-ins until then. Unit contract tests alone do not
establish live detection accuracy, no-writes behaviour, or real redaction on a host.
