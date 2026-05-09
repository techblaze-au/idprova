# Python examples

Runnable Python scripts that exercise the IDProva HTTP SDK against a registry. They are example code, not packaged anywhere.

## Files in this directory

- `issue_verify.py` — connects to a registry, lists existing AIDs, prints the count and the first three identifiers. Acts as a smoke test that the registry is reachable and the SDK shim under `sdks/python` is importable.
- `requirements.txt` — minimal runtime: `httpx>=0.26`. Required by `issue_verify.py`.
- `requirements-langchain.txt` — adds `langchain-core>=0.1` for examples that integrate with LangChain agents (none in this directory yet — pin is here for forthcoming examples).

## Prerequisites

- Python 3.10+
- A registry reachable at the URL in `IDPROVA_REGISTRY` (default `http://localhost:3000`). Run one locally with `cargo run -p idprova-registry` from the repo root.

## Run `issue_verify.py`

```bash
cd examples/python
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python issue_verify.py
```

Expected output when the registry is empty:

```
Registry has 0 AIDs

IDProva Python SDK working correctly!
```

If the registry is unreachable, the script prints `Could not list AIDs: ...` but still exits 0 — it is a demo, not a CI check.

## Pointing at a different registry

```bash
IDPROVA_REGISTRY=https://registry.idprova.dev python issue_verify.py
```

## Importing the SDK from these examples

The script does `sys.path.insert(0, '../../sdks/python')` to use the in-tree SDK without `pip install`. For application code, install the published package instead — see [`sdks/python/README.md`](../../sdks/python/README.md).
