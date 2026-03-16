# Registry Authentication Setup

Before running `publish-v0.1.0.sh`, set up auth for all three registries.

## 1. crates.io (Rust)

```bash
# Get token from https://crates.io/me → New Token
# Scopes needed: publish-new, publish-update
cargo login
# Paste your token when prompted
```

## 2. PyPI (Python)

```bash
# Get token from https://pypi.org/manage/account/token/
# Create a project-scoped token for "idprova" (or use a global token for first publish)
# Option A: Environment variable
export MATURIN_PYPI_TOKEN=pypi-AgEI...

# Option B: ~/.pypirc file
cat > ~/.pypirc << 'EOF'
[pypi]
username = __token__
password = pypi-AgEI...your-token-here
EOF
```

## 3. npm (TypeScript)

```bash
# Create account at https://www.npmjs.com/signup (if needed)
npm adduser
# Follow the prompts (username, password, email, OTP)

# Or use a token:
npm config set //registry.npmjs.org/:_authToken=npm_...
```

## 4. GitHub (for making repo public + pushing tags)

Already configured via git — just verify:
```bash
gh auth status
```

## Quick Test

After auth setup, verify with:
```bash
cargo publish -p idprova-core --dry-run  # Should succeed
npm whoami                                # Should show your username
```
