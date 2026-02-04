---
agent: agent
description: This prompt guides the user through updating the Python version in the pySigma-backend-uberAgent project to match the current pySigma minimum requirement.
model: Auto (copilot)
tools: ['execute', 'read', 'edit', 'search', 'web'] 
---

# pySigma-backend-uberAgent Update Python

## Overview

Update the Python version across all project configuration files to align with the current pySigma minimum requirement. Ensures consistency between Poetry configuration and development container.

## Reference Versions

Check the current pySigma Python requirement at:
https://github.com/SigmaHQ/pySigma/blob/main/pyproject.toml

Look for the `python = "^X.Y"` line under `[tool.poetry.dependencies]`.

Check the current pySigma recommended Poetry version at:
https://github.com/SigmaHQ/pySigma/blob/main/.github/workflows/test.yml

Look for the Poetry setup step (e.g. `snok/install-poetry@v1` or `pipx install poetry==A.B.C`) and note the pinned version.

## Workflow

### 1. Check Current pySigma Requirement

Fetch the pySigma pyproject.toml and identify the Python version:

```
# Look for: python = "^X.Y" under [tool.poetry.dependencies]
```

### 2. Update pyproject.toml

Location: `/pyproject.toml`

Update the Python dependency under `[tool.poetry.dependencies]`:

```toml
[tool.poetry.dependencies]
python = "^X.Y"
```

### 3. Update devcontainer.json

Location: `/.devcontainer/devcontainer.json`

Update the container image to match:

```json
{
  "image": "mcr.microsoft.com/devcontainers/python:X.Y"
}
```

### 4. Update GitHub Workflows

Locations:
- `/.github/workflows/release.yml`
- `/.github/workflows/test.yml`

Update any Python version references to match `X.Y`, including:
- `actions/setup-python` version
- Matrix `python-version` entries
- Any other pinned Python references

If a Poetry version is pinned, align it to pySigma’s recommended Poetry version.

### 5. Regenerate Lockfile

Update Poetry lockfile without changing other dependencies:

```
poetry lock --no-update
```

### 6. Verify Compatibility

Run tests to ensure the new Python version works:

```
poetry run pytest
```

## Best Practices

- Always check pySigma's current requirement before updating
- Update all Python version references together to maintain consistency
- Keep GitHub workflow Python and Poetry versions aligned with pySigma
- Rebuild the devcontainer after updating to apply changes
- Run the full test suite to catch any compatibility issues
