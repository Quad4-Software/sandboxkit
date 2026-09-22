# python-library-template

[![CI](https://github.com/Quad4-Software/python-library-template/actions/workflows/ci.yml/badge.svg)](https://github.com/Quad4-Software/python-library-template/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Quad4-Software/python-library-template/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Quad4-Software/python-library-template)
[![License: 0BSD](https://img.shields.io/badge/license-0BSD-blue)](LICENSE)

Quad4 template for dependency-free typed Python libraries.

## Contents

- `src/` layout with Hatchling, dynamic version from `__init__.py`
- Fully typed, `py.typed` shipped, mypy strict over `src` and `tests`
- ruff lint + format, bandit, pytest
- `make check` runs the full local gate
- GitHub Actions: CI matrix 3.10-3.14, CodeQL, OpenSSF Scorecard with SARIF
  upload, zizmor, dependency review, tag-triggered PyPI release with build
  provenance and attestations
- All actions pinned to commit SHAs, least-privilege permissions,
  `step-security/harden-runner` on every job, Dependabot with 7-day cooldown

## Using this template

1. Create a repository from this template (GitHub "Use this template" button)
   or copy the tree.
2. Rename the package:

   ```sh
   mv src/packagename src/mypkg
   mv tests/test_packagename.py tests/test_mypkg.py
   grep -rl packagename . | xargs sed -i 's/packagename/mypkg/g'
   ```

3. Update `pyproject.toml`: description, keywords, classifiers, repository URL.
4. Update `SECURITY.md` if the contact address differs.
5. For releases, configure a PyPI trusted publisher for the repository
   (workflow `release.yml`, environment `pypi`), then tag `v*` to publish.

License: 0BSD.
