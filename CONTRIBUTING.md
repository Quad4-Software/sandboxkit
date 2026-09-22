# Contributing

Report bugs through GitHub issues. Security reports go to
security@quad4.io (see SECURITY.md).

## Setup

    uv sync
    make check

`make check` runs the full local gate: ruff lint and format, bandit,
mypy strict, ty, and pytest with coverage.

## Conventions

- No runtime dependencies unless the project genuinely needs one.
- Source files start with the SPDX license identifier.
- Public API changes need tests.
- Commit messages: short, imperative, formal.
