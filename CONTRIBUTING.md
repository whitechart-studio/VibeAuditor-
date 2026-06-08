# Contributing to vibeAuditor

Thanks for helping make AI-built apps safer to ship.

## Good First Contributions

- Add framework-specific rules with clear examples.
- Improve finding messages and remediation text.
- Add scanner parsers that normalize external output into vibeAuditor findings.
- Add tests for false positives and false negatives.
- Create GitHub Actions and CI examples.

## Rule Guidelines

Rules should be high-signal and explain the risk in plain language. A good rule
has:

- a stable `VA###` id
- severity
- category
- short evidence
- a concrete fix
- one intentionally vulnerable example
- one safe example

Regex rules are welcome for obvious mistakes. For more complex behavior, prefer
small parsers or language-aware adapters.
