# Security Policy

vibeAuditor is a security tool, but it is still early-stage software.

## Reporting Vulnerabilities

Please do not open public issues for exploitable vulnerabilities in vibeAuditor
itself. Use a private disclosure channel once the project has a public repository.

Include:

- affected version or commit
- reproduction steps
- impact
- suggested fix, if known

## Scanner Safety

vibeAuditor runs locally and does not send source code to a remote service. When
`--external` is used, it invokes local scanner binaries installed on your machine.
