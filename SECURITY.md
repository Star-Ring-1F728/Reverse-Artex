# Security

English · [한국어](SECURITY.ko.md)

Reverse Artex is built for defensive investigation and protection of owned or explicitly authorized applications. ARTEX simulations validate defensive behavior on owned synthetic fixtures.

Reverse Artex 0.1.0-beta.1 is a beta for controlled evaluation. There is no published support lifetime or production security certification. Use the latest reviewed source or a verified archive and check [known limitations](docs/COMPATIBILITY.md).

## Deployment boundary

The default console listens on loopback and authenticates access using a process-scoped console key. Sensor credentials are separate and persist in private configuration. Keep access URLs, configuration, `.env`, tokens, signed approvals, and collected evidence out of public reports. The project does not configure an internet-facing administrator login or TLS proxy for you. Use an authenticated tunnel for remote administration and review [operations (Korean)](docs/OPERATIONS.md).

Automatic blocking, real host isolation, and autonomous response are off by default. Optional policy and SDK integrations require explicit trust, credentials, identities, scope, and review. Local-model output is untrusted interpretation of evidence, not proof that a system is secure. Test only applications and infrastructure you are authorized to administer.

## Reporting a vulnerability

This repository does not currently advertise a verified private disclosure mailbox or promise that GitHub private vulnerability reporting is enabled. Do not place an exploit, credentials, personal data, private evidence, or a live target in a public issue. First use an independently verified private contact for the repository owner, if one is available. If no private channel is available, a public report should only ask for a private contact and describe the affected component at a high level, without details that enable exploitation.

For a private report, include the source revision/version, OS and filesystem, affected optional profile, expected and observed behavior, and the smallest synthetic local reproduction. Share redacted configuration shapes rather than credential values. Describe whether existing trust or authorization must already be compromised. There is no guaranteed response time or bounty program.

## If an installation is affected

Stop the affected process and preserve its original logs and data before changing the installation. Disable any explicitly enabled response integration. Review and revoke active policies through the configured controller; cancelling an AI investigation does not necessarily revoke a policy already applied. Rotate exposed credentials in the systems that issue them. Restore only from a backup whose evidence and configuration can be verified. See [operations (Korean)](docs/OPERATIONS.md) and the relevant integration guide.
