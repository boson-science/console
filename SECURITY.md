# Security Policy

This repository is an independent, community-maintained fork of MinIO Console.
It is not affiliated with MinIO, Inc. Please do not report issues in this fork to
MinIO, Inc.

## Supported Versions

Security fixes are made on the `main` branch, which tracks console v1.7.6 plus
the downstream fixes listed in [FORK.md](FORK.md). The console ships embedded in
[boson-science/minio](https://github.com/boson-science/minio), and fixes reach
users through that project's releases.

## Reporting a Vulnerability

Report vulnerabilities privately through
[GitHub's private vulnerability reporting](https://github.com/boson-science/console/security/advisories/new)
for this repository. Please do not open a public issue.

Include a description of the issue, its impact (for example authentication
bypass or information disclosure), the steps to reproduce it, and any
assumptions the exploit makes (such as needing valid credentials).

## Disclosure Process

1. A maintainer confirms and reproduces the report, then replies to accept or
   decline it with a reason.
2. Similar code paths are audited for the same problem.
3. A fix with a regression test is prepared on a private advisory fork and
   merged to `main`.
4. A release of [boson-science/minio](https://github.com/boson-science/minio)
   that includes the fix is published, together with a GitHub security
   advisory. Reporters are credited only if they ask to be.
