# Security Policy

## Supported Versions

Mempool Radar is currently maintained on the `master` branch. Security fixes are
applied to the latest release and are not backported to older versions.

## Reporting a Vulnerability

Please do not disclose suspected vulnerabilities in a public issue, discussion,
or pull request.

Report vulnerabilities privately through [GitHub Security
Advisories](https://github.com/benthecarman/mempool-radar/security/advisories/new).
Include, when possible:

- A description of the vulnerability and its potential impact
- The affected version or commit
- Steps or a minimal proof of concept that reproduces the issue
- Any suggested mitigation or fix

You should receive an acknowledgement within seven days. After the report has
been investigated, the maintainer will share whether it is accepted and, when
possible, an expected remediation timeline. Please allow time for a fix to be
released before publicly disclosing the issue.

## Operational Security

Mempool Radar connects to Bitcoin Core and optional notification services. Keep
RPC credentials, cookie files, and API or bot tokens out of source control and
logs. Bind Bitcoin Core RPC and ZMQ interfaces only to trusted networks, and run
the service with the minimum filesystem and network access it requires.

Alerts produced by Mempool Radar are informational. They are not a substitute
for Bitcoin Core's transaction validation or consensus rules.
