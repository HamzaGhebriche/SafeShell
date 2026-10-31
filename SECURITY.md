# Security policy

SafeShell v0.1.0-alpha (package 0.1.0a1) is an experimental review candidate. No supported production release or independent audit
is claimed. Keep the host kernel, bubblewrap, libseccomp and Python security-patched.

Report suspected bypasses through
[GitHub private vulnerability reporting](https://github.com/HamzaGhebriche/SafeShell/security/advisories/new).
If the private form is unavailable, open only a public request for a private reporting channel,
without exploit details or secrets; no email address is advertised. Do not publish working
exploits or secrets in public issues. Include OS/kernel/backend versions,
`safeshell doctor --json`, a minimal reproduction with dummy files, expected/actual behavior,
and whether another process could modify the workspace concurrently.

Never send real credentials or raw private history. Consult [the threat model](docs/THREAT_MODEL.md)
for the supported boundary and known limitations. Runtime setup failure must never cause host
fallback; treat any such behavior as a critical vulnerability.
