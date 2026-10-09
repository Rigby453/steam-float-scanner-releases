# Seattle read-only diagnostics from Cloud via GitHub Actions

Install the workflow and fixed Python runner in the release repository.
Create the `seattle-diagnostics` environment, restricted to the exact `main`
branch, and provision `SFS_SEATTLE_SSH_PRIVATE_KEY` only as its environment
secret. No reviewer is imposed. The workflow pins the entire runner's SHA256;
a dispatcher with Contents write but no Workflows write cannot swap in a
secret-exfiltrating runner. Keep the SSH and signing environments separate.

The current key grants Administrator access. The runner executes only the
fixed read-only command in its source, but the credential itself is not
read-only. Environment administrators and authorized workflow maintainers
remain trusted. A dedicated server-enforced read-only key would reduce this
authority and requires a separate server configuration change.

Cloud triggers `seattle-diagnostics.yml` on `main`, with no command, path, or
host input. SSH originates from the GitHub-hosted runner; it does not depend
on the Cloud container supporting raw TCP/22. Actual GitHub-runner reachability
must still pass before calling access verified.

The command checks pinned host identity, installed EXE version, Scanner
process count, and code mentions in at most 500 lines from the last 256KiB of
the log. It never
starts, stops, installs, changes settings, arms AUTO_BUY, logs in, accepts
Guard, or buys. It reads no database or secret vault. Raw logs, process
command lines, passwords, key contents, and SSH stderr never reach stdout.
Only validated identities, version/timestamps, and whitelisted counters do.

The key is removed from child-process environments, stored briefly in a
private temporary file with mode 0600, and removed with that directory.
Host-key verification stays enabled; password and forwarding are disabled.
The current outward HTTPS IPv4 is observed before SSH. It may differ from
raw SSH egress and is not used to change firewall restrictions.

Dispatch:

```bash
gh workflow run seattle-diagnostics.yml --repo Rigby453/steam-float-scanner-releases --ref main
```

Wait for the exact run to complete and read its sanitized JSON. Code mentions
are historical evidence only: they do not prove current purchase readiness or
successful AUTO_BUY. Log modification time and installed version distinguish
old server state from the newly published release. Failed SSH proves only
that this attempted route failed. Real GUI/Steam checks remain separate.

Before commit, replace the workflow hash placeholder with SHA256 of the
exact LF-encoded Python file. No secrets belong in the checkout or artifacts.
