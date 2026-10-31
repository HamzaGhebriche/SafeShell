# Writable workspaces and concurrent writers

Granting `/workspace` grants every readable/writable included file, including Git metadata,
credentials, hooks, package scripts and outputs later used by host tools. Runtime restrictions
protect unmounted host paths; they do not protect granted data. A successful command can still
leave malicious outputs for later host execution. Do not trust generated artifacts automatically.

For untrusted code, stop host watchers/agents and make a private disposable copy. On GNU/Linux:

```sh
scratch=$(mktemp -d)
cp -R --one-file-system --no-preserve=links -- ./project "$scratch/project"
safeshell run --workspace "$scratch/project" --timeout 10 --max-output-bytes 65536 --yes -- /bin/sh -c 'printf demo > result.txt'
```

Inspect/copy back only intended outputs after review; delete the disposable directory when
finished. This example does not remove secrets from the copy: review what you copy before
granting it. `cp -R` preserves symlinks rather than following them; preflight rejects copied
special objects. Avoid `cp -al`, shared hardlinks and local Git clones that hardlink object
stores. Do not use a home directory, credential store, system root, FUSE/network filesystem or
active service-data directory as a workspace. Keep audit history outside it.

Known races: resolving the path, scanning contents, checking nested mounts, reading policy,
analyzing executable arguments and attaching mounts are separate operations. The same policy
object is used after approval, but code/workspace data can change. A concurrent host process
with the same UID can rename directories, introduce hardlinks/mounts/special files, replace
executables or alter configuration between checks and attachment. Such processes are outside
the supported boundary. Runtime/package updates by root must also not race a session.

A private copy reduces accidental interaction with cooperating host tools. It is not protection
from a malicious same-UID host process, nor an atomic snapshot. Race-resistant attachment,
immutable runtime images and filesystem snapshots are not implemented in this alpha.
