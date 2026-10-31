"""Record the actual guest namespace inventory using an empty disposable workspace."""

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

SOURCE = """
import json,os,pathlib
try: apparmor_profile=pathlib.Path('/proc/self/attr/current').read_text().strip()
except OSError: apparmor_profile='unavailable'
files,dirs,links=[],[],{}
for folder,names,entries in os.walk('/',followlinks=False):
    names[:]=[name for name in names if str(pathlib.Path(folder)/name) not in ('/proc','/dev','/tmp','/home','/workspace')]
    for name in names+entries:
        path=pathlib.Path(folder)/name
        if path.is_symlink(): links[str(path)]=os.readlink(path)
        elif path.is_file(): files.append(str(path))
        elif path.is_dir(): dirs.append(str(path))
print(json.dumps({'runtime_files':sorted(files),'directories':sorted(dirs),'symlinks':links,
 'root_entries':sorted(os.listdir('/')),'proc_top_level':sorted(os.listdir('/proc')),
 'dev_entries':sorted(os.listdir('/dev')),'workspace_entries':os.listdir('/workspace'),
 'mountinfo':pathlib.Path('/proc/self/mountinfo').read_text(),
 'apparmor_profile':apparmor_profile,
 'dynamic_scope':'proc/dev and writable ephemeral/workspace contents can change; not a secrecy guarantee for kernel metadata'}))
"""


def main():
    from safeshell import backend, policy

    blocks = []
    with tempfile.TemporaryDirectory(prefix="safeshell-inventory-") as workspace:
        status = backend.run(
            Path(workspace), ["/usr/bin/python3", "-c", SOURCE], policy.Policy(), blocks.append, 20
        )
    if status:
        raise RuntimeError(f"Inventory failed: {status}: {b''.join(blocks)!r}")
    inventory = json.loads(b"".join(blocks))
    expected = {target for _, target in backend.runtime.profile()}
    if set(inventory["runtime_files"]) != expected:
        raise RuntimeError("Observed runtime files differ from the explicit mount inventory")
    print(json.dumps(inventory, indent=2))


if __name__ == "__main__":
    main()
