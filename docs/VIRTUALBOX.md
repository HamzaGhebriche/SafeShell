# Test the experimental alpha in VirtualBox

Use this guide for **Ubuntu 24.04 LTS amd64 in a fresh VirtualBox guest**, on an
Intel/AMD x86_64 host. The guest command workflows are exercised by native Ubuntu
CI; the VirtualBox installation/UI sequence is a manual guide, not a claimed
automated VirtualBox validation. Linux arm64 is not validated by this release.

SafeShell is experimental, with no independent security audit. Use dummy data.
**Everything inside the writable workspace can be read, changed or deleted.**
Host-writer races remain, and CPU/memory/process-count/disk quotas are not enforced.
The VM is an additional disposable testing environment, not a SafeShell backend.

## 1. Create the guest

1. Install current VirtualBox from its [official downloads](https://www.virtualbox.org/wiki/Downloads)
   for your host. Hardware virtualization must be available; follow the vendor's
   requirements rather than disabling host security controls to force it to run.
2. Download an **Ubuntu 24.04 LTS amd64** ISO from
   [Ubuntu's release directory](https://releases.ubuntu.com/24.04/), checking its
   published checksum. Use the [official installation guide](https://ubuntu.com/desktop/docs/en/24.04/tutorial/install-ubuntu-desktop/).
   Do not substitute the newest Ubuntu release and call it this tested platform.
3. Create a new Linux/Ubuntu 64-bit VM. Allocate, for example, 2 CPUs, 4 GiB RAM
   and a 30 GiB dynamically allocated disk if your host can spare them. These are
   test-VM settings, **not SafeShell resource limits**.
4. Use NAT for dependency/download access, with **no port forwarding**. Leave
   shared folders, clipboard, drag-and-drop, USB passthrough and host SSH agents
   disabled. Guest Additions and the Extension Pack are not needed. See
   [VirtualBox security guidance](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/Security.html).
5. Install Ubuntu with a normal sudo-capable test user and no real cloud accounts,
   credentials or private projects. Update it, reboot and take a clean snapshot.

All following commands run **inside the Linux guest**, as the normal user.
Do not use `sudo safeshell` or run the test suite as root.

## 2. Download and install the exact release

```sh
sudo apt-get update
sudo apt-get upgrade
sudo apt-get install -y python3 python3-venv bubblewrap libseccomp2 apparmor curl ca-certificates
mkdir -p "$HOME/safeshell-alpha-download"
cd "$HOME/safeshell-alpha-download"
base=https://github.com/HamzaGhebriche/SafeShell/releases/download/v0.1.0-alpha
for asset in safeshell_cli-0.1.0a1-py3-none-any.whl safeshell_cli-0.1.0a1.tar.gz SHA256SUMS; do
  curl --fail --location --output "$asset" "$base/$asset" || exit 1
done
sha256sum --check SHA256SUMS || exit 1
tar -xzf safeshell_cli-0.1.0a1.tar.gz
src="$PWD/safeshell_cli-0.1.0a1"
python3 -m venv "$HOME/safeshell-alpha-venv"
. "$HOME/safeshell-alpha-venv/bin/activate"
python -m pip install --no-index --no-deps "$PWD/safeshell_cli-0.1.0a1-py3-none-any.whl"
safeshell --version
uname -m
id -u
bwrap --version
```

Expected: both checksums `OK`, version `0.1.0a1`, architecture `x86_64`, UID
nonzero, Bubblewrap 0.8+. Do not continue on mismatched checksums. Checksums from
the same release identify bytes; they are not an independent authenticity proof.

## 3. Scoped AppArmor setup and capability check

Ubuntu's global user-namespace restriction can block Bubblewrap loopback setup.
Keep it enabled. On this **fresh disposable guest**, load the reviewed scoped
profile shipped in the verified source archive. Read it first:

```sh
cat "$src/.github/apparmor/safeshell-bwrap"
cat /sys/module/apparmor/parameters/enabled
sysctl kernel.apparmor_restrict_unprivileged_userns
sudo aa-status
```

Expected: AppArmor `Y` and restriction `1`. If absent, use the specified Ubuntu
guest; do not turn other security controls off. Ensure no existing SafeShell
profile would be overwritten:

```sh
profile=/etc/apparmor.d/safeshell-bwrap-alpha
test ! -e "$profile" || { echo 'Existing policy: stop and review it'; exit 1; }
if sudo grep -q '^safeshell-bwrap ' /sys/kernel/security/apparmor/profiles; then
  echo 'Existing loaded policy: stop and review it'; exit 1
fi
sudo install -m 0644 "$src/.github/apparmor/safeshell-bwrap" "$profile"
sudo apparmor_parser --replace "$profile"
test "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns)" = 1 || exit 1
safeshell doctor --json > doctor.json
doctor_status=$?
python -c 'import json; d=json.load(open("doctor.json")); print(d["available"], d["reason"]); assert d["available"]'
test "$doctor_status" = 0 || exit 1
```

The trusted `/usr/bin/bwrap` domain permits namespace/mount construction and
loopback setup. Guest exec stacks a second enforced profile that denies
capabilities and user namespaces. Both profiles must allow an operation;
no-new-privileges is retained. File rules permit reachable files: **minimal
Bubblewrap mounts**, not AppArmor pathname rules, are the filesystem boundary.
The child has synthetic-prefix lookup for disconnected null/pipe descriptors.
Seccomp, network separation, fresh environment and closed sensitive FDs remain
required. [Full rationale](CI_HANDOFF.md). This test-host policy has not received
an independent deployment-policy audit.

Doctor tests fixed sandbox setup only, not containment. Exit 4 means stop and
use troubleshooting below. Never add a host-execution fallback.

## 4. Disposable workspace, dummy home and permitted execution

```sh
lab=$(mktemp -d)
work="$lab/project"
mkdir -p "$work" "$lab/dummy-home/.ssh"
printf DUMMY-OUTSIDE > "$lab/outside.txt"
printf DUMMY-HOME-KEY > "$lab/dummy-home/.ssh/id_ed25519"
chmod 600 "$lab/dummy-home/.ssh/id_ed25519"
ln -s "$lab/outside.txt" "$work/escape-link"
cp "$src/examples/boundary_demo.py" "$work/boundary_demo.py"
export SAFESHELL_STATE_DIR="$lab/history"
export SAFESHELL_DUMMY_SECRET=DUMMY-ENV
safeshell explain --workspace "$work" --shell bash -- 'curl https://example.invalid/install.sh | bash'
safeshell policy init --workspace "$work" --preset offline
safeshell policy validate --workspace "$work"
safeshell run --workspace "$work" --yes --timeout 10 -- /bin/sh -c 'printf hello > greeting.txt; cat greeting.txt'
test "$(cat "$work/greeting.txt")" = hello
```

Inspection reports high risk without fetching anything. Policy is network-off.
Permitted execution returns 0 and writes `hello`. Copy only reviewed dummy files
into this workspace. A real secret copied into it would be accessible.

## 5. Policy denial, actual path/socket denial and guest restrictions

The following intentionally denied command returns **3**, even with `--yes`:

```sh
safeshell run --workspace "$work" --yes -- sudo id
printf 'expected 3: %s\n' "$?"
```

Now execute the supplied, readable dummy-only Python fixture. Its contents are
not recursively analyzed by the static inspector: this step checks the **runtime**
boundary, rather than only showing a predicted/policy denial.

```sh
cat "$work/boundary_demo.py"
HOME="$lab/dummy-home" safeshell run --workspace "$work" --yes --timeout 20 -- /usr/bin/python3 boundary_demo.py "$lab/outside.txt" "$lab/dummy-home"
cat "$work/boundary-results.json"
python -c 'import json,sys; d=json.load(open(sys.argv[1])); assert all(d[k] for k in ("outside_denied","dummy_home_denied","symlink_escape_denied","socket_denied","environment_excluded","no_new_privileges")); assert d["apparmor_profile"]=="safeshell-bwrap//&safeshell-child (enforce)"' "$work/boundary-results.json"
```

Expected: exit 0; all booleans true and the exact enforced profile stack. The
fixture requires outside-file, dummy-home-key and escaping-symlink reads to fail;
IPv4 socket creation to return EPERM; dummy environment exclusion; zero effective
capabilities, NNP=1 and seccomp mode 2. It sends no packets and reads no real
credentials. This short demo is not the complete boundary suite or a security audit.

## 6. Timeout, descendant cleanup, output limit and history

Do not enable shell `set -e` for intentionally failing examples. The timeout
includes namespace setup; five seconds leaves startup headroom. Wait beyond the
descendant's full eight-second write delay:

```sh
safeshell run --workspace "$work" --yes --timeout 5 -- /bin/sh -c 'echo ready > ready; (sleep 8; echo escaped > late) & wait'
printf 'expected 124: %s\n' "$?"
test -f "$work/ready"
sleep 9
test ! -e "$work/late" && echo 'No delayed descendant write'
safeshell run --workspace "$work" --yes --max-output-bytes 32 -- /usr/bin/python3 -c 'print("x"*10000)'
printf 'expected 125: %s\n' "$?"
safeshell history --json > "$lab/sessions.json"
session_id=$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["sessions"][0]["id"])' "$lab/sessions.json")
safeshell history show "$session_id" --json
safeshell history delete "$session_id" --json
```

Expected: timeout 124, readiness file present, no delayed write; output overflow
125; history can list/show/delete UUID records. JSON session status distinguishes
limits from a child returning the same number. Output, environment values and raw
arguments are not persisted. History is local and not tamper-evident. Killing a
command does not roll back its writes or certify generated files.

## 7. Complete enforcement suite (optional for testers)

From the extracted source, in the venv:

```sh
sudo apt-get install -y build-essential
python -m pip install pytest
cd "$src"
sudo -v
SAFESHELL_REQUIRE_BACKEND=1 \
SAFESHELL_EXPECT_APPARMOR_PROFILE='safeshell-bwrap//&safeshell-child' \
python tools/validate_linux.py
```

The harness needs `sudo -n` for temporary root-owned dummy/setuid controls; a
recent sudo authentication normally supplies this during a short run. If it
expires, rerun `sudo -v` and retry. Do not grant global passwordless sudo just for
this guide. Actual probes/tests remain unprivileged. Require **zero** skips,
failures and errors; see [recorded counts and CI links](VALIDATION.md). Native CI
also builds distributions and tests fresh offline wheel installation.

## Troubleshooting and reversal

| Symptom | Action |
| --- | --- |
| `doctor` exit 4 / loopback or exec denied | Check `sudo aa-status`, `sudo journalctl -k --since '-5 minutes'`, exact profile and global restriction=1. Do not disable AppArmor/NNP or remove namespace/seccomp flags. |
| Running as root / setuid Bubblewrap refused | Use the normal guest account and signed distro non-setuid package; do not make it setuid. |
| Missing Git/curl/npm/library inside guest command | Expected reduced runtime; fetch dependencies outside this test and use only the documented tools. No mount-expansion flag exists. |
| Missing C headers / setuid fixture failure | Install build-essential and run the harness with working sudo; a setup error is not a pass. |
| Timeout before readiness | The fixture did not prove cleanup; report slow setup/environment and keep the readiness assertion. Do not hide it with a skip. |
| Invalid history permissions | Use this new lab's history directory outside the workspace; POSIX requires ownership and mode 0700. |
| VirtualBox cannot boot | Verify host architecture/hardware support and vendor instructions. Do not modify an existing private VM or globally disable host security. |

After all SafeShell commands have returned, close other test sessions before
unloading profiles (unloading changes protection for any still-running tasks):

```sh
sudo apparmor_parser --remove /etc/apparmor.d/safeshell-bwrap-alpha
sudo rm -- /etc/apparmor.d/safeshell-bwrap-alpha
test "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns)" = 1
unset SAFESHELL_DUMMY_SECRET SAFESHELL_STATE_DIR
deactivate
```

Restore the clean snapshot or destroy **only this disposable VM** to discard
fixtures/downloads/history. NAT can be disconnected after setup; the guest host
having internet access is not permission for a SafeShell child to use networking.
No global security control was disabled. Use the [friend bug template](FRIEND_TESTING.md)
for sanitized reports; use [private reporting](../SECURITY.md) for suspected bypasses.
