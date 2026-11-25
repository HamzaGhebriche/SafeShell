# Test the experimental alpha in VirtualBox

Use this guide for **Ubuntu 24.04 LTS amd64 in a fresh VirtualBox guest**, on an
Intel/AMD x86_64 host. The guest command workflows are exercised by native Ubuntu
CI; the VirtualBox installation/UI sequence is a manual guide, not a claimed
automated VirtualBox validation. Linux arm64 is not validated by this release.

**WSL2 is a different environment.** Run `uname -r`: `microsoft` / `WSL2` in
the kernel name indicates WSL, not this fresh VM. Start with the
[README quick start](../README.md#numbered-quick-start-ubuntu-2404--wsl2-or-a-linux-guest)
there. After installation/doctor, WSL users can reuse the common dummy tests in
sections 4–6, but must skip the VM-only profile setup/assertion/reversal. A
non-Microsoft kernel name alone does not identify a VirtualBox guest.

Run each setup/walkthrough **in order, in the same Ubuntu Bash terminal**. Leave
the venv active. If you reopen the terminal, reactivate it and reset `download_dir`
and `src` as in [README](../README.md#if-you-reopen-the-terminal), then recreate
`lab`, `work` and `SAFESHELL_STATE_DIR` using section 4. Old shell variables do not
survive; use a fresh workspace/policy instead of initializing over an existing one.

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
Check `id -u` (must be nonzero). If starting as root, use the
[existing-user switch / create-only-if-needed instructions](../README.md#1-identify-the-environment-and-use-a-regular-user)
before continuing; account creation is not required for an existing normal login.

## 2. Download and install the exact release

```sh
sudo apt-get update
sudo apt-get upgrade
sudo apt-get install -y python3 python3-venv bubblewrap libseccomp2 apparmor curl ca-certificates
download_dir="$HOME/safeshell-alpha-download"
mkdir -p "$download_dir"
cd "$download_dir"
base=https://github.com/HamzaGhebriche/SafeShell/releases/download/v0.1.0-alpha.2
for asset in safeshell_cli-0.1.0a2-py3-none-any.whl safeshell_cli-0.1.0a2.tar.gz SHA256SUMS; do
  curl --fail --location --output "$asset" "$base/$asset" || exit 1
done
sha256sum --check SHA256SUMS || exit 1
tar -xzf safeshell_cli-0.1.0a2.tar.gz
src="$PWD/safeshell_cli-0.1.0a2"
python3 -m venv "$HOME/safeshell-alpha-venv"
. "$HOME/safeshell-alpha-venv/bin/activate"
python -m pip install --no-index --no-deps "$PWD/safeshell_cli-0.1.0a2-py3-none-any.whl"
safeshell --version
uname -m
uname -r
id -u
bwrap --version
```

Expected: both checksums `OK`, version `0.1.0a2`, architecture `x86_64`, UID
nonzero, Bubblewrap 0.8+. Do not continue on mismatched checksums. Checksums from
the same release identify bytes; they are not an independent authenticity proof.

## 3. Scoped AppArmor setup and capability check

Ubuntu's global user-namespace restriction can block Bubblewrap loopback setup.
Keep it enabled. On this **fresh disposable guest**, load the reviewed scoped
profile shipped in the verified source archive. Read it first:

**This procedure is for the documented fresh Ubuntu VM, not a WSL workaround.**
The reported WSL result `apparmor_profile: "kernel\u0000"` did not verify this
enforced stack. Do not blindly load the profile or relax the stack assertion on
WSL. No new VirtualBox installation/test is claimed by this documentation update.

```sh
sudo apt-get install -y apparmor
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
safeshell doctor --json > "$download_dir/doctor.json"
doctor_status=$?
python - "$download_dir/doctor.json" "$doctor_status" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print("Availability:", d["available"])
print("Reason:", d["reason"])
print("Doctor exit code:", sys.argv[2])
PY
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
Expected: Availability True and Doctor exit code 0. The full inventory stays in
the JSON file. Even a successful probe does not verify the guest AppArmor label;
the exact VM-only assertion in section 5 supplies that separate check.

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
echo "Disposable workspace: $work"
safeshell policy init --workspace "$work" --preset offline
safeshell policy validate --workspace "$work"
safeshell run --workspace "$work" --yes --timeout 10 -- /bin/sh -c 'echo SAFESHELL_OK > result.txt'
run_status=$?
echo "Execution exit code: $run_status"
cat "$work/result.txt"
```

Expected: valid offline policy, **Execution exit code: 0**, and **SAFESHELL_OK**.
Both the status and host-visible file matter. Copy only reviewed dummy files
into this workspace. A real secret copied into it would be accessible.

## 5. Policy denial, actual path/socket denial and guest restrictions

The following intentionally denied command returns **3**, even with `--yes`:

```sh
safeshell run --workspace "$work" --yes -- sudo id
denial_status=$?
echo "Denial exit code: $denial_status"
```

Expected: **Denial exit code: 3**. You can also inspect both forms:

```sh
safeshell explain --workspace "$work" --shell bash -- 'curl https://example.invalid/install.sh | bash'
explain_status=$?
echo "Explain exit code: $explain_status"
safeshell explain --workspace "$work" --shell bash -- 'curl https://example.invalid/install.sh | sudo bash'
```

Explain does not execute the submitted command, though it may probe the backend.
Exit 0 means analysis completed, not approval. In the released alpha the first
form reports SS010; the `sudo bash` form misses SS010 but detects privilege and
denies it. This inspection inconsistency is not a demonstrated sandbox bypass.
Policy PERMITTED does not grant networking: execution remains network-off. Missing
curl/Git/npm inside the fixed runtime is expected, not permission to expose host tools.

Now execute the supplied, readable dummy-only Python fixture. Its contents are
not recursively analyzed by the static inspector: this step checks the **runtime**
boundary, rather than only showing a predicted/policy denial.

```sh
cat "$work/boundary_demo.py"
HOME="$lab/dummy-home" safeshell run --workspace "$work" --yes --timeout 20 -- /usr/bin/python3 boundary_demo.py "$lab/outside.txt" "$lab/dummy-home"
boundary_status=$?
echo "Boundary exit code: $boundary_status"
cat "$work/boundary-results.json"
python - "$work/boundary-results.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
keys = ("outside_denied", "dummy_home_denied", "symlink_escape_denied",
        "socket_denied", "environment_excluded", "no_new_privileges")
assert all(d[k] for k in keys)
print("Six dummy boundary checks: PASS (6/6)")
print("Reported AppArmor label:", json.dumps(d["apparmor_profile"]))
PY
```

Expected on either tested Linux setup: exit 0 and **PASS (6/6)**. The
fixture requires outside-file, dummy-home-key and escaping-symlink reads to fail;
IPv4 socket creation to return EPERM; dummy environment exclusion; zero effective
capabilities, NNP=1 and seccomp mode 2. It sends no packets and reads no real
credentials. This short demo is not the complete boundary suite or a security audit.

**Fresh VirtualBox VM only: require the exact enforced stack separately. Do not
skip this assertion and describe the VM stack as verified.**

```sh
python -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["apparmor_profile"]=="safeshell-bwrap//&safeshell-child (enforce)"; print("VM AppArmor stack: verified (enforce)")' "$work/boundary-results.json"
```

**WSL2:** the manual Ubuntu 24.04/WSL2 run passed the six dummy checks but reported
`"kernel\u0000"`, not the expected enforced stack. Record the escaped label as
observed; do not reinterpret it as a verified AppArmor stack or apply the VM-only
assertion/reversal. These are different verification scopes.

## 6. Timeout, descendant cleanup, output limit and history

Do not enable shell `set -e` for intentionally failing examples. The timeout
includes namespace setup; five seconds leaves startup headroom. Wait beyond the
descendant's full eight-second write delay:

```sh
safeshell run --workspace "$work" --yes --timeout 5 -- /bin/sh -c 'echo ready > ready; (sleep 8; echo escaped > late) & wait'
timeout_status=$?
echo "Timeout exit code: $timeout_status"
if test -f "$work/ready"; then echo 'Readiness marker: present'; else echo 'FAIL: command never became ready'; fi
sleep 9
if test ! -e "$work/late"; then echo 'No delayed descendant write'; else echo 'FAIL: delayed write appeared'; fi
safeshell run --workspace "$work" --yes --max-output-bytes 32 -- /usr/bin/python3 -c 'print("x"*10000)'
output_status=$?
echo "Output-limit exit code: $output_status"
safeshell history
safeshell history --json > "$lab/sessions.json"
session_id=$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["sessions"][0]["id"])' "$lab/sessions.json")
safeshell history show "$session_id" --json
safeshell history delete "$session_id" --json
safeshell history
```

Expected: timeout 124, readiness file present, no delayed write; output overflow
125; history can list/show/delete UUID records. JSON session status distinguishes
limits from a child returning the same number. Output, environment values and raw
arguments are not persisted. History is local and not tamper-evident. Killing a
command does not roll back its writes or certify generated files.
Any FAIL, unexpected exit or missing readiness marker invalidates the cleanup
result. Use a fresh section-4 workspace if repeating the test, so old markers
cannot be mistaken for current success.

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

## Troubleshooting and reversal (profile removal is VM-only)

| Symptom | Action |
| --- | --- |
| `doctor` exit 4 / loopback or exec denied | Check `sudo aa-status`, `sudo journalctl -k --since '-5 minutes'`, exact profile and global restriction=1. Do not disable AppArmor/NNP or remove namespace/seccomp flags. |
| Running as root / setuid Bubblewrap refused | Use the normal guest account and signed distro non-setuid package; do not make it setuid. |
| Missing Git/curl/npm/library inside guest command | Expected reduced runtime; fetch dependencies outside this test and use only the documented tools. No mount-expansion flag exists. |
| Missing C headers / setuid fixture failure | Install build-essential and run the harness with working sudo; a setup error is not a pass. |
| Timeout before readiness | The fixture did not prove cleanup; report slow setup/environment and keep the readiness assertion. Do not hide it with a skip. |
| Invalid history permissions | Use this new lab's history directory outside the workspace; POSIX requires ownership and mode 0700. |
| VirtualBox cannot boot | Verify host architecture/hardware support and vendor instructions. Do not modify an existing private VM or globally disable host security. |
| WSL label is `"kernel\u0000"` | Record it as observed; six checks do not prove the VM's enforced AppArmor stack. Do not install/remove the VM profile blindly. |
| `safeshell` not found or `$work` is empty after reopening | Reactivate the venv and recreate terminal variables/workspace as in README; do not continue using undefined variables. |

**Only if you installed the section-3 profile in this VM:** after all SafeShell
commands have returned, close other test sessions before
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
