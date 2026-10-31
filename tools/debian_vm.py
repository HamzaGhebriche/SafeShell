"""Disposable native Debian/KVM validation, with official HTTPS image + SHA512 checks.

Run on a Linux host with /dev/kvm, qemu-system-x86_64, qemu-img, cloud-localds,
ssh-keygen, ssh and scp. No host folder, agent or real SSH key is shared with the guest.
"""

import argparse
import hashlib
import json
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

BASE = "https://cloud.debian.org/images/cloud/bookworm/latest/"
IMAGE = "debian-12-genericcloud-amd64.qcow2"


def call(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def digest(path):
    result = hashlib.sha512()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def prepare_results(path):
    if path.exists() and any(path.iterdir()):
        raise SystemExit(
            "Results directory is not empty; choose a fresh --results path to avoid stale evidence"
        )
    path.mkdir(parents=True, exist_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Local source distribution archive")
    parser.add_argument("--cache", type=Path, default=Path.home() / ".cache/safeshell-vm")
    parser.add_argument("--results", type=Path, default=Path("validation-results/debian"))
    parser.add_argument("--image-sha512", help="Require a specific cached/official image checksum")
    parser.add_argument(
        "--wheel", type=Path, help="Also verify a clean offline wheel installation in the guest"
    )
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    if not Path("/dev/kvm").exists():
        raise SystemExit(
            "Native Debian VM unavailable: /dev/kvm is required (no container substitution)"
        )
    for name in ("qemu-system-x86_64", "qemu-img", "cloud-localds", "ssh-keygen", "ssh", "scp"):
        if not shutil.which(name):
            raise SystemExit(f"Native Debian VM unavailable: missing {name}")
    args.cache.mkdir(parents=True, exist_ok=True)
    prepare_results(args.results)
    image = args.cache.resolve() / IMAGE
    if args.image_sha512 and image.exists() and digest(image) == args.image_sha512:
        expected = args.image_sha512
    else:
        checksums = urllib.request.urlopen(BASE + "SHA512SUMS", timeout=60).read().decode()
        expected = next(
            line.split()[0] for line in checksums.splitlines() if line.split()[-1] == IMAGE
        )
        if args.image_sha512 and expected != args.image_sha512:
            raise SystemExit(
                "Official latest image changed; supply the recorded cached image to reproduce"
            )
        if not image.exists() or digest(image) != expected:
            print("Downloading official Debian 12 cloud image", flush=True)
            temporary = image.with_suffix(".download")
            with (
                urllib.request.urlopen(BASE + IMAGE, timeout=120) as response,
                temporary.open("wb") as output,
            ):
                shutil.copyfileobj(response, output)
            if digest(temporary) != expected:
                temporary.unlink()
                raise RuntimeError("Debian cloud image checksum mismatch")
            temporary.replace(image)
    (args.results / "image.json").write_text(
        json.dumps(
            {
                "url": BASE + IMAGE,
                "sha512": expected,
                "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "hypervisor": "QEMU KVM, no host folder mounts",
            },
            indent=2,
        )
    )
    with tempfile.TemporaryDirectory(prefix="safeshell-debian-vm-") as directory:
        root = Path(directory)
        key = root / "key"
        call(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)])
        public = key.with_suffix(".pub").read_text().strip()
        (root / "user-data").write_text(
            "#cloud-config\nusers:\n  - name: safeshell\n    groups: [sudo]\n    shell: /bin/bash\n    sudo: 'ALL=(ALL) NOPASSWD:ALL'\n    ssh_authorized_keys:\n      - "
            + public
            + '\napt:\n  conf: |\n    APT::Install-Recommends "false";\npackage_update: true\npackages: [bubblewrap, libseccomp2, python3, python3-pytest, python3-venv, build-essential]\n'
        )
        (root / "meta-data").write_text(
            "instance-id: safeshell-alpha-validation\nlocal-hostname: safeshell-debian\n"
        )
        seed = root / "seed.img"
        disk = root / "disk.qcow2"
        call(["cloud-localds", str(seed), str(root / "user-data"), str(root / "meta-data")])
        call(
            ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(image), str(disk), "8G"]
        )
        with socket.socket() as channel:
            channel.bind(("127.0.0.1", 0))
            port = channel.getsockname()[1]
        options = [
            "-i",
            str(key),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=3",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            f"UserKnownHostsFile={root / 'known_hosts'}",
            "-o",
            "LogLevel=ERROR",
        ]
        ssh = ["ssh", *options, "-p", str(port), "safeshell@127.0.0.1"]
        scp = ["scp", *options, "-P", str(port)]
        with (args.results / "console.log").open("wb") as console:
            process = subprocess.Popen(
                [
                    "qemu-system-x86_64",
                    "-accel",
                    "kvm",
                    "-cpu",
                    "host",
                    "-m",
                    "2048",
                    "-smp",
                    "2",
                    "-display",
                    "none",
                    "-serial",
                    "stdio",
                    "-monitor",
                    "none",
                    "-drive",
                    f"file={disk},if=virtio,format=qcow2",
                    "-drive",
                    f"file={seed},if=virtio,format=raw,readonly=on",
                    "-netdev",
                    f"user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:22",
                    "-device",
                    "virtio-net-pci,netdev=net0",
                ],
                stdin=subprocess.DEVNULL,
                stdout=console,
                stderr=subprocess.STDOUT,
            )
            try:
                print("Waiting for Debian guest SSH and signed-package provisioning", flush=True)
                deadline = time.monotonic() + 600
                while subprocess.run(
                    [*ssh, "true"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                ).returncode:
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError(
                            "Debian VM did not become available; inspect console.log"
                        )
                    time.sleep(2)
                call([*ssh, "cloud-init status --wait"], timeout=900)
                call([*scp, str(source), "safeshell@127.0.0.1:source.tar.gz"])
                call(
                    [
                        *ssh,
                        "mkdir -p candidate && tar -xzf source.tar.gz -C candidate --strip-components=1",
                    ]
                )
                tests = subprocess.run(
                    [*ssh, "cd candidate && python3 tools/validate_linux.py"],
                    timeout=900,
                    check=False,
                )
                if args.wheel and tests.returncode == 0:
                    call(
                        [
                            *scp,
                            str(args.wheel.resolve(strict=True)),
                            "safeshell@127.0.0.1:" + args.wheel.name,
                        ]
                    )
                    with (args.results / "installed-smoke.json").open("w") as result:
                        call(
                            [
                                *ssh,
                                "cd candidate && python3 tools/smoke_installed.py "
                                + shlex.quote("../" + args.wheel.name)
                                + " --require-backend",
                            ],
                            stdout=result,
                            timeout=300,
                        )
                call(
                    [
                        *scp,
                        "-r",
                        "safeshell@127.0.0.1:candidate/validation-results/.",
                        str(args.results),
                    ]
                )
                return tests.returncode
            finally:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    raise SystemExit(main())
