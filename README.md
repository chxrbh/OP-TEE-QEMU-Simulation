# Secure IIoT OP-TEE QEMU Simulation

Secure IIoT is an OP-TEE QEMU prototype for an edge/fog cryptographic
pipeline. It demonstrates sensor packets encrypted in Normal World, sensitive
processing inside an OP-TEE Trusted Application (TA), homomorphic aggregation
over Paillier ciphertexts, and final cloud-object preparation without returning
the plaintext aggregate to Normal World.

This repository is prepared for:

```text
https://github.com/chxrbh/OP-TEE-QEMU-Simulation
```

This is a research and presentation prototype. It is not a production security
implementation.

## Current Status

The build and run instructions target OP-TEE QEMU Armv7-A, also called QEMU v7
in the OP-TEE documentation. The current project Makefiles use:

- `arm-linux-gnueabihf` Buildroot toolchain
- `optee_os/out/arm/export-ta_arm32`
- OP-TEE client `libteec`
- OpenSSL `libcrypto` in the Buildroot sysroot

QEMU v8 / Armv8-A is related but not the default target for this repository as
currently configured. Porting to QEMU v8 normally means changing the
cross-compiler, sysroot, and TA dev kit paths to their AArch64/Arm64 variants.

## What It Demonstrates

Current full-crypto flow:

```text
Sensor simulator / Normal World
-> AES-GCM encrypted sensor packet
-> Fog Processing command inside the TA
-> AES-GCM authentication and decrypt inside Secure World
-> Paillier encrypt inside Secure World
-> Paillier ciphertext returned to Normal World
-> Fog host aggregates ciphertexts outside the TA
-> Mock KMM forwards the aggregate
-> Storage-Preparation command inside the TA
-> Paillier decrypt inside Secure World
-> AES-GCM encrypt final cloud object inside Secure World
-> Cloud stores {Cdata, Ck_placeholder}
```

The logical Fog Processing TA and Storage-Preparation TA roles are implemented
as separate commands in one OP-TEE TA binary:

- `TA_HELLO_WORLD_CMD_PROCESS_SENSOR_PACKET`
- `TA_HELLO_WORLD_CMD_PREPARE_STORAGE`

The inherited OP-TEE example filenames are still present. In particular,
`ta/hello_world_ta.c` is the main Secure IIoT TA command handler.

## Repository Layout

- `Makefile`: primary build entry point for host binaries and the TA.
- `CMakeLists.txt`: CMake host-target description kept for compatibility.
- `PROJECT_SUMMARY.md`: detailed architecture, file, and limitation notes.
- `host/`: Normal World demos, verification tools, benchmarks, KMM mock, and
  host-side Paillier helpers.
- `ta/`: OP-TEE TA sources, TA ABI header, bundled LibTomMath, and TA build
  files.

Generated files are intentionally ignored by `.gitignore`, including host
binaries, object files, and built TA artifacts such as `.ta`, `.elf`, `.map`,
and `.dmp` files.

## Requirements

Use a Linux host. Ubuntu 22.04 or 20.04 are the most commonly used OP-TEE build
hosts.

You need:

- Git and the Android `repo` tool.
- An OP-TEE QEMU v7 developer checkout from
  `https://github.com/OP-TEE/manifest.git`.
- OP-TEE toolchains built by the OP-TEE build system.
- Buildroot output containing `libteec` and OpenSSL headers/libraries.
- Enough disk space and time for a full OP-TEE/QEMU build.

The official OP-TEE documentation lists current prerequisite packages and QEMU
setup commands:

- OP-TEE prerequisites:
  <https://optee.readthedocs.io/en/latest/building/prerequisites.html>
- OP-TEE build flow:
  <https://optee.readthedocs.io/en/latest/building/gits/build.html>
- OP-TEE QEMU device notes:
  <https://optee.readthedocs.io/en/4.9.0/building/devices/qemu.html>

For Ubuntu 22.04, the OP-TEE prerequisite list includes packages such as
`build-essential`, `git`, `curl`, `repo`, `python3-*`, `device-tree-compiler`,
`libssl-dev`, `libglib2.0-dev`, `libpixman-1-dev`, `libslirp-dev`, `make`,
`ninja-build`, `rsync`, `uuid-dev`, `wget`, `xterm`, and related build tools.
Check the official page above before doing a fresh build because OP-TEE
dependencies can change.

## Reproducible Setup

The examples below use `~/optee` as the OP-TEE workspace. You may use another
path by changing `OPTEE_DIR`.

### 1. Build OP-TEE QEMU v7

```sh
export OPTEE_DIR="$HOME/optee"

mkdir -p "$OPTEE_DIR"
cd "$OPTEE_DIR"
repo init -u https://github.com/OP-TEE/manifest.git
repo sync -j"$(nproc)"

cd "$OPTEE_DIR/build"
make toolchains
make -j"$(nproc)"
```

The default OP-TEE manifest is the QEMU v7 / Armv7-A target. OP-TEE also
documents QEMU v8 with `repo init -u https://github.com/OP-TEE/manifest.git -m
qemu_v8.xml`, but this repository currently uses QEMU v7 Arm32 build paths.

### 2. Add This Repository to `optee_examples`

If starting from GitHub:

```sh
cd "$OPTEE_DIR/optee_examples"
git clone https://github.com/chxrbh/OP-TEE-QEMU-Simulation.git secure_iiot
cd secure_iiot
```

If you already copied this project into OP-TEE, make sure it is located at:

```text
$OPTEE_DIR/optee_examples/secure_iiot
```

### 3. Build the Secure IIoT Host Apps and TA

```sh
cd "$OPTEE_DIR/optee_examples/secure_iiot"

make clean
make \
  CROSS_COMPILE="$OPTEE_DIR/out-br/host/bin/arm-linux-gnueabihf-" \
  TEEC_EXPORT="$OPTEE_DIR/out-br/host/arm-buildroot-linux-gnueabihf/sysroot/usr" \
  TA_DEV_KIT_DIR="$OPTEE_DIR/optee_os/out/arm/export-ta_arm32"
```

The top-level `Makefile` builds both:

- Normal World binaries under `host/`
- The TA binary under `ta/`

Expected TA output:

```text
ta/8aaaf200-2450-11e4-abe2-0002a5d5c51b.ta
```

## Install Into QEMU Rootfs

Copy the host tools and TA into the Buildroot target filesystem:

```sh
export OPTEE_DIR="$HOME/optee"
cd "$OPTEE_DIR/optee_examples/secure_iiot"

sudo cp host/secure_iiot* "$OPTEE_DIR/out-br/target/usr/bin/"
sudo cp ta/*.ta "$OPTEE_DIR/out-br/target/lib/optee_armtz/"
sudo chmod +x "$OPTEE_DIR/out-br/target/usr/bin"/secure_iiot*
```

Rebuild the root filesystem and start OP-TEE QEMU:

```sh
cd "$OPTEE_DIR/build"
make buildroot
make run-only
```

If QEMU stops at the monitor, continue it with:

```text
c
```

Then log in to Normal World as:

```text
root
```

## Recommended Demo Order

Run these inside OP-TEE QEMU Normal World:

```sh
secure_iiot_full_crypto_demo
secure_iiot_full_crypto_verify
secure_iiot_delegate_demo
secure_iiot_full_crypto_bench 30
secure_iiot_full_crypto_bench 30 2048
```

The `2048` benchmark mode is intentionally host-side reference timing. It
prints that TA-side 2048-bit Paillier is not enabled in this QEMU prototype,
instead of silently substituting the 512-bit TA path.

## Available Binaries

| Binary | Purpose |
| --- | --- |
| `secure_iiot_full_crypto_demo` | Main full pipeline demo: AES-GCM packet decrypt in TA, Paillier encrypt in TA, host aggregation, Paillier decrypt in TA, and AES-GCM cloud-object encryption in TA. |
| `secure_iiot_full_crypto_verify` | Correctness verification for the full crypto path. Uses host-side private-key checks only for prototype testing. |
| `secure_iiot_full_crypto_bench [iterations [512\|2048]]` | Full path benchmark. Default/live TA mode uses the 512-bit prototype Paillier key; `2048` runs host-side reference timing. |
| `secure_iiot_delegate_demo` | Delegation and revocation control-flow demo using mocked KMM logic while still invoking the TA crypto path. |
| `secure_iiot_paillier_ta_demo` | Focused TA-side Paillier encryption demo. |
| `secure_iiot_paillier_ref` | Host-side Paillier correctness reference. Does not call OP-TEE. |
| `secure_iiot_paillier_bench [key_bits iterations]` | Host-side Paillier benchmark. Does not call OP-TEE. |
| `secure_iiot_demo` / `secure_iiot` | Earlier presentation/compatibility demo paths. |
| `secure_iiot_bench` | Earlier OP-TEE timing benchmark. |

## Useful Run Commands

```sh
secure_iiot_full_crypto_demo
secure_iiot_full_crypto_verify
secure_iiot_full_crypto_bench 30
secure_iiot_full_crypto_bench 30 2048
secure_iiot_paillier_ref
secure_iiot_paillier_bench 512 100
secure_iiot_paillier_bench 2048 30
secure_iiot_paillier_ta_demo
secure_iiot_delegate_demo
secure_iiot_demo
secure_iiot_bench 100
```

Important success lines include:

- `AES-GCM verification passed`
- `Real Paillier encryption inside TA completed`
- `Fog host aggregated real Paillier ciphertext outside TA.`
- `Storage-Preparation TA performed real Paillier decrypt inside Secure World.`
- `Storage-Preparation TA encrypted final aggregate with AES-GCM.`
- `Cloud stores only {Cdata, Ck_placeholder}.`
- `Plaintext aggregate was not returned to Normal World.`
- `Paillier verification: PASS`
- `Cloud object verification: PASS`

## Troubleshooting

- `TA_DEV_KIT_DIR not found`: build OP-TEE first with `make -j$(nproc)` from
  `$OPTEE_DIR/build`, then check that
  `$OPTEE_DIR/optee_os/out/arm/export-ta_arm32` exists.
- `tee_client_api.h not found`: check that `TEEC_EXPORT` points to
  `$OPTEE_DIR/out-br/host/arm-buildroot-linux-gnueabihf/sysroot/usr`.
- `arm-linux-gnueabihf-gcc not found`: run `make toolchains` from
  `$OPTEE_DIR/build` and verify
  `$OPTEE_DIR/out-br/host/bin/arm-linux-gnueabihf-gcc` exists.
- TA cannot be opened in QEMU: confirm the `.ta` file was copied to
  `/lib/optee_armtz/` in the target rootfs and that `make buildroot` was run
  after copying.
- Host binary not found in QEMU: confirm it was copied to `/usr/bin/` in the
  target rootfs and that the rootfs was rebuilt.
- `xtest` failures or OP-TEE boot issues: first verify a clean upstream OP-TEE
  QEMU build works before adding this example.

## Benchmark Notes

- QEMU timings include OP-TEE round-trip overhead and prototype cryptographic
  work.
- The first TA call can be slower because the TA is loaded and initialized.
- Use warm-up iterations and report mean, p50, and p95 values.
- QEMU timing is useful for functional comparison and prototype trends, not
  production hardware claims.
- The live TA path uses 512-bit Paillier for demo stability and speed.
- Production-relevant evaluation should use target hardware and 2048-bit or
  stronger Paillier keys.

## Prototype Limitations

- OP-TEE QEMU v7 / Armv7-A is the documented target.
- No physical TrustZone, SGX, or production TEE hardware claim.
- Fixed demo AES and Paillier keys.
- 512-bit Paillier in the live TA path for fast functional demonstration.
- KMM attestation, delegation, and revocation are mocked.
- CP-ABE is represented as `Ck_placeholder`.
- The two logical TA roles are currently separate commands in one TA binary.
- No Kubernetes, distributed KMM, production key vault, or real cloud storage
  integration is implemented.

In the full crypto path, the plaintext aggregate is decrypted and re-encrypted
inside the TA. Normal World stores and forwards ciphertexts and metadata; the
cloud-side object is represented as `{Cdata, Ck_placeholder}`.

## GitHub Preparation Checklist

Before pushing to GitHub:

```sh
cd "$OPTEE_DIR/optee_examples/secure_iiot"
make clean
git status --short
git add .
git commit -m "Prepare Secure IIoT OP-TEE QEMU simulation"
git branch -M main
git remote add origin https://github.com/chxrbh/OP-TEE-QEMU-Simulation.git
git push -u origin main
```

Do not commit generated host binaries, object files, or TA build outputs. They
should be rebuilt from source by following the steps above.
