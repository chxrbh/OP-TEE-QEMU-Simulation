# Secure IIoT OP-TEE Project Summary

## 1. Project Overview

This project is a Secure IIoT edge/fog processing prototype implemented with OP-TEE. It demonstrates how sensor readings can move through a cryptographic pipeline where sensitive operations happen inside a Trusted Application (TA), while Normal World only handles ciphertexts and orchestration.

The current prototype implements the following flow:

- Sensor readings are encrypted as AES-GCM packets in the Normal World host/sensor simulator.
- The Fog Processing TA decrypts and authenticates those AES-GCM packets inside Secure World.
- The Fog Processing TA converts each plaintext reading into a Paillier ciphertext inside Secure World.
- The Fog Host aggregates Paillier ciphertexts outside the TA using Paillier homomorphic multiplication.
- A mocked/local KMM control-plane combines or forwards aggregate metadata for the current window.
- The Storage-Preparation TA path decrypts the final Paillier aggregate inside Secure World.
- The Storage-Preparation TA path re-encrypts the final aggregate into an AES-GCM cloud object.
- The cloud-side output stores only encrypted data, represented as `{Cdata, Ck_placeholder}`.

This is a prototype and presentation implementation. It runs in OP-TEE QEMU, not on physical TrustZone hardware. It does not claim production security.

## 2. Architecture Flow

Full current pipeline:

```text
Sensor / Normal World host
-> AES-GCM encrypted packet
-> Fog Processing TA
-> AES-GCM decrypt inside Secure World
-> Paillier encrypt inside Secure World
-> Paillier ciphertext returned to Normal World
-> Fog Host Paillier aggregation outside TA
-> KMM mock window combine
-> Storage-Preparation TA
-> Paillier decrypt inside Secure World
-> AES-GCM encrypt cloud object inside Secure World
-> Cloud stores {Cdata, Ck_placeholder}
```

Implemented as real cryptography:

- AES-GCM packet encryption in the Normal World sensor simulator.
- AES-GCM packet authentication and decryption inside the TA.
- Paillier encryption inside the TA using a fixed 512-bit prototype key.
- Paillier ciphertext aggregation outside the TA in Normal World.
- Paillier aggregate decryption inside the TA storage-preparation command.
- AES-GCM encryption of the final cloud object inside the TA storage-preparation command.

Mocked or prototype-only:

- KMM is local mocked control-plane logic.
- CP-ABE is represented by a `Ck_placeholder` placeholder.
- Delegation and revocation are mocked for control-flow demonstration.
- Demo AES and Paillier keys are fixed prototype values.
- OP-TEE runs in QEMU.
- The Paillier key is 512-bit for speed and prototype validation only.

Implementation note: the logical Fog Processing TA and Storage-Preparation TA roles are currently implemented as separate commands inside the same OP-TEE TA binary. This keeps the prototype simple while preserving the intended trust-boundary flow.

## 3. Trust Boundary

Normal World can see:

- AES-GCM ciphertext packets sent by the sensor simulator.
- AES-GCM nonces, tags, and packet metadata.
- Paillier ciphertexts returned by the Fog Processing TA.
- Paillier aggregate ciphertexts produced by homomorphic aggregation.
- The final AES-GCM encrypted cloud object.

Normal World performs:

- Sensor packet creation in the simulator.
- Paillier aggregation over ciphertexts.
- KMM mock orchestration and metadata logging.
- Benchmarking and presentation output.

Normal World should not learn:

- Plaintext sensor readings after packet submission.
- The plaintext final aggregate from the storage-preparation path.
- Production key material in a final system.

Secure World TA performs:

- AES-GCM packet authentication and decryption.
- Paillier encryption of individual readings.
- Paillier decryption of the final aggregate.
- AES-GCM encryption of the cloud object.

Cloud storage receives only the AES-GCM encrypted object and the mocked CP-ABE key wrapper placeholder `{Cdata, Ck_placeholder}`. The plaintext aggregate is not returned to Normal World in the full crypto demo path.

## 4. File Structure

### Top Level

- `Makefile`: builds the host programs and TA by invoking `make -C host` and `make -C ta`.
- `CMakeLists.txt`: CMake build description for the older/basic host targets. The Makefile is the main build path for the full current binary set.
- `PROJECT_SUMMARY.md`: this project summary document.

### `host/`

- `main.c`: earlier standalone real AES-GCM demo path. It sends AES-GCM packets to the TA and uses the older fake Paillier compatibility branch.
- `main_demo.c`: presentation demo. Shows KMM setup, sensor AES-GCM packets, Fog Processing TA calls, Paillier ciphertext output, fog aggregation, and cloud-object storage messaging.
- `main_bench.c`: OP-TEE benchmark mode for fog-processing calls and, where applicable, storage-preparation calls. Reports mean, min, max, p50, and p95 latency.
- `main_delegate_demo.c`: delegation/revocation presentation demo. Uses mocked KMM delegation control flow while still invoking the TA for cryptographic processing.
- `main_paillier_ref.c`: host-side real Paillier reference test. Does not call OP-TEE; validates Paillier encryption, homomorphic addition, decryption, and serialization.
- `main_paillier_bench.c`: host-side Paillier benchmark. Measures Normal World reference Paillier performance, not TA performance.
- `main_paillier_ta_demo.c`: dedicated TA-side Paillier encryption demo. AES-GCM decrypt and Paillier encrypt happen inside the TA; aggregation happens in Normal World.
- `main_full_crypto_demo.c`: full real crypto presentation path. Demonstrates AES-GCM packet decrypt, TA-side Paillier encrypt, host-side Paillier aggregation, TA-side Paillier decrypt, and TA-side AES-GCM cloud-object encryption.
- `main_full_crypto_verify.c`: correctness verification for the full crypto path. Uses host-side private-key verification only for prototype testing.
- `main_full_crypto_bench.c`: full pipeline benchmark. Measures Fog TA, host aggregation, and Storage-Preparation TA timing for the real crypto path.
- `common.c` / `common.h`: shared host helpers for AES-GCM packet creation, OP-TEE session handling, TA command invocation, timing, hex output, and prototype cloud-object verification.
- `kmm_mock.c` / `kmm_mock.h`: local mocked KMM control-plane logic for fog registration, sensor assignment, delegation/revocation, and window-combine narration.
- `paillier_host.c` / `paillier_host.h`: host-side Paillier reference, serialization helpers, mock aggregation helpers, and real ciphertext aggregation over TA-produced Paillier ciphertexts.
- `Makefile`: builds all current Normal World binaries and links against `libteec` and OpenSSL `libcrypto`.

### `ta/`

- `hello_world_ta.c`: main TA command handler. Despite the inherited OP-TEE example name, this file implements the Secure IIoT TA commands: AES-GCM packet processing and storage preparation.
- `paillier_ta.c` / `paillier_ta.h`: TA-side Paillier implementation. Includes mock fallback APIs and real 512-bit prototype Paillier encrypt/decrypt using LibTomMath.
- `libtommath/`: bundled big integer support used for Paillier inside the TA.
- `include/hello_world_ta.h`: shared TA UUID, command IDs, packet/result structures, storage-preparation structures, and Paillier ciphertext size constants.
- `user_ta_header_defines.h`: TA UUID binding, stack size, heap/data size, version, and TA description.
- `sub.mk`: TA source compilation list. It currently builds `hello_world_ta.c`, `paillier_ta.c`, and all `libtommath/*.c` sources.
- `Makefile`: OP-TEE TA build file using `TA_DEV_KIT_DIR`.
- `8aaaf200-2450-11e4-abe2-0002a5d5c51b.ta`: built TA binary.

Files such as `aes_gcm_ta.c`, `aes_gcm_ta.h`, `storage_prep_ta.c`, and `storage_prep_ta.h` are not separate files in the current tree. Their logic is currently implemented inside `hello_world_ta.c`.

## 5. Binaries

Current built host binaries:

| Binary | Purpose | Real AES-GCM | Real Paillier | Calls OP-TEE TA | Use |
| --- | --- | --- | --- | --- | --- |
| `secure_iiot` | Alias/copy of `secure_iiot_demo` | Yes | Partial/current TA path, with compatibility demo behavior | Yes | Convenience demo |
| `secure_iiot_demo` | Main presentation demo for KMM setup, sensor packets, TA processing, aggregation, and cloud object narration | Yes | TA returns real Paillier when enabled; storage branch keeps compatibility messaging | Yes | Presentation |
| `secure_iiot_delegate_demo` | Delegation and revocation control-flow demo | Yes | Uses TA Paillier output when enabled; KMM delegation is mocked | Yes | Presentation |
| `secure_iiot_bench` | OP-TEE timing benchmark for fog processing and storage paths | Yes | Uses TA real Paillier encrypt when enabled; points to full benchmark for storage decrypt | Yes | Benchmark |
| `secure_iiot_paillier_ref` | Host-side Paillier reference correctness test | No | Yes, host-side only | No | Verification/reference |
| `secure_iiot_paillier_bench` | Host-side Paillier benchmark | No | Yes, host-side only | No | Benchmark |
| `secure_iiot_paillier_ta_demo` | Dedicated TA-side Paillier encryption demo | Yes | Yes, TA encrypt plus host aggregate/reference verify | Yes | Presentation/verification |
| `secure_iiot_full_crypto_demo` | Full real crypto pipeline demo | Yes | Yes, TA encrypt, host aggregate, TA decrypt | Yes | Presentation |
| `secure_iiot_full_crypto_verify` | Full crypto correctness verification | Yes | Yes, with host-side private-key verification only for testing | Yes | Verification |
| `secure_iiot_full_crypto_bench` | Full real crypto pipeline benchmark | Yes | Yes, including TA decrypt in storage-preparation path | Yes | Benchmark |

Current built TA binary:

- `ta/8aaaf200-2450-11e4-abe2-0002a5d5c51b.ta`: OP-TEE Trusted Application containing both logical Fog Processing and Storage-Preparation commands.

## 6. Implemented Real Components

- Real AES-GCM packet encryption in Normal World is implemented in `host/common.c` using OpenSSL EVP.
- Real AES-GCM packet decryption and tag verification inside the Fog Processing TA is implemented in `ta/hello_world_ta.c` using the OP-TEE Internal API.
- Real Paillier encryption inside the Fog Processing TA is implemented in `ta/paillier_ta.c` using LibTomMath and fixed 512-bit prototype key material.
- Real Paillier aggregation outside the TA is implemented in `host/paillier_host.c` by multiplying ciphertexts modulo `n^2`.
- Real Paillier decryption inside the Storage-Preparation TA path is implemented in `ta/paillier_ta.c` and invoked by `prepare_storage()` in `ta/hello_world_ta.c`.
- Real AES-GCM encryption of the cloud object inside the Storage-Preparation TA path is implemented in `ta/hello_world_ta.c`.

## 7. Mocked / Prototype Components

- KMM is mocked as local control-plane code in `host/kmm_mock.c`.
- CP-ABE is mocked as a `Ck_placeholder` in demo output.
- Delegation and revocation are mocked for control-flow demonstration.
- Attestation and key provisioning are not production-grade.
- Demo AES keys are fixed in code for repeatable prototype testing.
- OP-TEE runs in QEMU emulator, not on physical TrustZone hardware.
- Paillier uses a 512-bit prototype key. Production should use 2048-bit or stronger keys.
- The logical Fog Processing TA and Storage-Preparation TA are currently separate commands in one TA binary. They can be split into stricter separate TAs later if required.

## 8. Build Commands

From the project directory:

```sh
cd ~/optee/optee_examples/secure_iiot
make clean
make \
  CROSS_COMPILE=~/optee/out-br/host/bin/arm-linux-gnueabihf- \
  TEEC_EXPORT=~/optee/out-br/host/arm-buildroot-linux-gnueabihf/sysroot/usr \
  TA_DEV_KIT_DIR=~/optee/optee_os/out/arm/export-ta_arm32
```

## 8.1 Recommended Presentation Run Order

Inside OP-TEE QEMU Normal World:

```sh
secure_iiot_full_crypto_demo
secure_iiot_full_crypto_verify
secure_iiot_delegate_demo
secure_iiot_full_crypto_bench 30
secure_iiot_full_crypto_bench 30 2048
```

Binary groups:

- Presentation: `secure_iiot_full_crypto_demo`, `secure_iiot_delegate_demo`
- Verification: `secure_iiot_full_crypto_verify`, `secure_iiot_paillier_ref`
- Benchmark: `secure_iiot_full_crypto_bench`, `secure_iiot_paillier_bench`
- Legacy/compatibility: `secure_iiot_demo`, `secure_iiot`, `secure_iiot_bench`

The presentation demo uses the 512-bit fixed Paillier key for speed. The
benchmark command `secure_iiot_full_crypto_bench 30 2048` provides a
paper-aligned 2048-bit host-side Paillier reference benchmark and explicitly
prints that TA-side 2048-bit Paillier is not enabled in this QEMU prototype.

## 9. Install Commands

Copy the host binaries and TA into the Buildroot target filesystem:

```sh
sudo cp host/secure_iiot_demo ~/optee/out-br/target/usr/bin/
sudo cp host/secure_iiot_delegate_demo ~/optee/out-br/target/usr/bin/
sudo cp host/secure_iiot_bench ~/optee/out-br/target/usr/bin/
sudo cp host/secure_iiot_paillier_ref ~/optee/out-br/target/usr/bin/
sudo cp host/secure_iiot_paillier_bench ~/optee/out-br/target/usr/bin/
sudo cp host/secure_iiot_paillier_ta_demo ~/optee/out-br/target/usr/bin/
sudo cp host/secure_iiot_full_crypto_demo ~/optee/out-br/target/usr/bin/
sudo cp host/secure_iiot_full_crypto_verify ~/optee/out-br/target/usr/bin/
sudo cp host/secure_iiot_full_crypto_bench ~/optee/out-br/target/usr/bin/
sudo cp host/secure_iiot ~/optee/out-br/target/usr/bin/
sudo cp ta/*.ta ~/optee/out-br/target/lib/optee_armtz/
sudo chmod +x ~/optee/out-br/target/usr/bin/secure_iiot*
```

Rebuild the Buildroot image and run QEMU:

```sh
cd ~/optee/build
make buildroot
make run-only
```

In the QEMU monitor:

```text
c
```

In Normal World login:

```text
root
```

## 10. Run Commands

Example commands inside OP-TEE QEMU Normal World:

```sh
secure_iiot_demo
secure_iiot_delegate_demo
secure_iiot_bench 100
secure_iiot_paillier_ref
secure_iiot_paillier_bench 512 100
secure_iiot_paillier_ta_demo
secure_iiot_full_crypto_demo
secure_iiot_full_crypto_verify
secure_iiot_full_crypto_bench 30
secure_iiot_full_crypto_bench 30 2048
secure_iiot_paillier_bench 2048 30
```

## 11. Expected Important Output

Important messages to look for:

- `AES-GCM verification passed`
- `Real Paillier encryption inside TA completed`
- `Secure IIoT Paillier ciphertext_len=128`
- `Fog Processing TA returned real Paillier ciphertext len=128 bytes`
- `Fog host aggregated real Paillier ciphertext outside TA.`
- `Storage-Preparation TA performed real Paillier decrypt inside Secure World.`
- `Storage-Preparation TA encrypted final aggregate with AES-GCM.`
- `Cloud stores only {Cdata, Ck_placeholder}.`
- `Plaintext aggregate was not returned to Normal World.`

For correctness verification, expected output includes:

- `Paillier verification: PASS`
- `Cloud object verification: PASS`

For benchmark output, expected fields include:

- `fog_ta_mean_us`
- `fog_ta_p50_us`
- `fog_ta_p95_us`
- `host_aggregate_mean_us`
- `storage_ta_mean_us`
- `storage_ta_p50_us`
- `storage_ta_p95_us`

## 12. Measurement Notes

- Benchmark timing measures OP-TEE QEMU round-trip latency plus the prototype cryptographic work in that path.
- The first TA call may be slower because the TA must be loaded and initialized.
- Use warm-up iterations before measured iterations.
- Report mean, p50, and p95, not only one average.
- QEMU timing is useful for functional comparison and prototype trends, but it is not production hardware timing.
- 512-bit Paillier is prototype-only and much faster than a production-strength Paillier key.
- The full presentation path uses 512-bit Paillier for live-demo stability.
- The 2048-bit benchmark mode is host-side Paillier reference timing; TA-side 2048-bit Paillier is not silently substituted for the 512-bit TA path.
- Production evaluation should repeat measurements on the final hardware and with 2048-bit or stronger Paillier keys.

## 13. How This Maps to the Paper

- Fog Processing TA maps to the paper's fog SGX/TEE enclave role.
- Storage-Preparation TA maps to the KMM-hosted storage-preparation enclave role.
- KMM mock maps to the paper's control-plane trust anchor.
- Paillier aggregation outside the TA maps to fog/KMM homomorphic combine over ciphertexts.
- The cloud object maps to `Cdata`.
- `Ck_placeholder` maps to the CP-ABE protected storage key placeholder.

Important terminology note: this implementation uses OP-TEE in QEMU. It should not be described as running on SGX hardware or physical TrustZone hardware.

## 14. Remaining Work

- Replace mocked KMM with a real KMM service.
- Add real attestation and secure key provisioning.
- Split Fog Processing TA and Storage-Preparation TA into stricter separate TAs if required by the final architecture.
- Upgrade Paillier from the 512-bit prototype key to 2048-bit or stronger.
- Add a real CP-ABE implementation for `Ck_placeholder`.
- Add a real multi-fog deployment or separate OP-TEE/TEE instances.
- Replace fixed demo keys with provisioned and protected key material.
- Add real sensor input instead of fixed demo readings.
- Add Kubernetes/cloud storage integration if required.
- Run production-relevant benchmarks on target hardware.
