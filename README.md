I created the **build scripts, offline-bundle packaging scripts, installer, tests, and Codex handoff package**.

**The actual compiled Noir binaries and full offline RPM bundles are not included.** This environment could not fetch build inputs and had neither target operating system nor the native build tools. Consequently, native compilation and offline installation remain untested. The downloads below are build kits—not finished runtime bundles.

## Downloads

| Package | Contents |
|---|---|
| **noir-1.4.0-build-handoff.zip[Complete build and Codex handoff package — ZIP](sandbox:/mnt/data/noir-1.4.0-build-handoff.zip)** | Both target workflows, all scripts, documentation, tests, source references, and implementation status |
| noir-1.4.0-build-handoff.tar.gz[Complete package — tar.gz](sandbox:/mnt/data/noir-1.4.0-build-handoff.tar.gz) | Same contents, with Unix executable permissions preserved |
| **noir-1.4.0-rocky9-build-kit.tar.gz[Standalone Rocky Linux 9 build kit](sandbox:/mnt/data/noir-1.4.0-rocky9-build-kit.tar.gz)** | Self-contained copy of the build infrastructure for the Rocky workflow |
| **noir-1.4.0-alt104-build-kit.tar.gz[Standalone ALT Linux 10.4 build kit](sandbox:/mnt/data/noir-1.4.0-alt104-build-kit.tar.gz)** | Self-contained copy of the build infrastructure for the ALT workflow |
| noir-1.4.0-build-kits-SHA256SUMS.txt[Archive SHA-256 checksums](sandbox:/mnt/data/noir-1.4.0-build-kits-SHA256SUMS.txt) | Checksums for all four downloads |

For direct inspection: CODEX_HANDOFF.md[Codex handoff](sandbox:/mnt/data/noir-1.4.0-build-handoff/CODEX_HANDOFF.md), README.md[main README](sandbox:/mnt/data/noir-1.4.0-build-handoff/README.md), and STATUS.json[implementation/validation status](sandbox:/mnt/data/noir-1.4.0-build-handoff/STATUS.json).

**Architecture assumption: x86-64.** The scripts reject other architectures.

## 1. Build design

### Pinned Noir release and compiler

The scripts interpret “Noir 1.4” as **v1.4.0** and pin its exact source commit:

```text
8b8d1683ba7b70387c4abf9f34c8d7f0a74b6ba4
```

That commit corresponds to the requested upstream release; the scripts do not build an unpinned `main` branch. [GitHub](https://github.com/owasp-noir/noir/releases/tag/v1.4.0)

The compiler is **Crystal 1.21.0**, matching the compiler version selected in Noir’s tagged Dockerfile. Its download filename and SHA-256 are pinned in `profiles/versions.env`. [GitHub](https://raw.githubusercontent.com/owasp-noir/noir/v1.4.0/Dockerfile)

### Independent native builds

The intended execution environments are **two separate native build VMs**:

| Rocky build | ALT build |
|---|---|
| Actual Rocky Linux 9 installation | Actual ALT Linux 10.4 installation |
| Rocky development libraries and RPMs | ALT development libraries and RPMs |
| Separate source checkout and caches | Separate source checkout and caches |
| Separate compilation, logs, and artifacts | Separate compilation, logs, and artifacts |

The application is built against each distribution’s native libraries. No compiled Noir executable or C object is reused between platforms. This includes rebuilding the vendored tree-sitter objects that appear in Noir’s upstream build/cleanup process. [GitHub](https://raw.githubusercontent.com/owasp-noir/noir/v1.4.0/justfile)

For ALT, use the **same edition and package baseline as the intended deployment**. The implementation deliberately does not treat an arbitrary p10 container as proof of ALT 10.4 compatibility.

## 2. Scripts provided

| Script | Purpose |
|---|---|
| `build-rocky9.sh` | Complete Rocky acquisition, compilation, testing, and packaging workflow |
| `build-alt104.sh` | Corresponding independent ALT workflow |
| `make-full-rocky9.sh` | Create a full Rocky offline bundle from an existing binary build |
| `make-full-alt104.sh` | Create a full ALT offline bundle from an existing binary build |
| `templates/install.sh` | Offline installer copied into each generated runtime bundle |
| `templates/verify.sh` | Strict payload checksum verifier |
| `tests/smoke.py` | Functional tests against a real built Noir executable |
| `tests/acceptance-vm.sh` | Offline installation and functional testing in a disposable target VM |

The functional tests cover version/help, Flask and Spring endpoint extraction, JSON and OpenAPI output, passive scanning, and Git revision comparison.

### What the full-bundle workflow includes

The implemented packaging workflow collects the application’s native RPM dependencies, plus Git, certificates, verification utilities, and their required dependencies.

Git is included because Noir’s `--diff-ref` functionality uses Git. Passive rules are also bundled separately rather than assuming they will be downloaded after installation. Both requirements are reflected in the upstream runtime configuration. [GitHub](https://raw.githubusercontent.com/owasp-noir/noir/v1.4.0/Dockerfile)

The launcher supplies the packaged rules through Noir’s supported `NOIR_BUNDLED_RULES_PATH` setting. The documentation also explains how to select that rules directory explicitly, because an existing user-managed rules directory has precedence in upstream Noir. [GitHub](https://raw.githubusercontent.com/owasp-noir/noir/v1.4.0/src/utils/passive_rules_updater.cr)

The RPM collector explicitly acquires selected dependencies even when they are already installed on the builder. This avoids the omission that can occur when using a dependency-download operation that fetches only missing packages. DNF documents that distinction for `--resolve` and `--alldeps`. [DNF Plugins Core Documentation](https://dnf-plugins-core.readthedocs.io/en/latest/download.html)

**These native packaging paths still require execution and validation.** In particular, the ALT APT-RPM acquisition path is implemented but has not been tested on ALT.

## 3. Building the bundles

Use an ordinary user with `sudo` in each disposable, connected build VM. Do **not** run source compilation as root.

### On Rocky Linux 9

```bash
tar -xzf noir-1.4.0-rocky9-build-kit.tar.gz
cd noir-1.4.0-rocky9-build-kit

./build-rocky9.sh all
```

### On ALT Linux 10.4

```bash
tar -xzf noir-1.4.0-alt104-build-kit.tar.gz
cd noir-1.4.0-alt104-build-kit

./build-alt104.sh all
```

The `all` workflow performs dependency bootstrap, input acquisition and verification, native compilation, upstream tests, functional smoke tests, binary packaging, and full-bundle packaging. A failing phase stops the workflow and preserves logs.

**After successful native execution**, the expected runtime archives are:

```text
out/rocky9/
├── noir-1.4.0-rocky9-x86_64-binary.tar.gz
└── noir-1.4.0-rocky9-x86_64-full.tar.gz

out/alt104/
├── noir-1.4.0-alt104-x86_64-binary.tar.gz
└── noir-1.4.0-alt104-x86_64-full.tar.gz
```

Each receives a checksum sidecar.

The **binary bundle** contains the executable, launcher, passive rules, source/shard snapshot, licenses, installer, and metadata. It assumes native runtime dependencies are already available.

The **full bundle** adds the native runtime RPM dependency set for offline installation.

Neither is a complete Linux installation image or a fully offline *rebuild* environment.

## 4. Offline installation procedure

For a successfully generated Rocky full bundle:

```bash
sha256sum -c noir-1.4.0-rocky9-x86_64-full.tar.gz.sha256

tar -xzf noir-1.4.0-rocky9-x86_64-full.tar.gz
cd noir-1.4.0-rocky9-x86_64-full

./verify.sh
sudo ./install.sh --plan
sudo ./install.sh --apply

noir version
```

Use the corresponding `alt104` filename on ALT.

The installer is implemented to use **local bundle files only**. It verifies payload checksums and trusted RPM signatures, previews changes, and tests the RPM transaction before installing.

**Different installed package versions are blocked by default.** After reviewing differences and taking a VM snapshot, an explicit option permits normal RPM upgrades:

```bash
sudo ./install.sh --plan --allow-package-changes
sudo ./install.sh --apply --allow-package-changes
```

It does not use forced downgrades, dependency bypasses, package erasure, or automatic import of untrusted signing keys.

The full procedure, rules handling, installation paths, and recovery limitations are in the RUNTIME-README.md[runtime installation guide](sandbox:/mnt/data/noir-1.4.0-build-handoff/docs/RUNTIME-README.md).

## 5. Validation actually completed

**37 local helper tests passed.** Python compilation checks also passed, and all four downloadable archives were extracted and checked against their payload manifests.

Those tests cover helper logic, checksum/tamper handling, mocked RPM-signature and dependency cases, shell syntax, entry-point help, and wrong-OS guards. They do **not** substitute for real Noir or RPM execution.

| Validation | Status |
|---|---|
| Local helper tests and syntax checks | **Passed** |
| Downloadable archive integrity checks | **Passed** |
| Native Rocky compilation | **Not run** |
| Native ALT compilation | **Not run** |
| Real Noir functional tests | **Not run** |
| Native RPM acquisition/signature/dependency tests | **Not run** |
| Clean-target offline installation | **Not run** |

The local-checks.log[local test log](sandbox:/mnt/data/noir-1.4.0-build-handoff/evidence/local-checks.log) and ACCEPTANCE.md[native acceptance procedure](sandbox:/mnt/data/noir-1.4.0-build-handoff/docs/ACCEPTANCE.md) are included.

## 6. Handoff to Codex

Attach the **complete ZIP package** and use this prompt:

```text
Read AGENTS.md, CODEX_HANDOFF.md, STATUS.json, README.md,
docs/ACCEPTANCE.md, and docs/SOURCES.md.

Finish the native execution and qualification of this implementation.

Produce four real Noir 1.4.0 x86_64 runtime archives:
1. Rocky Linux 9 binary bundle.
2. Rocky Linux 9 full offline installation bundle.
3. ALT Linux 10.4 binary bundle.
4. ALT Linux 10.4 full offline installation bundle.

Use independent native build environments matching the actual deployment
editions and package baselines. Preserve source/compiler pins, separate
source trees and caches, RPM signatures, and dependency/conflict checks.

Fix observed native build or packaging failures, especially the unvalidated
ALT APT-RPM path. Install and test each full bundle in a separate clean
target VM with networking disabled.

Return the real archives, checksums, tested scripts, build logs, and
qualification receipts tied to the actual artifact hashes. Update
STATUS.json honestly. Do not describe helper tests as native qualification
or substitute upstream prebuilt Noir executables.
```

The handoff contains implementation details, known risks, extension priorities, and a SOURCES.md[primary-source reference guide](sandbox:/mnt/data/noir-1.4.0-build-handoff/docs/SOURCES.md) for continued work.
