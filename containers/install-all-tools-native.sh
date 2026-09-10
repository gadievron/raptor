#!/usr/bin/env bash

set -euo pipefail

MANIFEST="${RAPTOR_ALL_TOOLS_MANIFEST:-/usr/local/share/raptor/all-tools-manifest.json}"
WORK_DIR="$(mktemp -d /tmp/raptor-all-tools-native.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

manifest_value() {
    jq -er "$1" "$MANIFEST"
}

tool_value() {
    local tool="$1"
    local field="$2"
    jq -er --arg tool "$tool" --arg field "$field" '.tools[$tool][$field]' "$MANIFEST"
}

download_sha256() {
    local tool="$1"
    local destination="$2"
    local url sha256
    url="$(tool_value "$tool" url)"
    sha256="$(tool_value "$tool" sha256)"
    curl -fL --retry 5 --retry-all-errors --retry-delay 2 \
        "$url" -o "$destination"
    printf '%s  %s\n' "$sha256" "$destination" > "$destination.sha256"
    sha256sum -c "$destination.sha256"
}

verify_coccinelle_python_runtime() {
    local smoke_dir="$WORK_DIR/coccinelle-python-smoke"
    local smoke_output
    mkdir -p "$smoke_dir"

    cat > "$smoke_dir/probe.c" <<'EOF'
void coccinelle_python_marker(void);
void probe(void) {
    coccinelle_python_marker();
}
EOF
    cat > "$smoke_dir/probe.cocci" <<'EOF'
@python_runtime@
position p;
@@
coccinelle_python_marker@p();

@script:python@
p << python_runtime.p;
@@
import sys
for _p in p:
    sys.stderr.write(
        "COCCIRESULT:coccinelle-python-runtime:%d\n" % int(_p.line)
    )
EOF

    if ! smoke_output="$(
        spatch \
            --sp-file "$smoke_dir/probe.cocci" \
            "$smoke_dir/probe.c" \
            --no-show-diff \
            --very-quiet \
            2>&1
    )"; then
        printf '%s\n' "$smoke_output" >&2
        return 1
    fi
    printf '%s\n' "$smoke_output"
    grep -F "COCCIRESULT:coccinelle-python-runtime:" <<< "$smoke_output" >/dev/null
}

install_coccinelle() {
    local python_bin=/usr/local/bin/python3
    local python_config=/usr/local/bin/python3-config
    local python_version python_libdir python_library python_ldflags
    local coccinelle_version coccinelle_archive

    python_version="$(
        "$python_bin" -c \
            'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")'
    )"
    if [ "$python_version" != "3.14" ]; then
        printf 'Coccinelle requires the image Python 3.14 runtime, found %s\n' \
            "$python_version" >&2
        return 1
    fi
    python_libdir="$(
        "$python_bin" -c \
            'import sysconfig; print(sysconfig.get_config_var("LIBDIR"))'
    )"
    python_library="$(
        "$python_bin" -c \
            'import sysconfig; print(sysconfig.get_config_var("LDLIBRARY"))'
    )"
    python_ldflags="$("$python_config" --embed --ldflags)"
    test -f "$python_libdir/$python_library"

    # PyML resolves libpython through the dynamic-loader cache. Register the
    # /usr/local CPython build before compiling and running Python SmPL.
    printf '%s\n' "$python_libdir" > /etc/ld.so.conf.d/raptor-python.conf
    ldconfig
    ldconfig -p | grep -F "$python_library" >/dev/null

    coccinelle_version="$(tool_value coccinelle version)"
    coccinelle_archive="$WORK_DIR/coccinelle.tar.gz"
    download_sha256 coccinelle "$coccinelle_archive"
    tar --no-same-owner -xzf "$coccinelle_archive" -C "$WORK_DIR"
    (
        cd "$WORK_DIR/coccinelle-$coccinelle_version"

        # CPython 3.8+ separates extension and embedding metadata. Bundled
        # PyML queries python-X.Y.pc, whose Libs omits -lpython and aborts
        # before its later python-config fallback. Use the embed metadata.
        pyml_source=bundles/pyml/pyml-current/py.ml
        sed -i \
            's/pkg-config --libs python-%d.%d"/pkg-config --libs python-%d.%d-embed"/' \
            "$pyml_source"
        grep -F 'pkg-config --libs python-%d.%d-embed' "$pyml_source" >/dev/null

        PYVER="$python_version" \
        PYTHON="$python_bin" \
        LDFLAGS="-L${python_libdir} ${python_ldflags}" \
            ./configure \
                --prefix=/usr/local \
                --enable-python=yes \
                --with-python="$python_bin"
        grep -q '^FEATURE_PYTHON=1$' Makefile.config
        make -j"$(nproc)" all.opt
        make install
    )

    verify_coccinelle_python_runtime
}

arch="$(dpkg --print-architecture)"
case "$arch" in
    amd64) ;;
    *)
        printf 'all-tools native installer: unsupported architecture: %s\n' "$arch" >&2
        exit 65
        ;;
esac

if [ -n "${RAPTOR_ALL_TOOLS_NATIVE_ONLY:-}" ]; then
    case "$RAPTOR_ALL_TOOLS_NATIVE_ONLY" in
        coccinelle)
            install_coccinelle
            exit 0
            ;;
        *)
            printf 'Unknown native-only install target: %s\n' \
                "$RAPTOR_ALL_TOOLS_NATIVE_ONLY" >&2
            exit 64
            ;;
    esac
fi

radare2_deb="$WORK_DIR/radare2.deb"
r2ghidra_deb="$WORK_DIR/r2ghidra.deb"
download_sha256 radare2 "$radare2_deb"
download_sha256 r2ghidra "$r2ghidra_deb"
dpkg -i "$radare2_deb" "$r2ghidra_deb"

install_coccinelle

ffuf_archive="$WORK_DIR/ffuf.tar.gz"
download_sha256 ffuf "$ffuf_archive"
tar --no-same-owner -xzf "$ffuf_archive" -C "$WORK_DIR"
install -m 0755 "$WORK_DIR/ffuf" /usr/local/bin/ffuf

nuclei_archive="$WORK_DIR/nuclei.zip"
download_sha256 nuclei "$nuclei_archive"
unzip -q "$nuclei_archive" -d "$WORK_DIR/nuclei"
install -m 0755 "$WORK_DIR/nuclei/nuclei" /usr/local/bin/nuclei

go_archive="$WORK_DIR/go.tar.gz"
download_sha256 go "$go_archive"
rm -rf /usr/local/go
tar --no-same-owner -xzf "$go_archive" -C /usr/local
ln -s /usr/local/go/bin/go /usr/local/bin/go
ln -s /usr/local/go/bin/gofmt /usr/local/bin/gofmt

rust_version="$(tool_value rust version)"
rust_nightly="$(tool_value rust nightly_toolchain)"
rustup_init="$WORK_DIR/rustup-init"
download_sha256 rust "$rustup_init"
chmod 0755 "$rustup_init"
RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo \
    "$rustup_init" -y --no-modify-path --profile minimal \
    --default-toolchain "$rust_version"
RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo \
    /opt/cargo/bin/rustup toolchain install \
    "$rust_nightly" --profile minimal
ln -s /opt/cargo/bin/rustc /usr/local/bin/rustc
ln -s /opt/cargo/bin/cargo /usr/local/bin/cargo
ln -s /opt/cargo/bin/rustup /usr/local/bin/rustup

cargo_fuzz_version="$(tool_value cargo-fuzz version)"
RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo \
    /opt/cargo/bin/cargo install --locked \
    --version "$cargo_fuzz_version" cargo-fuzz

cat > /usr/local/bin/cargo-fuzz <<EOF
#!/usr/bin/env bash
set -euo pipefail
export RUSTUP_HOME=/opt/rustup
export RUSTUP_TOOLCHAIN="$rust_nightly"
exec /opt/cargo/bin/cargo-fuzz "\$@"
EOF
chmod 0755 /usr/local/bin/cargo-fuzz

cargo_fuzz_smoke=/usr/local/share/raptor/cargo-fuzz-smoke
cargo_fuzz_vendor=/usr/local/share/raptor/cargo-fuzz-vendor
cargo_fuzz_lock=/usr/local/share/raptor/cargo-fuzz-smoke.Cargo.lock
cargo_fuzz_lock_sha256="$(tool_value cargo-fuzz fixture_lock_sha256)"
test -f "$cargo_fuzz_lock"
printf '%s  %s\n' "$cargo_fuzz_lock_sha256" "$cargo_fuzz_lock" \
    > "$WORK_DIR/cargo-fuzz-lock.sha256"
sha256sum -c "$WORK_DIR/cargo-fuzz-lock.sha256"
rm -rf "$cargo_fuzz_smoke" "$cargo_fuzz_vendor"
install -d -m 0755 \
    "$cargo_fuzz_smoke/.cargo" \
    "$cargo_fuzz_smoke/src" \
    "$cargo_fuzz_smoke/fuzz/fuzz_targets"

cat > "$cargo_fuzz_smoke/Cargo.toml" <<'EOF'
[package]
name = "raptor-cargo-fuzz-smoke"
version = "0.0.0"
publish = false
edition = "2021"

[lib]
path = "src/lib.rs"
EOF

cat > "$cargo_fuzz_smoke/src/lib.rs" <<'EOF'
pub fn checksum(data: &[u8]) -> u8 {
    data.iter().fold(0, |sum, byte| sum.wrapping_add(*byte))
}
EOF

cat > "$cargo_fuzz_smoke/fuzz/Cargo.toml" <<'EOF'
[package]
name = "raptor-cargo-fuzz-smoke-fuzz"
version = "0.0.0"
publish = false
edition = "2021"

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"

[dependencies.raptor-cargo-fuzz-smoke]
path = ".."

[[bin]]
name = "smoke"
path = "fuzz_targets/smoke.rs"
test = false
doc = false
bench = false

[workspace]
members = ["."]
EOF

install -m 0644 "$cargo_fuzz_lock" "$cargo_fuzz_smoke/fuzz/Cargo.lock"

cat > "$cargo_fuzz_smoke/fuzz/fuzz_targets/smoke.rs" <<'EOF'
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = raptor_cargo_fuzz_smoke::checksum(data);
});
EOF

RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo \
    RUSTUP_TOOLCHAIN="$rust_nightly" \
    /opt/cargo/bin/cargo vendor --locked \
    --manifest-path "$cargo_fuzz_smoke/fuzz/Cargo.toml" \
    "$cargo_fuzz_vendor" > "$cargo_fuzz_smoke/.cargo/config.toml"
chown -R root:root \
    /opt/cargo \
    /opt/rustup \
    "$cargo_fuzz_smoke" \
    "$cargo_fuzz_vendor"
chmod -R a+rX \
    /opt/cargo \
    /opt/rustup \
    "$cargo_fuzz_smoke" \
    "$cargo_fuzz_vendor"

maven_version="$(tool_value maven version)"
maven_url="$(tool_value maven url)"
maven_sha512="$(tool_value maven sha512)"
maven_archive="$WORK_DIR/maven.tar.gz"
curl -fL --retry 5 --retry-all-errors --retry-delay 2 \
    "$maven_url" -o "$maven_archive"
printf '%s  %s\n' "$maven_sha512" "$maven_archive" > "$maven_archive.sha512"
sha512sum -c "$maven_archive.sha512"
tar --no-same-owner -xzf "$maven_archive" -C /opt
ln -s "/opt/apache-maven-$maven_version" /opt/maven
ln -s /opt/maven/bin/mvn /usr/local/bin/mvn

for binary in r2 spatch ffuf nuclei go rustc cargo cargo-fuzz mvn; do
    command -v "$binary" >/dev/null
done

printf 'Installed native all-tools snapshot %s\n' \
    "$(manifest_value '.snapshot_date')"
