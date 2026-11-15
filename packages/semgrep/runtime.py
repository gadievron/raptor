"""Use a verified installed Snap application without executing its dispatcher.

Only the conventional Semgrep/core layout is supported. Unknown layouts fail
explicitly; they never fall back to snapd, another Python, or an unsandboxed run.
"""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from core.security.capped_read import read_capped, read_capped_with_stat

_SNAP_ROOT = Path('/snap')
_DISPATCHERS = (Path('/usr/bin/snap'), Path('/usr/lib/snapd/snapd'))
_METADATA_CAP = 64 * 1024
_SITE_ENTRY_CAP = 4096


class SnapRuntimeError(ValueError):
    """A recognized Snap launcher has no safely usable installed runtime."""


def _identity(path: Path) -> tuple:
    st = path.stat()
    return (str(path), st.st_dev, st.st_ino, st.st_mode, st.st_uid,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _trusted_path(path: Path, *, executable: bool = False) -> Path:
    """Refuse writable/unowned input before using it as runtime authority."""
    resolved = path.resolve(strict=True)
    for candidate in (resolved, *resolved.parents):
        st = os.stat(candidate)
        # Host root may appear as the overflow UID in an outer user namespace.
        # Numeric Snap roots are additionally required to be read-only mounts.
        if st.st_uid not in {0, 65534} or st.st_mode & 0o022:
            raise SnapRuntimeError(f'Untrusted Semgrep runtime path: {candidate}')
        if os.geteuid() != 0 and os.access(candidate, os.W_OK):
            raise SnapRuntimeError(f'Writable Semgrep runtime path: {candidate}')
    if executable:
        st = os.stat(resolved)
        if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111:
            raise SnapRuntimeError(f'Invalid Semgrep executable: {resolved}')
    return resolved


def _readonly_revision(path: Path) -> None:
    raw = read_capped(Path('/proc/self/mountinfo'), 1024 * 1024,
                      raise_on_refusal=True)
    if raw is None:
        raise SnapRuntimeError('Cannot verify read-only Snap revision mounts')
    matches = []
    for line in raw.decode('utf-8', errors='strict').splitlines():
        before, after = line.split(' - ', 1)
        left, right = before.split(), after.split()
        mount = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), left[4])
        if mount == str(path):
            matches.append('ro' in left[5].split(',') and right[0] == 'squashfs')
    if matches != [True]:
        raise SnapRuntimeError(f'Semgrep runtime is not a read-only Snap revision: {path}')


def _inside(path: Path, root: Path, *, executable: bool = False) -> Path:
    resolved = _trusted_path(path, executable=executable)
    if not resolved.is_relative_to(root):
        raise SnapRuntimeError(f'Semgrep runtime path escapes its revision: {path}')
    return resolved


def _metadata(path: Path, root: Path) -> tuple[str, tuple]:
    path = _inside(path, root)
    raw, st = read_capped_with_stat(path, _METADATA_CAP)
    if raw is None or st is None:
        raise SnapRuntimeError(f'Cannot read bounded Semgrep runtime metadata: {path}')
    if st.st_mode & 0o022 or st.st_uid not in {0, 65534}:
        raise SnapRuntimeError(f'Untrusted Semgrep metadata: {path}')
    return raw.decode('utf-8', errors='strict'), (str(path), hashlib.sha256(raw).hexdigest())


def _field(text: str, name: str, *, separator: str = ':') -> str:
    values = []
    for line in text.split('\n'):  # line-model: field values strip CR below; metadata records split only at LF.
        key, found, value = line.partition(separator)
        if found and key.rstrip(' \t') == name:
            values.append(value.strip(' \t\r'))
            if len(values) > 1:
                break
    if len(values) != 1:
        raise SnapRuntimeError(f'Missing or duplicate Semgrep metadata field: {name}')
    value = values[0]
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    return value


def _distribution_metadata(site: Path) -> Path:
    """Find one metadata directory while closing the actual directory stream."""
    selected = None
    with os.scandir(site) as entries:
        for count, entry in enumerate(entries, 1):
            if count > _SITE_ENTRY_CAP:
                raise SnapRuntimeError('Semgrep package directory exceeds its discovery budget')
            if not (entry.name.startswith('semgrep-') and entry.name.endswith('.dist-info')):
                continue
            if not entry.is_dir(follow_symlinks=False):
                raise SnapRuntimeError('Unsupported Semgrep distribution directory')
            if selected is not None:
                raise SnapRuntimeError('Ambiguous Semgrep distribution metadata')
            selected = site / entry.name / 'METADATA'
    if selected is None:
        raise SnapRuntimeError('Missing Semgrep distribution metadata')
    return selected


def _revision(name: str) -> tuple[Path, Path]:
    alias = _SNAP_ROOT / name / 'current'
    if not alias.is_symlink():
        raise SnapRuntimeError(f'Missing Snap revision selector: {alias}')
    target = os.readlink(alias)
    if re.fullmatch(r'[1-9][0-9]*', target) is None:
        raise SnapRuntimeError(f'Unsupported Snap revision selector: {alias}')
    root = _trusted_path(alias)
    expected = (_SNAP_ROOT / name / target).absolute()
    if root != expected or not root.is_dir():
        raise SnapRuntimeError(f'Escaping Snap revision selector: {alias}')
    _readonly_revision(root)
    return alias, root


@dataclass(frozen=True)
class SnapRuntime:
    launcher: str
    app_root: Path
    base_root: Path
    interpreter: Path
    frontend: Path
    site_packages: Path
    stdlib: Path
    version: str
    identity: tuple

    @property
    def command_prefix(self) -> tuple[str, str]:
        return str(self.interpreter), str(self.frontend)

    @property
    def tool_paths(self) -> tuple[str, ...]:
        return (str(self.interpreter), str(self.stdlib), str(self.frontend),
                str(self.site_packages))

    def child_environment(self, environment: dict[str, str]) -> dict[str, str]:
        from core.config import RaptorConfig
        # Use the existing allowlist/blocklist and credential policy before
        # adding the tightly scoped packaged-Python exceptions. Keep generated
        # safe defaults (Git isolation, CI marker, trusted temporary directory).
        result = RaptorConfig.get_safe_env()
        credentials = RaptorConfig._metadata_credential_names()
        for name, value in environment.items():
            allowed = (name in RaptorConfig.SAFE_ENV_ALLOWLIST or
                       name.startswith(RaptorConfig.SAFE_ENV_PREFIXES) or
                       name in RaptorConfig.PROXY_ENV_VARS)
            if (allowed and not RaptorConfig.is_dangerous_env_name(name) and
                    name not in credentials and
                    not name.endswith(('_API_KEY', '_API_TOKEN'))):
                result[name] = value
        result = {k: v for k, v in result.items()
                  if not k.startswith('PYTHON') and k not in {
                      'VIRTUAL_ENV', 'CONDA_PREFIX', '__PYVENV_LAUNCHER__'}}
        result.update(PYTHONHOME=str(self.base_root / 'usr'),
                      PYTHONPATH=str(self.site_packages),
                      PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1',
                      PATH=f'{self.base_root}/usr/bin:/usr/bin:/bin')
        return result

    def validate_output_version(self, text: str, *, max_output_bytes: int) -> None:
        """Bind output to this selected package before accepting its evidence."""
        if (not isinstance(text, str) or len(text) > max_output_bytes or
                len(text.encode('utf-8', errors='surrogatepass')) > max_output_bytes):
            raise SnapRuntimeError('Semgrep JSON output exceeds the output budget')
        try:
            data = json.loads(text)
        except (ValueError, RecursionError) as exc:
            raise SnapRuntimeError('Semgrep JSON output is not a valid object') from exc
        actual = data.get('version') if isinstance(data, dict) else None
        if actual != self.version:
            raise SnapRuntimeError(
                f'Semgrep output version does not match selected runtime {self.version}')

    def validate(self) -> None:
        current = resolve_snap_runtime(self.launcher)
        if current is None or current != self:
            raise SnapRuntimeError('Semgrep Snap changed after runtime selection; retry the scan')


def resolve_snap_runtime(binary: str) -> SnapRuntime | None:
    """Return a pinned runtime for recognized Snap dispatch, else None.

    Reads bounded installed metadata, never imports the application or runs a
    command. The fixed supported entrypoint is pysemgrep; metadata commands and
    environment mappings are not executed or evaluated.
    """
    try:
        if not os.path.isabs(binary) and os.sep not in binary:
            return None  # Caller must select bare names through PATH first.
        selected = Path(binary).absolute()
        resolved = selected.resolve(strict=False)
        dispatchers = {p.resolve(strict=True) for p in _DISPATCHERS if p.exists()}
        if resolved not in dispatchers:
            if resolved.is_relative_to(_SNAP_ROOT / 'semgrep'):
                raise SnapRuntimeError('Select the Semgrep Snap launcher, not a Python script inside its revision')
            if selected == _SNAP_ROOT / 'bin/semgrep':
                raise SnapRuntimeError('Semgrep Snap launcher does not identify a trusted dispatcher')
            return None
        if selected.name != 'semgrep':
            raise SnapRuntimeError('Snap launcher is not the Semgrep application')
        _trusted_path(resolved, executable=True)
        alias, app = _revision('semgrep')
        metadata, metadata_id = _metadata(app / 'meta/snap.yaml', app)
        if _field(metadata, 'name') != 'semgrep':
            raise SnapRuntimeError('Snap metadata does not identify Semgrep')
        version = _field(metadata, 'version')
        if re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version) is None:
            raise SnapRuntimeError('Unsupported Semgrep Snap version metadata')
        base_name = _field(metadata, 'base')
        if re.fullmatch(r'core(?:20|22|24|26)', base_name) is None:
            raise SnapRuntimeError('Unsupported Semgrep Snap base')
        base_alias, base = _revision(base_name)
        config, config_id = _metadata(app / 'pyvenv.cfg', app)
        py_version = _field(config, 'version', separator='=')
        match = re.fullmatch(r'(3\.[0-9]+)\.[0-9]+', py_version)
        if match is None:
            raise SnapRuntimeError('Unsupported Semgrep Python ABI metadata')
        python_name = 'python' + match[1]
        interpreter = _inside(base / 'usr/bin' / python_name, base, executable=True)
        stdlib = _inside(base / 'usr/lib' / python_name, base)
        site = _inside(app / 'lib' / python_name / 'site-packages', app)
        if not stdlib.is_dir() or not site.is_dir():
            raise SnapRuntimeError('Semgrep Python runtime directories are missing')
        frontend = _inside(app / 'bin/pysemgrep', app, executable=True)
        engine = _inside(site / 'semgrep/bin/semgrep-core', app, executable=True)
        distribution_path = _distribution_metadata(site)
        distribution, distribution_id = _metadata(distribution_path, app)
        if _field(distribution, 'Name') != 'semgrep' or _field(distribution, 'Version') != version:
            raise SnapRuntimeError('Semgrep package and Snap version metadata disagree')
        identity = (str(selected), str(alias), os.readlink(alias), str(base_alias),
                    os.readlink(base_alias), metadata_id, config_id, distribution_id,
                    *(_identity(p) for p in (resolved, app, base, interpreter, stdlib, site, frontend, engine)))
        return SnapRuntime(str(selected), app, base, interpreter, frontend, site,
                           stdlib, version, identity)
    except SnapRuntimeError:
        raise
    except (OSError, ValueError, RuntimeError, IndexError) as exc:
        raise SnapRuntimeError(f'Cannot safely use installed Semgrep Snap runtime: {exc}') from exc
