"""Recover distributor-published notices bound to the locked Cargo source.

Debian copyright files are distributor evidence, not upstream-authored notices.
Discovery uses the current public source pool; unrelated versions and changed
library sources must never inherit another release's copyright attribution.
"""
from dataclasses import asdict, dataclass
from email.parser import Parser
import hashlib
import http.client
import io
import lzma
from pathlib import PurePosixPath
import re
import tarfile

MAX_ARCHIVE = 64 * 1024 * 1024
MAX_METADATA = 4 * 1024 * 1024
MAX_TEXT = 512 * 1024
MAX_EXPANDED = 512 * 1024 * 1024



@dataclass(frozen=True)
class DistributorNoticeProof:
    """Source-control and archive identities retained with an unchanged notice."""
    publisher: str
    source_package: str
    source_version: str
    source_control_url: str
    source_control_sha256: str
    source_control_text: str
    upstream_archive_url: str
    upstream_archive_sha256: str
    packaging_archive_url: str
    packaging_archive_sha256: str
    source_match: dict
    notice_sha256: str
    scope: str


def _fields(text):
    message = Parser().parsestr(text)
    if any(len(message.get_all(key)) != 1 for key in message.keys()):
        raise ValueError('ambiguous Debian source metadata')
    return message


def _checksums(raw, source, version):
    text = raw.decode('utf-8').replace('\r\n', '\n')
    if text.startswith('-----BEGIN PGP SIGNED MESSAGE-----\n'):
        text = text.split('\n\n', 1)[1].split('\n-----BEGIN PGP SIGNATURE-----', 1)[0]
    fields = _fields(text)
    if fields['Source'] != source or fields['Version'] != version:
        raise ValueError('Debian source identity differs from selected release')
    checks = {}
    for line in fields.get('Checksums-Sha256', '').splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r'\s*([a-f0-9]{64})\s+([0-9]+)\s+([A-Za-z0-9_.+~-]+)\s*', line)
        if not match or match[3] in checks:
            raise ValueError('invalid Debian source checksums')
        checks[match[3]] = (match[1], int(match[2]))
    return checks


def _archive(raw, *, mode, prefix=None, copyright=False):
    hashes, texts, expanded = {}, {}, 0
    if len(raw) > MAX_ARCHIVE:
        raise ValueError('Debian source archive exceeds compressed budget')
    with tarfile.open(fileobj=io.BytesIO(raw), mode=mode) as archive:
        for index, member in enumerate(archive):
            expanded += member.size
            name = member.name.rstrip('/')
            path = PurePosixPath(name)
            if (index >= 30000 or expanded > MAX_EXPANDED or path.is_absolute()
                    or '..' in path.parts or '\\' in name or str(path) != name):
                raise ValueError('unsafe or oversized Debian source archive')
            if prefix:
                if name == prefix and member.isdir():
                    continue
                if not name.startswith(prefix + '/'):
                    raise ValueError('Debian upstream archive has an unrelated source root')
                name = name[len(prefix) + 1:]
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError('Debian source notice matching requires regular files')
            with archive.extractfile(member) as stream:
                if copyright and name == 'debian/copyright':
                    if member.size > MAX_TEXT:
                        raise ValueError('Debian copyright exceeds text budget')
                    body = stream.read(MAX_TEXT + 1)
                    texts[name] = body
                    digest = hashlib.sha256(body).hexdigest()
                else:
                    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            if name in hashes and hashes[name] != digest:
                raise ValueError('ambiguous duplicate Debian source member')
            # Some Debian repacks repeat the identical original manifest.
            # Compare its bytes in memory; never extract or follow tar paths.
            hashes[name] = digest
    return hashes, texts.get('debian/copyright')


def _canonical_license(value):
    # Debian's historical Expat name denotes the SPDX MIT identifier. Keep the
    # original declarations and full distributor text alongside this comparison.
    alternatives = re.split(r'\s+OR\s+', value.strip(), flags=re.I)
    if all(re.fullmatch(r'[A-Za-z0-9.+-]+', part) for part in alternatives):
        return tuple(sorted({'MIT' if part.upper() == 'EXPAT' else part.upper() for part in alternatives}))
    # Complex expressions must still match as declarations; no legal-text
    # interpretation or guessed rewrite of compound exceptions is performed.
    return re.sub(r'\s+', '', value).upper()


def _copyright(body, name, declared, repository):
    text = body.decode('utf-8')
    if not body.strip() or b'\x00' in body or len(body) > MAX_TEXT:
        raise ValueError('invalid Debian copyright text')
    paragraphs = [_fields(p) for p in text.lstrip('\\').split('\n\n') if p.strip()]
    header = paragraphs[0]
    if (header.get('Upstream-Name', '').replace('_', '-').lower() != name.replace('_', '-').lower()
            or header.get('Source', '').rstrip('/').removesuffix('.git') != repository.rstrip('/').removesuffix('.git')):
        raise ValueError('Debian copyright does not identify the publisher project')
    project = [p for p in paragraphs if p.get('Files', '').strip() == '*']
    if len(project) != 1 or not project[0].get('Copyright', '').strip():
        raise ValueError('Debian copyright lacks project attribution')
    license_name = project[0].get('License', '').splitlines()[0]
    if _canonical_license(license_name) != _canonical_license(declared):
        raise ValueError('distributor and publisher license declarations differ')
    if re.search(r'\b(?:TODO|FIXME|UNKNOWN)\b', project[0]['Copyright'], re.I):
        raise ValueError('Debian copyright attribution is unresolved')


def recover_debian_notice(name, version, raw, declared, repository, fetch):
    """Return an unchanged distributor notice and its checksum/source proof."""
    if not isinstance(declared, str) or not isinstance(repository, str):
        return None, None
    source = 'rust-' + name.replace('_', '-').lower()
    if not re.fullmatch(r'rust-[a-z0-9][a-z0-9-]*', source) or not re.fullmatch(r'[A-Za-z0-9.+-]+', version):
        return None, None
    base = f'https://deb.debian.org/debian/pool/main/{source[0]}/{source}/'
    listing = fetch(base, max_bytes=MAX_METADATA)
    if len(listing) > MAX_METADATA:
        raise ValueError('Debian pool index exceeds metadata budget')
    pattern = re.compile(re.escape(source + '_' + version + '-') + r'[A-Za-z0-9.+~]+\.dsc\Z')
    candidates = sorted({f for f in re.findall(r'href="([^"]+)"', listing.decode('utf-8')) if pattern.fullmatch(f)}, reverse=True)
    for filename in candidates[:5]:
        try:
            dsc = fetch(base + filename, max_bytes=MAX_TEXT)
            if len(dsc) > MAX_TEXT:
                raise ValueError('Debian source control exceeds text budget')
            release = filename[len(source) + 1:-4]
            checks = _checksums(dsc, source, release)
            upstream = source + '_' + version + '.orig.tar.gz'
            packaging = source + '_' + release + '.debian.tar.xz'
            expected, size = checks[upstream]
            match = {'kind': 'archive_sha256', 'crate_sha256': hashlib.sha256(raw).hexdigest()}
            if expected != match['crate_sha256']:
                if size > MAX_ARCHIVE:
                    raise ValueError('Debian upstream source exceeds archive budget')
                original = fetch(base + upstream, max_bytes=MAX_ARCHIVE)
                if len(original) != size or hashlib.sha256(original).hexdigest() != expected:
                    raise ValueError('Debian upstream source differs from source checksums')
                locked, _ = _archive(raw, mode='r|gz', prefix=name + '-' + version)
                repacked, _ = _archive(original, mode='r|gz', prefix=name + '-' + version)
                missing = set(locked) - set(repacked)
                if (not any(p.startswith('src/') and p.endswith('.rs') for p in locked)
                        or not {'Cargo.toml', 'Cargo.toml.orig'} <= set(repacked)
                        or set(repacked) - set(locked)
                        or any(locked[p] != digest for p, digest in repacked.items())
                        or any(PurePosixPath(p).parts[0] not in {'examples', 'tests', 'benches'} for p in missing)):
                    raise ValueError('Debian repack differs from locked library source or manifests')
                match.update(kind='repacked_source_files', matched_files=[{'path': p, 'sha256': repacked[p]} for p in sorted(repacked)],
                             omitted_development_files=sorted(missing))
            elif len(raw) != size:
                raise ValueError('Debian source size differs from locked archive')
            expected_packaging, size_packaging = checks[packaging]
            if size_packaging > MAX_ARCHIVE:
                raise ValueError('Debian packaging exceeds archive budget')
            packed = fetch(base + packaging, max_bytes=MAX_ARCHIVE)
            if len(packed) != size_packaging or hashlib.sha256(packed).hexdigest() != expected_packaging:
                raise ValueError('Debian packaging differs from source checksums')
            _, body = _archive(packed, mode='r|xz', copyright=True)
            if body is None:
                raise ValueError('Debian source lacks distributor copyright')
            _copyright(body, name, declared, repository)
            proof = asdict(DistributorNoticeProof(
                publisher='Debian', source_package=source, source_version=release,
                source_control_url=base + filename, source_control_sha256=hashlib.sha256(dsc).hexdigest(),
                source_control_text=dsc.decode('utf-8'), upstream_archive_url=base + upstream,
                upstream_archive_sha256=expected, packaging_archive_url=base + packaging,
                packaging_archive_sha256=expected_packaging, source_match=match,
                notice_sha256=hashlib.sha256(body).hexdigest(),
                scope='Distributor-published project notice; source linkage and repack omissions are recorded separately. Not upstream-authored text or a build attestation.'))
            return proof, body
        except (OSError, ValueError, KeyError, TypeError, IndexError, tarfile.TarError, EOFError, lzma.LZMAError, http.client.HTTPException):
            continue
    return None, None
