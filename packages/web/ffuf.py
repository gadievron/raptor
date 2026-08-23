#!/usr/bin/env python3
"""Narrow ffuf integration for RAPTOR web scans.

The runner is intentionally small and opt-in: operators must provide a
wordlist, and RAPTOR constrains the ffuf URL template to the configured target
origin before spawning the external binary.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from core.json.bounded import load_json_bounded
from core.logging import get_logger
from core.sandbox import run_untrusted_networked
from core.security.redaction import is_secret_field_name, redact_secrets

logger = get_logger()

# Byte ceiling for the ffuf results file. ffuf writes it from
# responses served by the attacker-controlled web target, so its
# size is adversary-influenced. Each result row is a small dict —
# even saturated wordlist runs stay far under this cap.
_MAX_FFUF_OUTPUT_BYTES = 64 * 1024 * 1024

# Applied when a request-multiplying mode (recursion, clusterbomb) is
# enabled without an explicit -rate: unbounded fan-out against a live
# target is an operational hazard, not a scanner feature.
DEFAULT_GUARDED_RATE = 50

# Methods ffuf may send. Write methods are permitted here because the
# operator opted in explicitly; policy layers above the engine decide
# whether a run may use them at all.
ALLOWED_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")

# Keyword shape for additional wordlists (-w path:KEYWORD).
WORDLIST_KEYWORD_RE = re.compile(r"^[A-Z][A-Z0-9]*$")

ALLOWED_MODES = ("clusterbomb", "pitchfork")


def toml_basic_string(value: str) -> str:
    """Encode a Python str as a TOML basic string.

    json.dumps is ALMOST a valid TOML encoder but represents astral-plane
    characters as UTF-16 surrogate-pair escapes, which TOML forbids: the
    reference parser rejects them, and go-toml v1 (ffuf's parser) silently
    substitutes U+FFFD — corrupting a credential on the wire with no error
    anywhere. Escape explicitly instead: \\uXXXX inside the BMP,
    \\UXXXXXXXX above it. Lone surrogates (surrogateescape'd undecodable
    input bytes) have no representation and are rejected loudly.
    """
    out = ['"']
    for ch in value:
        cp = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif 0xD800 <= cp <= 0xDFFF:
            msg = (
                "ffuf option value contains an unpaired surrogate "
                "(undecodable input bytes?) and cannot be encoded"
            )
            raise ValueError(msg)
        elif cp < 0x20 or cp == 0x7F:
            out.append(f"\\u{cp:04X}")
        elif cp > 0xFFFF:
            out.append(f"\\U{cp:08X}")
        elif cp > 0x7E:
            out.append(f"\\u{cp:04X}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def parse_wordlist_args(
    raw: tuple[str, ...] | list[str],
) -> tuple[Path, tuple[tuple[Path, str], ...]]:
    """Split repeatable ``--ffuf-wordlist`` values into primary + extras.

    The first entry is the primary wordlist and uses ffuf's implicit
    ``FUZZ`` keyword; every additional entry must carry a
    ``path:KEYWORD`` suffix naming its substitution keyword.
    """
    if not raw:
        msg = "at least one ffuf wordlist is required"
        raise ValueError(msg)

    def split(entry: str) -> tuple[str, str | None]:
        path, sep, suffix = entry.rpartition(":")
        if sep and WORDLIST_KEYWORD_RE.match(suffix):
            return path, suffix
        return entry, None

    primary_path, primary_keyword = split(raw[0])
    if primary_keyword is not None:
        msg = (
            "the first ffuf wordlist uses the implicit FUZZ keyword; "
            "only additional wordlists take a :KEYWORD suffix"
        )
        raise ValueError(msg)

    extras: list[tuple[Path, str]] = []
    for entry in raw[1:]:
        path, keyword = split(entry)
        if keyword is None:
            msg = (
                f"additional ffuf wordlists need a :KEYWORD suffix "
                f"(got {entry!r}); keywords look like W2 or PARAM"
            )
            raise ValueError(msg)
        if not path:
            msg = f"ffuf wordlist entry has an empty path: {entry!r}"
            raise ValueError(msg)
        extras.append((Path(path), keyword))
    return Path(primary_path), tuple(extras)


@dataclass(frozen=True)
class FfufConfig:
    """Configuration for an explicit ffuf content-discovery run."""

    wordlist: Path
    path_template: str = "FUZZ"
    threads: int = 10
    rate: int | None = None
    timeout: int = 30
    max_runtime: int = 300
    report_limit: int = 50
    binary: str = "ffuf"
    auto_calibration: bool = True
    calibration_strategy: str | None = None
    calibration_per_host: bool = False
    encoders: tuple[str, ...] = ()
    match_status: str | None = "200,204,301,302,307,401,403,405,500"
    filter_status: str | None = "404"
    filter_size: int | None = None
    headers: tuple[str, ...] = ()
    cookies: tuple[str, ...] = ()
    method: str = "GET"
    data: str | None = None
    extra_wordlists: tuple[tuple[Path, str], ...] = ()
    mode: str | None = None
    request_file: Path | None = None
    vhost: bool = False
    vhost_host_template: str | None = None
    stop_on_403: bool = False
    stop_on_spurious: bool = False
    stop_on_all_errors: bool = False
    extensions: tuple[str, ...] = ()
    recursion: bool = False
    recursion_depth: int = 2
    recursion_strategy: str = "default"
    max_runtime_job: int | None = None
    filter_words: int | None = None
    filter_lines: int | None = None
    match_regex: str | None = None
    filter_regex: str | None = None
    match_time: str | None = None
    filter_time: str | None = None


class FfufRunner:
    """Run ffuf against a single in-scope target origin."""

    def __init__(self, base_url: str, out_dir: Path, reveal_secrets: bool = False) -> None:
        self.base_url = base_url.rstrip("/")
        self.out_dir = out_dir
        self.reveal_secrets = reveal_secrets

    def _origin(self, url: str) -> tuple[str, str, int]:
        parsed = urlparse(url)
        default_port = 443 if parsed.scheme == "https" else 80
        return (
            parsed.scheme.lower(),
            (parsed.hostname or "").lower(),
            # Explicit test: port 0 is falsy but is NOT the default port.
            parsed.port if parsed.port is not None else default_port,
        )

    def _redact(self, value: object) -> str:
        return redact_secrets(value, reveal_secrets=self.reveal_secrets)

    def _redact_cookie_value(self, cookie: str) -> str:
        if self.reveal_secrets:
            return cookie
        parts = []
        for segment in cookie.split(";"):
            prefix = segment[: len(segment) - len(segment.lstrip())]
            stripped = segment.strip()
            if "=" not in stripped:
                parts.append(segment)
                continue
            name, _value = stripped.split("=", 1)
            parts.append(f"{prefix}{name}=[REDACTED]")
        return ";".join(parts)

    def _redact_header_value(self, header: str) -> str:
        if self.reveal_secrets or ":" not in header:
            return self._redact(header)
        name, value = header.split(":", 1)
        normalized = name.strip().lower()
        if normalized in {"authorization", "proxy-authorization"}:
            return f"{name}: [REDACTED]"
        if normalized in {"cookie", "set-cookie"}:
            return f"{name}: {self._redact_cookie_value(value.strip())}"
        if is_secret_field_name(normalized) or normalized in {
            "x-api-key",
            "x-auth-token",
            "x-csrf-token",
        }:
            return f"{name}: [REDACTED]"
        return self._redact(header)

    def _redact_json_value(self, value: object) -> object:
        """Redact secret-keyed values recursively in a parsed JSON body."""
        if isinstance(value, dict):
            return {
                key: (
                    "[REDACTED]"
                    if is_secret_field_name(str(key).strip().lower())
                    else self._redact_json_value(item)
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self._redact_json_value(item) for item in value]
        if isinstance(value, str):
            return self._redact(value)
        return value

    def _redact_body(self, body: str) -> str:
        """Redact secret material from a request body before logging.

        Form-encoded bodies ('&' or ';' separated) are redacted by secret
        field name, JSON bodies by secret key name recursively. Shapes
        without a reliable name/value pairing (multipart, malformed JSON)
        are dropped wholesale rather than risking a leak — the generic
        pattern redactor has no notion of field names.
        """
        if self.reveal_secrets:
            return body
        if body.lstrip().startswith(("{", "[")):
            try:
                return json.dumps(self._redact_json_value(json.loads(body)))
            except ValueError:
                return "[REDACTED-BODY]"
        if "content-disposition" in body.lower():
            return "[REDACTED-BODY]"
        if "=" not in body:
            return self._redact(body)
        segments = []
        for segment in re.split(r"([&;])", body):
            if segment in ("&", ";"):
                segments.append(segment)
                continue
            name, sep, _value = segment.partition("=")
            if sep and is_secret_field_name(name.strip().lower()):
                segments.append(f"{name}=[REDACTED]")
            else:
                segments.append(self._redact(segment))
        return "".join(segments)

    def _describe_delivered(self, config: FfufConfig) -> str:
        """Names-and-shapes summary of the options moved into the config
        file. Values are never included — pattern-based redaction misses
        secrets in non-secret-named fields, and this line lands in the
        persistent audit log."""
        parts = [
            header.split(":", 1)[0].strip() or "<header>"
            for header in config.headers
        ]
        for cookie in config.cookies:
            names = []
            for segment in cookie.split(";"):
                name, sep, _value = segment.strip().partition("=")
                names.append(name if sep else "<cookie>")
            parts.append(f"cookie({', '.join(names)})")
        if config.data:
            parts.append(self._describe_body(config.data))
        if config.vhost:
            parts.append("Host(vhost template)")
        return "; ".join(parts) if parts else "none"

    @staticmethod
    def _describe_body(data: str) -> str:
        """Field-name/shape description of a request body, no values."""
        stripped = data.lstrip()
        if stripped.startswith(("{", "[")):
            try:
                parsed = json.loads(data)
            except ValueError:
                return f"body({len(data)} bytes, opaque)"
            if isinstance(parsed, dict):
                keys = ", ".join(sorted(str(key) for key in parsed))
                return f"body(json keys: {keys})"
            return f"body({len(data)} bytes, json)"
        if "=" in data:
            names = []
            for segment in re.split(r"[&;]", data):
                name, sep, _value = segment.partition("=")
                names.append(name if sep else "<field>")
            return f"body(form fields: {', '.join(names)})"
        return f"body({len(data)} bytes, opaque)"

    def _redact_command(self, cmd: list[str]) -> list[str]:
        redacted: list[str] = []
        redact_next_cookie = False
        redact_next_body = False
        for part in cmd:
            if redact_next_cookie:
                redacted.append(self._redact_cookie_value(part))
                redact_next_cookie = False
                continue
            if redact_next_body:
                redacted.append(self._redact_body(part))
                redact_next_body = False
                continue
            if part == "-b":
                redacted.append(part)
                redact_next_cookie = True
                continue
            if part == "-d":
                redacted.append(part)
                redact_next_body = True
                continue
            if part == "-H":
                redacted.append(part)
                continue
            if redacted and redacted[-1] == "-H":
                redacted.append(self._redact_header_value(part))
                continue
            redacted.append(self._redact(part))
        return redacted

    def build_url_template(
        self,
        path_template: str,
        keywords: tuple[str, ...] = ("FUZZ",),
    ) -> str:
        """Build and scope-check the ffuf URL template.

        Accepting a raw URL from the CLI without checking it would let a
        saved RAPTOR config or copied command accidentally aim ffuf at a
        different host. Treat the template like WebClient paths: relative
        paths are anchored to ``base_url``; absolute URLs are allowed only
        when their normalized origin matches.

        The URL itself does not have to carry a fuzz keyword — request-body
        and header fuzzing keep the URL fixed. ``build_command`` enforces
        that at least one keyword appears somewhere in the request.

        ``urljoin`` intentionally normalizes ``..`` segments before the origin
        check. That can move a relative template outside the base path while
        staying on the same origin; this integration scopes ffuf to the target
        host/origin rather than to a specific subpath.
        """
        url_template = urljoin(self.base_url + "/", path_template)
        # Neutralize EVERY substitution keyword before the origin compare:
        # an extra wordlist keyword left in the hostname would otherwise
        # survive the probe and lowercase straight into the target host.
        probe_url = url_template
        for keyword in keywords:
            probe_url = probe_url.replace(keyword, "raptor-scope-probe")
        if self._origin(probe_url) != self._origin(self.base_url):
            msg = (
                "ffuf path template is outside configured target scope: "
                f"{self._redact(probe_url)}"
            )
            raise ValueError(msg)
        return url_template

    @staticmethod
    def _fuzz_keywords(config: FfufConfig) -> tuple[str, ...]:
        """Keywords ffuf will substitute for this configuration."""
        return ("FUZZ", *(keyword for _path, keyword in config.extra_wordlists))

    _MAX_REQUEST_FILE_BYTES = 1024 * 1024

    def _read_scoped_request_file(self, config: FfufConfig) -> str:
        """The raw request file's text, origin-scope-checked.

        Raw-request mode replaces the URL template, so origin
        enforcement moves here — and it must mirror ffuf's own
        ``parseRawRequest`` EXACTLY, failing closed on every ambiguity,
        because any divergence between what we check and what ffuf
        targets is a scope bypass:

        * ffuf takes an absolute-URI request line over the Host header
          entirely — we reject absolute-URI request lines;
        * ffuf stores headers in a map (last duplicate wins) and targets
          the case-sensitive ``Host`` key — we require exactly one
          host-named header, spelled exactly ``Host``;
        * ffuf TrimSpaces folded (leading-whitespace) lines into headers
          — we reject folding;
        * ffuf stops header parsing at the first blank line and drops a
          final unterminated line — we scan only the terminated header
          section and require the blank-line terminator;
        * the compare uses the EFFECTIVE port (explicit or the
          ``-request-proto`` scheme default) — a bare-host Host header
          must not widen scope to a different port on the same machine.
        """
        path = Path(config.request_file or "")
        if path.stat().st_size > self._MAX_REQUEST_FILE_BYTES:
            msg = "ffuf request file exceeds 1 MiB"
            raise ValueError(msg)
        text = path.read_text(encoding="utf-8", errors="replace")
        # '\n' only: ffuf reads with ReadString('\n'); Python's
        # splitlines() also splits on VT/FF/NEL/U+2028/29 — another
        # divergence class.
        lines = text.split("\n")
        request_line = lines[0].strip()
        parts = request_line.split(" ")
        if len(parts) < 3:
            msg = (
                "ffuf request file must start with a "
                "'METHOD /path HTTP/x.y' request line"
            )
            raise ValueError(msg)
        if parts[1].lower().startswith("http"):
            msg = (
                "ffuf raw-request mode requires a path-only request line — "
                "ffuf would take the target from an absolute URI and ignore "
                "the Host header"
            )
            raise ValueError(msg)

        host_named: list[tuple[str, str]] = []
        terminated = False
        for line in lines[1:]:
            stripped = line.rstrip("\r")
            if stripped.strip() == "":
                terminated = True
                break
            if stripped[:1] in (" ", "\t"):
                msg = (
                    "ffuf request file must not contain folded "
                    "(leading-whitespace) header lines"
                )
                raise ValueError(msg)
            name, sep, value = stripped.partition(":")
            if not sep:
                msg = f"malformed header line in ffuf request file: {stripped[:40]!r}"
                raise ValueError(msg)
            if name.strip().lower() == "host":
                host_named.append((name.strip(), value.strip()))
        if not terminated:
            msg = (
                "ffuf request file must terminate its headers with a blank "
                "line (ffuf drops a final unterminated line)"
            )
            raise ValueError(msg)
        if len(host_named) != 1:
            msg = (
                f"ffuf request file must carry exactly one Host header "
                f"(found {len(host_named)})"
            )
            raise ValueError(msg)
        host_name, raw_host = host_named[0]
        if host_name != "Host":
            msg = (
                "ffuf targets the exact-case 'Host' header; spell it 'Host:' "
                f"(got {host_name!r})"
            )
            raise ValueError(msg)

        # Neutralize keywords before the compare — a keyword inside the
        # Host would be substituted at runtime (same rule as the URL
        # template and vhost probes).
        probe = raw_host
        for keyword in self._fuzz_keywords(config):
            probe = probe.replace(keyword, "raptor-scope-probe")
        probe_host, probe_port = self._split_host_port(probe)
        scheme = (urlparse(self.base_url).scheme or "https").lower()
        default_port = 443 if scheme == "https" else 80
        parsed_base = urlparse(self.base_url)
        expected_host = (parsed_base.hostname or "").lower()
        expected_port = (
            parsed_base.port if parsed_base.port is not None else default_port
        )
        effective_probe_port = probe_port if probe_port is not None else default_port
        if probe_host != expected_host or effective_probe_port != expected_port:
            msg = (
                "ffuf request file Host is outside the configured target "
                f"scope: {self._redact(raw_host)}"
            )
            raise ValueError(msg)
        return text

    @staticmethod
    def _split_host_port(value: str) -> tuple[str, int | None]:
        """(lowercased host, explicit port or None); IPv6-bracket aware."""
        value = value.strip()
        if value.startswith("["):
            inside, _bracket, rest = value[1:].partition("]")
            host = inside.lower()
            if rest.startswith(":") and rest[1:].isdigit():
                return host, int(rest[1:])
            return host, None
        host, sep, port = value.rpartition(":")
        if sep and port.isdigit():
            return host.lower(), int(port)
        return value.lower(), None

    def _build_vhost_header(self, config: FfufConfig) -> str | None:
        """Synthesize and scope-check the fuzzed Host header for vhost mode.

        The TCP destination stays pinned to the target host by the egress
        proxy regardless — the Host header only selects virtual hosts on
        that same server — but the template is still constrained to
        subdomains of the target so a saved config cannot quietly probe a
        sibling engagement's namespace.
        """
        if not config.vhost:
            return None
        parsed = urlparse(self.base_url)
        target_host = (parsed.hostname or "").lower()
        port_suffix = f":{parsed.port}" if parsed.port is not None else ""
        template = config.vhost_host_template or f"FUZZ.{target_host}{port_suffix}"
        if "\n" in template or "\r" in template:
            msg = "ffuf vhost host template must not contain newlines"
            raise ValueError(msg)
        keywords = self._fuzz_keywords(config)
        if not any(kw in template for kw in keywords):
            msg = (
                "ffuf vhost host template must contain a wordlist keyword "
                f"(got {template!r})"
            )
            raise ValueError(msg)
        # The suffix check runs on the keyword-NEUTRALIZED template: a
        # keyword hiding inside the "suffix" would otherwise be
        # substituted by ffuf and escape the target namespace. The base
        # URL's own explicit port is allowed after the host.
        probe = template
        for keyword in keywords:
            probe = probe.replace(keyword, "raptor-scope-probe")
        probe = probe.lower()
        if port_suffix and probe.endswith(port_suffix):
            probe = probe[: -len(port_suffix)]
        if not probe.endswith("." + target_host):
            msg = (
                "ffuf vhost host template must stay under the target host "
                f"(expected a template ending in .{target_host}, "
                f"got {self._redact(template)})"
            )
            raise ValueError(msg)
        return f"Host: {template}"

    @classmethod
    def _require_fuzz_keyword(
        cls,
        config: FfufConfig,
        url_template: str,
        extra_haystacks: tuple[str, ...] = (),
    ) -> None:
        """Every keyword needs a substitution point; a dead wordlist is a
        config error, not a silent no-op."""
        keywords = cls._fuzz_keywords(config)
        # Cookies count: ffuf folds -b values into the effective Cookie
        # header before its own keyword check, so session-token fuzzing
        # via -b 'session=FUZZ' is legitimate.
        haystacks = [
            url_template,
            config.data or "",
            *config.headers,
            *config.cookies,
            *extra_haystacks,
        ]
        missing = [
            kw for kw in keywords
            if not any(kw in haystack for haystack in haystacks)
        ]
        if len(missing) == len(keywords):
            msg = (
                "ffuf configuration has no substitution point: put FUZZ in "
                "the URL template, request body, a header, or a cookie value"
            )
            raise ValueError(msg)
        if missing:
            msg = (
                f"ffuf wordlist keyword(s) never used: {', '.join(missing)}; "
                "place each keyword in the URL template, request body, a "
                "header, or a cookie value"
            )
            raise ValueError(msg)

    _TIME_MATCHER_RE = re.compile(r"^[<>]\d+$")

    @staticmethod
    def _validate_config(config: FfufConfig) -> None:
        """Reject configurations that cannot form a safe ffuf argv."""
        for wordlist_path in (
            config.wordlist,
            *(path for path, _keyword in config.extra_wordlists),
        ):
            # ffuf splits -w values on ':' (keyword suffix) and ','
            # (multi-value); a path containing either validates locally
            # but is misparsed inside ffuf.
            path_text = str(wordlist_path)
            if ":" in path_text or "," in path_text:
                msg = (
                    "ffuf wordlist paths must not contain ':' or ',' "
                    f"(ffuf splits -w on them): {path_text}"
                )
                raise ValueError(msg)
        if not config.wordlist.is_file():
            msg = f"ffuf wordlist not found: {config.wordlist}"
            raise FileNotFoundError(msg)
        if config.threads < 1:
            msg = "ffuf threads must be >= 1"
            raise ValueError(msg)
        if config.rate is not None and config.rate < 1:
            msg = "ffuf rate must be >= 1 when set"
            raise ValueError(msg)
        if config.timeout < 1:
            msg = "ffuf timeout must be >= 1"
            raise ValueError(msg)
        if config.max_runtime < 1:
            msg = "ffuf max runtime must be >= 1"
            raise ValueError(msg)
        if config.report_limit < 0:
            msg = "ffuf report limit must be >= 0"
            raise ValueError(msg)
        if config.filter_size is not None and config.filter_size < 0:
            msg = "ffuf filter size must be >= 0 when set"
            raise ValueError(msg)
        if config.method.upper() not in ALLOWED_METHODS:
            msg = f"ffuf method must be one of {', '.join(ALLOWED_METHODS)}"
            raise ValueError(msg)
        if config.calibration_strategy is not None:
            if config.calibration_strategy not in ("basic", "advanced"):
                msg = "ffuf calibration strategy must be 'basic' or 'advanced'"
                raise ValueError(msg)
            if not config.auto_calibration:
                msg = "ffuf calibration strategy requires auto-calibration"
                raise ValueError(msg)
        if config.calibration_per_host and not config.auto_calibration:
            msg = "ffuf per-host calibration requires auto-calibration"
            raise ValueError(msg)
        for spec in config.encoders:
            keyword, sep, chain = spec.partition(":")
            # ffuf splits the chain on single spaces (a doubled space
            # becomes an empty encoder name and a hard startup error),
            # so accept exactly what ffuf accepts: single-space-joined
            # lowercase-alphanumeric encoder names.
            tokens = chain.split(" ")
            if (
                not sep
                or not WORDLIST_KEYWORD_RE.match(keyword)
                or not tokens
                or not all(re.fullmatch(r"[a-z0-9]+", token) for token in tokens)
            ):
                msg = (
                    f"ffuf encoder spec must look like 'FUZZ:urlencode' or "
                    f"'W2:urlencode b64encode' (got {spec!r})"
                )
                raise ValueError(msg)
        if config.request_file is not None:
            if not Path(config.request_file).is_file():
                msg = f"ffuf request file not found: {config.request_file}"
                raise FileNotFoundError(msg)
            if config.path_template != "FUZZ":
                msg = (
                    "ffuf raw-request mode carries its own request line; "
                    "drop the path template"
                )
                raise ValueError(msg)
            if config.method.upper() != "GET" or config.data:
                msg = (
                    "ffuf raw-request mode carries its own method and body; "
                    "drop -X/-d options"
                )
                raise ValueError(msg)
            if config.vhost:
                msg = "ffuf raw-request mode cannot be combined with vhost mode"
                raise ValueError(msg)
            if config.recursion:
                msg = "ffuf recursion requires a URL template, not a request file"
                raise ValueError(msg)
        if config.vhost_host_template is not None and not config.vhost:
            msg = "ffuf vhost host template requires vhost mode"
            raise ValueError(msg)
        if config.vhost and config.recursion:
            msg = (
                "ffuf vhost mode fuzzes the Host header against a fixed URL "
                "and cannot be combined with recursion"
            )
            raise ValueError(msg)
        if config.vhost and config.extensions:
            # -e extends every substituted keyword value; in vhost mode
            # that appends '.php' to Host values — junk requests.
            msg = "ffuf extensions cannot be combined with vhost mode"
            raise ValueError(msg)
        if config.recursion and config.extra_wordlists:
            # Upstream documents recursion as FUZZ-only; the multi-keyword
            # interaction is unsupported territory.
            msg = (
                "ffuf recursion supports only the FUZZ keyword and cannot "
                "be combined with additional wordlists"
            )
            raise ValueError(msg)
        if config.vhost and any(
            header.split(":", 1)[0].strip().lower() == "host"
            for header in config.headers
            if ":" in header
        ):
            msg = (
                "ffuf vhost mode synthesizes the Host header; remove the "
                "explicit Host header or drop vhost mode"
            )
            raise ValueError(msg)
        if config.mode is not None and config.mode not in ALLOWED_MODES:
            msg = f"ffuf mode must be one of {', '.join(ALLOWED_MODES)}"
            raise ValueError(msg)
        if config.mode is not None and not config.extra_wordlists:
            msg = "ffuf mode requires additional wordlists (-w path:KEYWORD)"
            raise ValueError(msg)
        keywords = ["FUZZ"]
        for path, keyword in config.extra_wordlists:
            if not path.is_file():
                msg = f"ffuf wordlist not found: {path}"
                raise FileNotFoundError(msg)
            if not WORDLIST_KEYWORD_RE.match(keyword):
                msg = (
                    f"ffuf wordlist keyword {keyword!r} must be uppercase "
                    "alphanumeric starting with a letter (e.g. W2, PARAM)"
                )
                raise ValueError(msg)
            keywords.append(keyword)
        if len(set(keywords)) != len(keywords):
            msg = "ffuf wordlist keywords must be unique (FUZZ is reserved for the primary)"
            raise ValueError(msg)
        for spec in config.encoders:
            keyword = spec.partition(":")[0]
            if keyword not in keywords:
                msg = (
                    f"ffuf encoder names unknown keyword {keyword!r}; "
                    "declare its wordlist first"
                )
                raise ValueError(msg)
        for kw in keywords:
            for other in keywords:
                if kw != other and kw in other:
                    # ffuf substitutes keywords as raw strings; FUZZ inside
                    # FUZZ2 would corrupt the other keyword's placeholder.
                    msg = (
                        f"ffuf wordlist keyword {kw!r} is a substring of "
                        f"{other!r}; keywords must not contain each other"
                    )
                    raise ValueError(msg)
        if not config.vhost:
            # A fuzzed Host header outside vhost mode would be wire-identical
            # to vhost mode while skipping its target-suffix scope check —
            # the one control the egress proxy cannot back up.
            for header in config.headers:
                if ":" not in header:
                    continue
                header_name, header_value = header.split(":", 1)
                if header_name.strip().lower() == "host" and any(
                    kw in header_value for kw in keywords
                ):
                    msg = (
                        "fuzzing the Host header requires vhost mode, which "
                        "scope-checks the host template; use --ffuf-vhost"
                    )
                    raise ValueError(msg)
        if config.recursion_depth < 1:
            msg = "ffuf recursion depth must be >= 1"
            raise ValueError(msg)
        if config.recursion_strategy not in ("default", "greedy"):
            msg = "ffuf recursion strategy must be 'default' or 'greedy'"
            raise ValueError(msg)
        if config.max_runtime_job is not None and config.max_runtime_job < 1:
            msg = "ffuf max runtime per job must be >= 1 when set"
            raise ValueError(msg)
        if config.filter_words is not None and config.filter_words < 0:
            msg = "ffuf filter words must be >= 0 when set"
            raise ValueError(msg)
        if config.filter_lines is not None and config.filter_lines < 0:
            msg = "ffuf filter lines must be >= 0 when set"
            raise ValueError(msg)
        for label, ext in (("extension", e) for e in config.extensions):
            if (
                len(ext) < 2
                or not ext.startswith(".")
                or any(c in ext for c in ",\n\r\t ")
            ):
                msg = (
                    f"ffuf {label} must look like '.php' "
                    f"(got {ext!r}): leading dot, no commas or whitespace"
                )
                raise ValueError(msg)
        for label, value in (
            ("match regex", config.match_regex),
            ("filter regex", config.filter_regex),
        ):
            # Deliberately not compiled here: ffuf uses Go regexp, and
            # Python acceptance is neither necessary nor sufficient.
            # ffuf's own config error surfaces through the returncode.
            if value is not None and ("\n" in value or "\r" in value):
                msg = f"ffuf {label} must not contain newlines"
                raise ValueError(msg)
        for label, value in (
            ("match time", config.match_time),
            ("filter time", config.filter_time),
        ):
            if value is not None and not FfufRunner._TIME_MATCHER_RE.match(value):
                msg = f"ffuf {label} must look like '>100' or '<100' (milliseconds)"
                raise ValueError(msg)
        if any("\n" in header or "\r" in header for header in config.headers):
            msg = "ffuf headers must not contain newlines"
            raise ValueError(msg)
        if any("\n" in cookie or "\r" in cookie for cookie in config.cookies):
            msg = "ffuf cookies must not contain newlines"
            raise ValueError(msg)
        # Beyond CR/LF: Go's net/http refuses to SEND a header containing
        # any control character, so ffuf would exit 0 having made zero
        # requests — a run that reads as "no findings". Fail loudly here.
        if any(
            any(ord(c) < 0x20 or ord(c) == 0x7F for c in value)
            for value in (*config.headers, *config.cookies)
        ):
            msg = "ffuf headers and cookies must not contain control characters"
            raise ValueError(msg)
        if any(
            ":" not in header or not header.split(":", 1)[0].strip()
            for header in config.headers
        ):
            msg = "ffuf headers must be in 'Name: value' form"
            raise ValueError(msg)

    def build_config_file_content(self, config: FfufConfig) -> str | None:
        """TOML for the credential-bearing options (headers, cookies, body).

        Anything on the child argv is readable by every same-UID process
        via /proc; delivering these values through ffuf's ``-config`` file
        keeps them off it. Only the secret-carrying options move — the
        rest of the argv stays self-describing for logs and audit trails.

        Values are encoded with :func:`toml_basic_string`, which escapes
        every metacharacter and rejects unencodable input, so header,
        cookie, and body content cannot break out of its TOML field.
        """
        headers = list(config.headers)
        vhost_header = self._build_vhost_header(config)
        if vhost_header is not None:
            headers.append(vhost_header)
        if not headers and not config.cookies and not config.data:
            return None
        lines = ["[http]"]
        if headers:
            lines.append("    headers = [")
            lines.extend(f"        {toml_basic_string(header)}," for header in headers)
            lines.append("    ]")
        if config.cookies:
            lines.append("    cookies = [")
            lines.extend(f"        {toml_basic_string(cookie)}," for cookie in config.cookies)
            lines.append("    ]")
        if config.data:
            lines.append(f"    data = {toml_basic_string(config.data)}")
        return "\n".join(lines) + "\n"

    def build_command(
        self,
        config: FfufConfig,
        output_file: Path,
        config_file: Path | None = None,
    ) -> list[str]:
        """Return argv for a safe, non-shell ffuf invocation.

        When ``config_file`` is given, the credential-bearing options
        (headers, cookies, body) are NOT emitted on the argv — the caller
        delivers them via that ffuf ``-config`` TOML instead (see
        :meth:`build_config_file_content`).
        """
        self._validate_config(config)

        request_text: str | None = None
        if config.request_file is not None:
            request_text = self._read_scoped_request_file(config)

        # In vhost mode the URL is fixed and the Host header carries the
        # keyword; the dataclass default path template of "FUZZ" would
        # otherwise force a URL substitution point that vhost mode forbids.
        path_template = config.path_template
        if config.vhost and path_template == "FUZZ":
            path_template = ""
        if request_text is not None:
            # Raw-request mode: the file IS the request; no URL template.
            url_template = ""
        else:
            url_template = self.build_url_template(
                path_template, self._fuzz_keywords(config)
            )
        if config.recursion and not url_template.endswith("FUZZ"):
            # ffuf constraint (optionsparser HasSuffix check): recursion
            # re-queues discovered directories by substituting FUZZ at the
            # very end of the URL — a trailing slash is a hard config
            # error upstream, so reject it here instead of at runtime.
            msg = (
                "ffuf recursion requires the URL template to end with FUZZ "
                f"(got {self._redact(url_template)})"
            )
            raise ValueError(msg)
        vhost_header = self._build_vhost_header(config)
        if config.vhost and any(
            kw in url_template for kw in self._fuzz_keywords(config)
        ):
            msg = (
                "ffuf vhost mode fuzzes the Host header; remove wordlist "
                "keywords from the URL template or drop vhost mode"
            )
            raise ValueError(msg)
        extra_haystacks: tuple[str, ...] = ()
        if vhost_header:
            extra_haystacks += (vhost_header,)
        if request_text is not None:
            extra_haystacks += (request_text,)
        self._require_fuzz_keyword(
            config,
            url_template,
            extra_haystacks=extra_haystacks,
        )
        cmd = [config.binary]
        if request_text is not None:
            cmd.extend([
                "-request",
                str(config.request_file),
                "-request-proto",
                urlparse(self.base_url).scheme or "https",
            ])
        else:
            cmd.extend(["-u", url_template])
        cmd.extend([
            "-w",
            str(config.wordlist),
            "-of",
            "json",
            "-o",
            str(output_file),
            "-noninteractive",
            "-t",
            str(config.threads),
            "-timeout",
            str(config.timeout),
            # ffuf-side runtime cap: ffuf exits cleanly at -maxtime and
            # flushes its JSON report. The Python-side subprocess timeout
            # (see run()) is only a backstop with a grace window — if it
            # fired first, the kill would discard the report.
            "-maxtime",
            str(config.max_runtime),
        ])
        if config.stop_on_403:
            cmd.append("-sf")
        if config.stop_on_spurious:
            cmd.append("-se")
        if config.stop_on_all_errors:
            cmd.append("-sa")
        if config.auto_calibration:
            cmd.append("-ac")
            if config.calibration_strategy is not None:
                cmd.extend(["-acs", config.calibration_strategy])
            if config.calibration_per_host:
                cmd.append("-ach")
        for spec in config.encoders:
            cmd.extend(["-enc", spec])
        if config.match_status:
            cmd.extend(["-mc", config.match_status])
        if config.filter_status:
            cmd.extend(["-fc", config.filter_status])
        if config.filter_size is not None:
            cmd.extend(["-fs", str(config.filter_size)])
        if config.filter_words is not None:
            cmd.extend(["-fw", str(config.filter_words)])
        if config.filter_lines is not None:
            cmd.extend(["-fl", str(config.filter_lines)])
        if config.match_regex is not None:
            cmd.extend(["-mr", config.match_regex])
        if config.filter_regex is not None:
            cmd.extend(["-fr", config.filter_regex])
        if config.match_time is not None:
            cmd.extend(["-mt", config.match_time])
        if config.filter_time is not None:
            cmd.extend(["-ft", config.filter_time])
        if config.extensions:
            cmd.extend(["-e", ",".join(config.extensions)])
        if config.method.upper() != "GET":
            cmd.extend(["-X", config.method.upper()])
        if config_file is not None:
            cmd.extend(["-config", str(config_file)])
        else:
            if config.data:
                cmd.extend(["-d", config.data])
            for header in config.headers:
                cmd.extend(["-H", header])
            if vhost_header is not None:
                cmd.extend(["-H", vhost_header])
            for cookie in config.cookies:
                cmd.extend(["-b", cookie])
        for extra_path, keyword in config.extra_wordlists:
            cmd.extend(["-w", f"{extra_path}:{keyword}"])
        if config.extra_wordlists:
            # Emit the mode explicitly (ffuf would default to clusterbomb)
            # so the argv in logs and audit trails is self-describing.
            cmd.extend(["-mode", config.mode or "clusterbomb"])
        if config.recursion:
            cmd.append("-recursion")
            cmd.extend(["-recursion-depth", str(config.recursion_depth)])
            cmd.extend(["-recursion-strategy", config.recursion_strategy])
        max_runtime_job = config.max_runtime_job
        if max_runtime_job is None and config.recursion:
            # One hot directory must not consume the whole -maxtime budget.
            max_runtime_job = max(60, config.max_runtime // 4)
        if max_runtime_job is not None:
            cmd.extend(["-maxtime-job", str(max_runtime_job)])
        rate = config.rate
        if rate is None:
            # Pitchfork iterates wordlists in lockstep and does not
            # multiply request counts; clusterbomb and recursion do.
            if config.recursion:
                guard_reason = "recursion"
            elif config.extra_wordlists and (config.mode or "clusterbomb") == "clusterbomb":
                guard_reason = "clusterbomb multi-wordlist mode"
            else:
                guard_reason = None
            if guard_reason is not None:
                rate = DEFAULT_GUARDED_RATE
                logger.info(
                    "ffuf %s enabled with no explicit rate limit; applying "
                    "default -rate %d req/s (pass --ffuf-rate to override)",
                    guard_reason,
                    rate,
                )
        if rate is not None:
            cmd.extend(["-rate", str(rate)])
        return cmd

    def run(self, config: FfufConfig) -> dict[str, Any]:
        """Run ffuf in RAPTOR's sandbox and return a compact result summary.

        ffuf exits non-zero for several operational conditions (no matches,
        interrupted run, config error). RAPTOR keeps the raw JSON artifact when
        present and reports the return code instead of treating every non-zero
        as a scanner crash.
        """
        binary_path = shutil.which(config.binary)
        if binary_path is None:
            msg = (
                f"ffuf binary not found on PATH: {config.binary}. "
                "Install ffuf or pass --ffuf-bin."
            )
            raise FileNotFoundError(msg)
        # Exec via the REAL path: go-install / package-manager setups
        # put a symlink on PATH; the mount-ns visibility check
        # realpaths cmd[0] and the tool_paths bind must carry the
        # RESOLVED parent, or the run silently drops to the
        # Landlock-only fallback tier (selftest-05 scanner precedent).
        binary_path = os.path.realpath(binary_path)

        # Wordlists follow the same realpath rule as the binary: the
        # mount-ns file bind and the Landlock read rule are created for
        # the path the child actually opens, and a symlinked wordlist
        # would leave its original path dangling inside the namespace.
        def _resolve_wordlist(path: Path) -> Path:
            resolved = Path(os.path.realpath(path))
            if resolved.parent != Path(os.path.abspath(path)).parent:
                # A repo-shipped wordlist that is secretly a symlink into
                # e.g. ~/.ssh would now be granted (and its lines sprayed
                # at the target as fuzz candidates). Can't be an error —
                # cross-directory symlinks are a legitimate operator
                # setup — but it must be loud.
                logger.warning(
                    "ffuf wordlist %s resolves OUTSIDE its directory to %s; "
                    "the sandbox read grant follows the resolved file — "
                    "verify the symlink is yours, not the scanned repo's",
                    self._redact(str(path)),
                    self._redact(str(resolved)),
                )
            return resolved

        config = replace(
            config,
            wordlist=_resolve_wordlist(config.wordlist),
            extra_wordlists=tuple(
                (_resolve_wordlist(path), keyword)
                for path, keyword in config.extra_wordlists
            ),
            request_file=(
                _resolve_wordlist(Path(config.request_file))
                if config.request_file is not None
                else None
            ),
        )

        target_host = (urlparse(self.base_url).hostname or "").lower()
        if not target_host:
            msg = "ffuf base URL must include a hostname"
            raise ValueError(msg)

        if config.threads > 200:
            # Not an error — operator opt-in — but almost always a typo'd
            # value or a DoS-against-self against a live target. Emitted
            # here rather than in build_command so the CLI preflight's
            # validation pass doesn't duplicate it.
            logger.warning(
                "ffuf threads=%d is unusually high for a live target; "
                "consider --ffuf-rate to bound request pressure",
                config.threads,
            )

        self.out_dir.mkdir(parents=True, exist_ok=True)
        output_file = self.out_dir / "ffuf_results.json"
        # A reused output dir (routine with project runs) may hold a
        # previous run's report; ffuf only writes on graceful exit, so a
        # stale file would be silently misattributed to this run on the
        # error and backstop-timeout paths.
        output_file.unlink(missing_ok=True)
        config_content = self.build_config_file_content(config)
        config_file = (
            self.out_dir / "ffuf_config.toml" if config_content is not None else None
        )
        cmd = self.build_command(config, output_file, config_file=config_file)
        # build_command uses the operator-facing name; swap in the
        # resolved real path for the exec.
        cmd[0] = binary_path
        redacted_cmd = self._redact_command(cmd)
        logger.info("Running sandboxed ffuf: %s", ' '.join(redacted_cmd))


        # ffuf's own -maxtime (== max_runtime) is the real cap; the
        # subprocess timeout is a backstop for a wedged process. It gets
        # a grace window so ffuf can exit cleanly and flush its report —
        # a backstop kill loses whatever ffuf had not yet written.
        grace = min(30, max(5, config.max_runtime // 10))
        timed_out = False
        returncode: int | None = None
        stderr_text = ""
        try:
            if config_file is not None and config_content is not None:
                # out_dir is the sandbox's WRITABLE scope, so a hostile
                # child from a PREVIOUS run could have left this path
                # behind as a symlink aimed anywhere on disk; O_EXCL
                # after the unlink refuses to follow anything and
                # guarantees a fresh 0600 inode for the credentials.
                # Residuals accepted by design: the child itself must be
                # able to read its own config (same UID, inside the
                # writable scope), and 0600 never defends against
                # same-UID processes — the channel this closes is the
                # world-readable /proc/<pid>/cmdline.
                config_file.unlink(missing_ok=True)
                fd = os.open(
                    config_file,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                )
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(config_content)
                logger.info(
                    "ffuf credential-bearing options delivered via %s (0600): %s",
                    config_file.name,
                    self._describe_delivered(config),
                )
            # File-granular read scope: the sandbox needs the wordlist
            # FILES, not their parent directories — a wordlist under
            # /etc must not put all of /etc in the read allowlist. Both
            # enforcement tiers support file paths (Landlock path_beneath
            # rules on O_PATH fds; mount-ns per-file bind with stub
            # creation).
            wordlist_files = list(dict.fromkeys(
                [str(config.wordlist)]
                + [str(path) for path, _keyword in config.extra_wordlists]
                + ([str(config.request_file)] if config.request_file else [])
            ))
            completed = run_untrusted_networked(
                cmd,
                output=str(self.out_dir),
                readable_paths=wordlist_files,
                proxy_hosts=[target_host],
                fake_home=True,
                tool_paths=[str(Path(binary_path).parent)],
                caller_label="web-ffuf",
                timeout=config.max_runtime + grace,
                capture_output=True,
                text=True,
            )
            returncode = completed.returncode
            stderr_text = completed.stderr or ""
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stderr_raw = exc.stderr
            if isinstance(stderr_raw, bytes):
                stderr_text = stderr_raw.decode("utf-8", errors="replace")
            else:
                stderr_text = stderr_raw or ""
            logger.warning(
                "ffuf did not exit at -maxtime %ds; killed after %ds grace — "
                "the report reflects only what ffuf flushed before the kill",
                config.max_runtime,
                grace,
            )
        finally:
            # Credentials should not persist at rest beyond the run; the
            # redacted log line above records what was delivered.
            # reveal_secrets keeps the file for local debugging.
            if config_file is not None and not self.reveal_secrets:
                config_file.unlink(missing_ok=True)

        results: list[dict[str, Any]] = []
        if output_file.exists():
            parsed: Any = None
            try:
                # Size-gated BEFORE the read: an over-budget results
                # file raises with the observed size and is reported
                # below like any other unparseable output.
                parsed = load_json_bounded(
                    output_file, max_bytes=_MAX_FFUF_OUTPUT_BYTES,
                )
            except ValueError as exc:
                # Malformed JSON, undecodable bytes, or over budget —
                # either way the raw file may still embed the delivered
                # credentials in its config block: restrict it.
                logger.warning("Could not parse ffuf JSON output: %s", exc)
                self._restrict_report(output_file)
            if isinstance(parsed, dict):
                raw_results = parsed.get("results") or []
                if isinstance(raw_results, list):
                    results = [r for r in raw_results if isinstance(r, dict)]
                self._scrub_report(output_file, parsed)
            elif parsed is not None:
                self._restrict_report(output_file)

        summarized_results = [self._summarize_result(r) for r in results[: config.report_limit]]
        return {
            "tool": "ffuf",
            "returncode": returncode,
            "timed_out": timed_out,
            "output_file": str(output_file),
            "result_count": len(results),
            "reported_result_count": len(summarized_results),
            "omitted_result_count": max(0, len(results) - len(summarized_results)),
            "results": summarized_results,
            "stderr": self._redact(self._redact_stderr(stderr_text.strip())),
        }

    @staticmethod
    def _restrict_report(output_file: Path) -> None:
        """0600 fallback when the raw report cannot be rewritten: ffuf
        embeds its full resolved config — delivered headers, cookies,
        and body verbatim — in the report, at 0644 by default."""
        try:
            output_file.chmod(0o600)
        except OSError:
            logger.debug("could not restrict ffuf report mode", exc_info=True)

    def _scrub_report(self, output_file: Path, parsed: dict[str, Any]) -> None:
        """Strip ffuf's embedded config and command line from the kept raw
        report and rewrite it as a fresh 0600 inode.

        Deleting the 0600 credentials TOML while ffuf's own report keeps
        the same header/cookie/body values at 0644 would make the
        at-rest guarantee theater. RAPTOR consumes only the results
        array; reveal_secrets keeps the report untouched.
        """
        if self.reveal_secrets:
            return
        removed = [key for key in ("config", "commandline") if key in parsed]
        if not removed:
            return
        scrubbed = {key: item for key, item in parsed.items() if key not in removed}
        scrubbed["redacted_keys"] = removed
        try:
            output_file.unlink(missing_ok=True)
            fd = os.open(
                output_file,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(scrubbed, handle)
        except OSError as exc:
            logger.warning("could not scrub ffuf report %s: %s", output_file, exc)

    _BANNER_LINE_RE = re.compile(r"^(\s*::\s*(Header|Data)\s*:\s*)(.*)$")

    def _redact_stderr(self, text: str) -> str:
        """Scrub ffuf's startup banner from captured stderr.

        Even in noninteractive mode the banner echoes every delivered
        header (cookies fold into a Cookie header) and the request body
        as ' :: Header : ...' / ' :: Data : ...' lines. Names stay,
        values go — the generic pattern redactor cannot know which
        values are secret.
        """
        if self.reveal_secrets:
            return text
        lines = []
        for line in text.split("\n"):
            matched = self._BANNER_LINE_RE.match(line)
            if not matched:
                lines.append(line)
                continue
            prefix, kind, value = matched.groups()
            if kind == "Header":
                name, sep, _val = value.partition(":")
                redacted = f"{name.strip()}: [REDACTED]" if sep else "[REDACTED]"
            else:
                redacted = "[REDACTED]"
            lines.append(prefix + redacted)
        return "\n".join(lines)

    def _clean_summary_text(self, value: object) -> str:
        """Sanitize a report field that echoes response-influenced data.

        Redact first — truncating before redaction could split a secret
        token mid-pattern — then strip newlines (log/report injection)
        and bound the length.
        """
        text = self._redact(value)
        return text.replace("\r", " ").replace("\n", " ")[:2048]

    @staticmethod
    def _clean_summary_int(value: object) -> int | None:
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        return value

    def _summarize_result(self, result: dict[str, Any]) -> dict[str, Any]:
        """Keep ffuf report entries compact, typed, and secret-redacted."""
        summary: dict[str, Any] = {
            "url": self._clean_summary_text(result.get("url", "")),
            "status": self._clean_summary_int(result.get("status")),
            "length": self._clean_summary_int(result.get("length")),
            "words": self._clean_summary_int(result.get("words")),
            "lines": self._clean_summary_int(result.get("lines")),
        }
        # vhost runs answer "which Host matched", not "which URL": ffuf
        # reports the substituted Host value in the per-result host field.
        host = result.get("host")
        if host:
            summary["host"] = self._clean_summary_text(host)
        # Raw-request runs fuzz positions the URL does not echo (a JSON
        # body field, a header value), so the per-result input map is
        # the only record of WHICH wordlist entry matched. FFUFHASH is
        # ffuf bookkeeping, not an input.
        inputs = result.get("input")
        if isinstance(inputs, dict):
            cleaned = {
                str(keyword): self._clean_summary_text(value)
                for keyword, value in inputs.items()
                if str(keyword) != "FFUFHASH"
            }
            if cleaned:
                summary["input"] = cleaned
        return summary
