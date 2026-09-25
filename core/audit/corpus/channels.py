"""Per-channel micro-corpora for the /audit calibration corpus.

Each audit channel (an orchestrator channel, refutation gate, or
mechanical detector — the token vocabulary ``expected_mechanism``
draws from) can carry its own local micro-corpus: a handful of
labels that exercise exactly that channel, refired after every
change to it without touching the full corpus.

Layout (mirrors the main ``labels/`` dir; content is LOCAL — the
tree ships this machinery, never label content)::

    core/audit/corpus/channels/<channel>/<bug_class>/x.label.json

``<channel>`` is a mechanism token (``[a-z0-9_]+``); the bug-class
level is a convention, not a requirement — the loader rglobs like
``load_all_labels``. A label may also carry an explicit ``channel``
field: when present it must agree with the directory it lives under
(refused on mismatch, never reconciled); when absent the directory
IS the channel (inherited for grouping, never written back).

Consumption today: :func:`load_channel_labels` (programmatic —
tests, refire tooling), the label linter (``python3 -m
core.audit.corpus.lint channels/<channel>``: the linter already
takes explicit paths), and :func:`group_labels_by_channel` for
field-based grouping of an already-loaded mixed set. The corpus
runner keeps reading the packaged ``labels/`` dir; channel dirs
never leak into a full-corpus run implicitly.
"""

from __future__ import annotations

from pathlib import Path

from core.audit.corpus.label import (
    CHANNEL_RE,
    FunctionLabel,
    load_all_labels,
)

CORPUS_DIR = Path(__file__).parent
CHANNELS_DIR = CORPUS_DIR / "channels"


class ChannelCorpusError(ValueError):
    """A channel micro-corpus failed validation."""


def validate_channel_name(channel: str) -> str:
    """Return *channel* or raise on a malformed name.

    ``fullmatch`` on the shared label-schema pattern: a ``$``-anchored
    ``re.match`` would still accept a trailing newline.
    """
    if not CHANNEL_RE.fullmatch(channel or ""):
        msg = (
            f"invalid channel name {channel!r}: must fully match "
            f"{CHANNEL_RE.pattern} (lowercase mechanism-token charset)"
        )
        raise ChannelCorpusError(msg)
    return channel


def list_channels(base: Path | None = None) -> list[str]:
    """Sorted channel names under the channels dir ([] when absent).

    A directory whose name violates the channel charset is an error,
    not a silent skip — a typoed channel dir would otherwise hide its
    labels from every per-channel surface.
    """
    root = base if base is not None else CHANNELS_DIR
    if not root.is_dir():
        return []
    names: list[str] = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        names.append(validate_channel_name(entry.name))
    return names


def channel_labels_dir(channel: str, base: Path | None = None) -> Path:
    """Path of one channel's micro-corpus dir (existence not implied)."""
    root = base if base is not None else CHANNELS_DIR
    return root / validate_channel_name(channel)


def load_channel_labels(
    channel: str,
    base: Path | None = None,
    bug_class: str | None = None,
) -> list[FunctionLabel]:
    """Load one channel's micro-corpus.

    Fail-closed on a missing dir (a typo must not read as an empty
    corpus) and on a label whose explicit ``channel`` field
    contradicts the directory it lives under. Labels without the
    field inherit the directory channel for grouping purposes only —
    the on-disk file is never rewritten.
    """
    labels_dir = channel_labels_dir(channel, base)
    if not labels_dir.is_dir():
        # A malformed SIBLING dir must not mask this error with its
        # own — the listing is best-effort context here.
        try:
            available: str = ", ".join(list_channels(base)) or "none"
        except ChannelCorpusError:
            available = "unlistable (malformed sibling channel dir)"
        msg = (
            f"no micro-corpus dir for channel {channel!r} at "
            f"{labels_dir} (available: {available})"
        )
        raise ChannelCorpusError(msg)
    labels = load_all_labels(corpus_dir=labels_dir, bug_class=bug_class)
    for label in labels:
        if label.channel and label.channel != channel:
            msg = (
                f"label {label.function_id!r} under channel dir "
                f"{channel!r} declares channel={label.channel!r} — "
                "refusing (channel tags are carried verbatim, never "
                "reconciled; move the label or fix the tag)"
            )
            raise ChannelCorpusError(msg)
    return labels


def group_labels_by_channel(
    labels: list[FunctionLabel],
) -> dict[str, list[FunctionLabel]]:
    """Group an already-loaded label set by its ``channel`` field.

    Labels without the field land under ``""`` — unchanneled is a
    real bucket, never defaulted into a named channel.
    """
    groups: dict[str, list[FunctionLabel]] = {}
    for label in labels:
        groups.setdefault(label.channel, []).append(label)
    return groups
