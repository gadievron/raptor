"""Label-scoped container/image cleanup.

Every artifact the container substrate creates carries caller labels,
so cleanup is exact-scope by construction: remove precisely the
containers/images stamped ``<label>=<value>``, never a neighbour's.
Best-effort throughout — a wedged daemon degrades to "0 removed", it
never raises into a caller's teardown path.
"""

from __future__ import annotations

from core.container.proc import run_cli


def remove_labeled_containers(label: str, value: str,
                              timeout: float = 30.0) -> int:
    """``docker rm -f`` every container labeled ``label=value``.
    Returns the count removed (0 when none matched or on any failure)."""
    if not value:
        return 0
    list_result = run_cli(
        ["docker", "ps", "-aq", "--filter", f"label={label}={value}"],
        timeout=timeout,
    )
    if list_result.returncode != 0:
        return 0
    ids = [i.strip() for i in (list_result.stdout or "").splitlines()
           if i.strip()]
    if not ids:
        return 0
    outcome = run_cli(["docker", "rm", "-f", *ids], timeout=timeout)
    return len(ids) if outcome.returncode == 0 else 0


def remove_labeled_images(
    label: str,
    value: str,
    *,
    tag_repo: str | None = None,
    tag_value: str | None = None,
    timeout: float = 30.0,
) -> int:
    """Remove IMAGES labeled ``label=value``; returns tags removed.

    Removes by TAG (not ``-f`` by ID) so a multi-tag image deletes
    cleanly as its last tag goes; ``<none>`` rows are skipped (left for
    the dangling prune) and duplicates deduped. Call AFTER
    :func:`remove_labeled_containers` so no live container holds the
    image.

    ``tag_repo``/``tag_value`` add a kill-path fallback sweep: a
    SIGKILL'd builder can leave a tagged image WITHOUT the label (the
    in-process labeling ran after the kill), so a second query lists
    ``tag_repo``'s images and keeps those whose tag equals
    ``tag_value`` or starts with ``tag_value + "-"`` — still scoped to
    exactly the caller's unit, so concurrent neighbours are never
    touched.
    """
    if not value:
        return 0
    tags: list[str] = []
    label_result = run_cli(
        [
            "docker", "images",
            "--filter", f"label={label}={value}",
            "--format", "{{.Repository}}:{{.Tag}}",
        ],
        timeout=timeout,
    )
    if label_result.returncode == 0:
        for t in (label_result.stdout or "").splitlines():
            t = t.strip()
            if t and "<none>" not in t:
                tags.append(t)
    if tag_repo and tag_value:
        tag_result = run_cli(
            ["docker", "images", tag_repo,
             "--format", "{{.Repository}}:{{.Tag}}"],
            timeout=timeout,
        )
        if tag_result.returncode == 0:
            for t in (tag_result.stdout or "").splitlines():
                t = t.strip()
                if not t or "<none>" in t or ":" not in t:
                    continue
                tagpart = t.split(":", 1)[1]
                if tagpart == tag_value or tagpart.startswith(tag_value + "-"):
                    tags.append(t)
    tags = list(dict.fromkeys(tags))  # dedupe, preserve order
    if not tags:
        return 0
    outcome = run_cli(["docker", "rmi", *tags], timeout=timeout)
    return len(tags) if outcome.returncode == 0 else 0


def prune_dangling_images(timeout: float = 30.0) -> None:
    """Prune dangling images only — safe against in-use images and
    current tag-references."""
    run_cli(["docker", "image", "prune", "-f"], timeout=timeout)
