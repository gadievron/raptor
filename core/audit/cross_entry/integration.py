"""Confined context discovery and audit integration; disabled unless opted in."""
from __future__ import annotations

import os
import hashlib
import re
import time
from pathlib import Path
from typing import Any, Iterable


from .model import Limits

MODES = {"off", "index", "shadow", "context", "study"}
_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"}


def collect_sources(target: Path, report_files: Iterable[str], limits: Limits, *,
                    include_dirs: Iterable[Path] = ()) -> tuple[dict[str,str],dict]:
    """Prioritize report files and their immediate siblings inside target.

    Never follow symlink directories or escaping files. Discovery itself is
    bounded, and an unenumerated tail is recorded rather than called complete.
    """
    target = Path(target).resolve()
    root = target.parent if target.is_file() else target
    include_dirs = tuple(dict.fromkeys(Path(p).resolve() for p in include_dirs))
    include_prefixes = [os.path.relpath(p,root).replace(os.sep,"/") for p in include_dirs]
    coverage: dict[str,Any] = {"root":str(root),"report_scope":sorted(set(report_files)),
        "skipped":[],"truncated":[],"discovered":[],"raw_source_hashes":{},
        "include_dirs":[str(p) for p in include_dirs],"include_prefixes":include_prefixes,
        "auxiliary_headers":{},"include_edges":{},
        "collection_strategy":"report-header-frontier-siblings-closure-v3"}
    priority = []
    for fp in coverage["report_scope"]:
        if not fp:
            continue
        path = Path(fp)
        path = (root/path).resolve() if not path.is_absolute() else path.resolve()
        if not path.is_relative_to(root):
            coverage["skipped"].append({"file":fp,"reason":"outside_context_root"})
        else:
            priority.append(path)
    if target.is_file():
        priority.insert(0,target)
    sources = {}
    seen = set()
    used = 0
    start = time.monotonic()

    def add(path: Path) -> bool:
        nonlocal used
        if path.suffix.lower() not in _SUFFIXES:
            return True
        try:
            resolved = path.resolve()
        except (OSError,RuntimeError):
            coverage["skipped"].append({"file":str(path),"reason":"unresolvable_path"})
            return True
        if resolved in seen:
            return True
        seen.add(resolved)
        anchor = root if resolved.is_relative_to(root) else next((p for p in include_dirs
            if resolved.is_relative_to(p) and resolved.suffix.lower() in {".h",".hpp",".hh",".hxx"}),None)
        if anchor is None:
            coverage["skipped"].append({"file":str(path),"reason":"escaping_symlink"})
            return True
        key = os.path.relpath(resolved,root).replace(os.sep,"/")
        coverage["discovered"].append(key)
        if len(sources) >= limits.max_files or time.monotonic()-start >= limits.scan_seconds:
            coverage["truncated"].append("discovery_budget")
            return False
        try:
            from core.source.contained import read_contained_bytes
            got = read_contained_bytes(anchor,resolved,max(0,limits.max_bytes-used))
            if got is None:
                coverage["skipped"].append({"file":key,"reason":"unreadable_or_nonregular"})
                return True
            body,truncated = got
            if truncated:
                coverage["skipped"].append({"file":key,"reason":"byte_budget"})
                return True
            used += len(body)
            coverage["raw_source_hashes"][key] = hashlib.sha256(body).hexdigest()
            sources[key] = body.decode("utf-8",errors="replace")
            if not resolved.is_relative_to(root):
                coverage["auxiliary_headers"][key] = str(resolved)
        except OSError:
            coverage["skipped"].append({"file":key,"reason":"unreadable"})
        return True

    for path in priority:
        if not add(path):
            break

    missing_includes = set()

    def headers(keys: list[str], *, recursive: bool, cap: int, record_budget: bool = True) -> None:
        queue = list(keys)
        processed = set()
        while queue and time.monotonic()-start < limits.scan_seconds:
            key = queue.pop(0)
            if key in processed:
                continue
            processed.add(key)
            for match in re.finditer(r'^\s*#\s*include\s*[<"]([^>"\n]+)[>"]',sources[key],re.MULTILINE):
                name = match.group(1)
                choices = [root/Path(key).parent/name,root/name,root/"include"/name]+[p/name for p in include_dirs]
                def permitted(path):
                    resolved = path.resolve()
                    return resolved.is_relative_to(root) or (resolved.suffix.lower() in {".h",".hpp",".hh",".hxx"}
                        and any(resolved.is_relative_to(p) for p in include_dirs))
                found = next((p for p in choices if permitted(p) and p.is_file()),None)
                if found is None:
                    if (key,name) not in missing_includes:
                        missing_includes.add((key,name))
                        coverage["skipped"].append({"file":key,"include":name,"reason":"include_unresolved"})
                    continue
                if found.resolve() not in seen and len(sources) >= cap:
                    if record_budget:
                        coverage["truncated"].append("header_budget")
                    continue
                if not add(found):
                    return
                header = os.path.relpath(found.resolve(),root).replace(os.sep,"/")
                coverage["include_edges"].setdefault(key,{})[name] = header
                if recursive:
                    if header in sources and header not in processed:
                        queue.append(header)

    # Give report headers an initial share, then collect sibling producers
    # before expanding the recursive include closure. A full repository root
    # must not spend every source slot on headers before seeing sibling .c's.
    headers(list(sources),recursive=True,cap=min(limits.max_files,len(sources)+max(1,limits.max_files//4)),record_budget=False)
    for folder in sorted({p.parent for p in priority}):
        if time.monotonic()-start >= limits.scan_seconds:
            break
        try:
            for path in sorted(folder.iterdir(),key=lambda p:(p.suffix.lower() in {".h",".hpp",".hh",".hxx"},p.name)):
                if path.is_file() and not add(path):
                    break
        except OSError:
            coverage["skipped"].append({"file":str(folder),"reason":"unreadable_directory"})
    headers(list(sources),recursive=True,cap=limits.max_files)
    for folder, dirs, files in os.walk(root,followlinks=False):
        dirs[:] = sorted(d for d in dirs if not d.startswith(".") and not (Path(folder)/d).is_symlink())
        if len(sources) >= limits.max_files or time.monotonic()-start >= limits.scan_seconds:
            coverage["truncated"].append("unscanned_subtrees")
            break
        for name in sorted(files):
            if not add(Path(folder)/name):
                break
    coverage["truncated"] = sorted(set(coverage["truncated"]))
    coverage["complete"] = not coverage["skipped"] and not coverage["truncated"]
    return sources,coverage


def prepare_cross_entry(target: Path, gaps: list[dict], *, mode: str, out_dir: Path,
                        limits: Limits | None = None, client: Any = None,
                        entry_points: Iterable[str] = (), model_key: str = "configured",
                        should_stop=None, context_root: Path | None = None,
                        drain_index: bool = False, delivery_receipts: dict | None = None,
                        include_dirs: Iterable[Path] = ()) -> dict[str,str]:
    """Advance durable discovery/study work and prepare one review evidence batch."""
    from .runner import prepare
    return prepare(target,gaps,mode=mode,out_dir=out_dir,limits=limits,client=client,
                   entry_points=entry_points,model_key=model_key,should_stop=should_stop,
                   context_root=context_root,drain_index=drain_index,delivery_receipts=delivery_receipts,
                   include_dirs=include_dirs)


def json_text(value: Any) -> str:
    import json
    return json.dumps(value,sort_keys=True,ensure_ascii=True)
