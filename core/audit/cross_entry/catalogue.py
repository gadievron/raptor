"""Incremental repository-wide retrieval catalogue, independent of model context.

Terms are approximate nominations, never evidence of type/alias equality. Only
the existing typed index over a confined source view supplies study evidence.
SQLite stores compressed snapshots and unfinished directories/files, so a
work quantum is a checkpoint rather than a permanent source-tree cutoff.
"""
from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import time
import zlib
from pathlib import Path

from core.json import dumps_canonical
from core.source.contained import read_contained_bytes

from .model import digest

SUFFIXES = {".c",".h",".cc",".cpp",".cxx",".hpp",".hh",".hxx"}
VERSION = 1


def retrieval_terms(source: str) -> set[str]:
    terms = {"field:"+m for m in re.findall(r"(?:->|\.)\s*([A-Za-z_]\w*)",source)}
    terms |= {"type:"+m for m in re.findall(r"\b(?:struct|class|union)\s+([A-Za-z_]\w*)",source)}
    terms |= {"symbol:"+m for m in re.findall(r"\b([A-Za-z_]\w*)\s*\(",source)}
    return terms


class Catalogue:
    def __init__(self, root: Path, out_dir: Path):
        self.root = Path(root).resolve()
        self.out_dir = Path(out_dir).resolve()
        self.path = self.out_dir/("cross-entry-catalogue-"+digest(str(self.root))[:16]+".sqlite")
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT);
            CREATE TABLE IF NOT EXISTS directories(path TEXT PRIMARY KEY,status TEXT,priority INTEGER);
            CREATE TABLE IF NOT EXISTS files(path TEXT PRIMARY KEY,seen INTEGER,signature TEXT,
                sha TEXT,body BLOB,status TEXT,error TEXT,version INTEGER);
            CREATE TABLE IF NOT EXISTS terms(term TEXT,path TEXT,PRIMARY KEY(term,path));
            CREATE INDEX IF NOT EXISTS terms_path ON terms(path);
            CREATE TABLE IF NOT EXISTS exclusions(path TEXT PRIMARY KEY,reason TEXT);
        """)
        self.changed = set()

    def close(self):
        self.db.close()

    def _meta(self,key,default="0"):
        row = self.db.execute("SELECT value FROM meta WHERE key=?",(key,)).fetchone()
        return row[0] if row else default

    def _set(self,key,value):
        self.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)",(key,str(value)))

    def begin(self, report_files=()):
        if self._meta("active") != "1":
            self._set("generation",int(self._meta("generation"))+1)
            self._set("active",1)
            self.db.execute("DELETE FROM directories")
            self.db.execute("DELETE FROM exclusions")
            self.db.execute("INSERT INTO directories VALUES ('','pending',0)")
        for fp in report_files:
            path = (self.root/fp).resolve()
            if path.is_relative_to(self.root):
                self._discover(path.relative_to(self.root).as_posix())
                parent = path.parent.relative_to(self.root).as_posix()
                if parent == ".":
                    parent = ""
                self.db.execute("INSERT OR IGNORE INTO directories VALUES (?,'pending',10)",(parent,))
        self.db.commit()

    def _discover(self, path):
        if Path(path).suffix.lower() not in SUFFIXES:
            return
        try:
            info = (self.root/path).stat()
            signature = dumps_canonical([info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns])
        except OSError:
            signature = "unreadable"
        old = self.db.execute("SELECT signature,status,version FROM files WHERE path=?",(path,)).fetchone()
        generation = int(self._meta("generation"))
        if old is None:
            self.db.execute("INSERT INTO files VALUES (?,?,?,NULL,NULL,'pending','',?)",(path,generation,signature,VERSION))
        elif old["signature"] != signature or old["version"] != VERSION or old["status"] == "blocked":
            self.db.execute("UPDATE files SET signature=?,seen=?,status='pending',error='' WHERE path=?",(signature,generation,path))
            self.changed.add(path)
        else:
            self.db.execute("UPDATE files SET seen=? WHERE path=?",(generation,path))

    def ingest(self, sources: dict[str,str], raw_hashes: dict[str,str]):
        """Reuse already-confined warm-context reads when the byte hash agrees."""
        for path,source in sources.items():
            body = source.encode("utf-8")
            sha = hashlib.sha256(body).hexdigest()
            if raw_hashes.get(path) != sha:
                continue
            self._discover(path)
            row = self.db.execute("SELECT sha,status FROM files WHERE path=?",(path,)).fetchone()
            if row and (row["sha"] != sha or row["status"] != "indexed"):
                self._store(path,body)
        self.db.commit()

    def _store(self,path,body):
        sha = hashlib.sha256(body).hexdigest()
        old = self.db.execute("SELECT sha FROM files WHERE path=?",(path,)).fetchone()
        if old and old[0] != sha:
            self.changed.add(path)
        self.db.execute("UPDATE files SET sha=?,body=?,status='indexed',error='',version=? WHERE path=?",
                        (sha,zlib.compress(body),VERSION,path))
        self.db.execute("DELETE FROM terms WHERE path=?",(path,))
        self.db.executemany("INSERT INTO terms VALUES (?,?)",[(t,path) for t in sorted(retrieval_terms(body.decode(errors="replace")))])

    def advance(self, limits, should_stop=None):
        start = time.monotonic()
        files = 0
        size = 0
        directories = 0
        while files < limits.index_batch_files and size < limits.index_batch_bytes:
            if time.monotonic()-start >= limits.index_batch_seconds or (should_stop and should_stop()):
                break
            row = self.db.execute("SELECT path FROM files WHERE status='pending' ORDER BY path LIMIT 1").fetchone()
            if row:
                path = row[0]
                got = read_contained_bytes(self.root,path,limits.max_bytes)
                if got is None or got[1]:
                    reason = "file_byte_limit" if got else "unreadable_or_nonregular"
                    self.db.execute("UPDATE files SET status='blocked',error=? WHERE path=?",(reason,path))
                else:
                    self._store(path,got[0])
                    size += len(got[0])
                files += 1
                self.db.commit()  # A completed file survives interruption.
                continue
            row = self.db.execute("SELECT path FROM directories WHERE status='pending' ORDER BY priority DESC,path LIMIT 1").fetchone()
            if row is None:
                break
            relative = row[0]
            folder = self.root/relative
            try:
                for entry in sorted(os.scandir(folder),key=lambda e:e.name):
                    path = Path(entry.path)
                    rel = path.relative_to(self.root).as_posix()
                    reason = "output_directory" if path == self.out_dir else "symlink" if entry.is_symlink() else "git_metadata" if entry.name == ".git" else None
                    if reason:
                        self.db.execute("INSERT OR REPLACE INTO exclusions VALUES (?,?)",(rel,reason))
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        self.db.execute("INSERT OR IGNORE INTO directories VALUES (?,'pending',0)",(rel,))
                    elif Path(entry.name).suffix.lower() in SUFFIXES:
                        self._discover(rel)
                self.db.execute("UPDATE directories SET status='done' WHERE path=?",(relative,))
            except OSError:
                self.db.execute("UPDATE directories SET status='blocked' WHERE path=?",(relative,))
            directories += 1
            self.db.commit()
        if not self.db.execute("SELECT 1 FROM directories WHERE status='pending' LIMIT 1").fetchone() and not self.db.execute("SELECT 1 FROM files WHERE status='pending' LIMIT 1").fetchone():
            # Only a complete directory walk may remove old paths.
            if not self.db.execute("SELECT 1 FROM directories WHERE status='blocked' LIMIT 1").fetchone():
                generation = int(self._meta("generation"))
                removed = [r[0] for r in self.db.execute("SELECT path FROM files WHERE seen!=?",(generation,))]
                self.changed.update(removed)
                for path in removed:
                    self.db.execute("DELETE FROM files WHERE path=?",(path,))
                    self.db.execute("DELETE FROM terms WHERE path=?",(path,))
            self._set("active",0)
            self.db.commit()
        return {**self.summary(),"batch_files":files,"batch_bytes":size,"batch_directories":directories}

    def summary(self):
        counts = {r[0]:r[1] for r in self.db.execute("SELECT status,count(*) FROM files GROUP BY status")}
        dirs = {r[0]:r[1] for r in self.db.execute("SELECT status,count(*) FROM directories GROUP BY status")}
        return {"catalogue":str(self.path),"files":counts,"directories":dirs,
                "excluded":[dict(r) for r in self.db.execute("SELECT path,reason FROM exclusions ORDER BY path")],
                "discovery_complete":not dirs.get("pending") and not dirs.get("blocked"),
                "index_complete":not dirs.get("pending") and not dirs.get("blocked") and not counts.get("pending") and not counts.get("blocked"),
                "generation":int(self._meta("generation")),"retrieval_only":True}

    def matching_files(self, terms):
        # The temporary query table avoids SQLite's parameter-count ceiling.
        self.db.execute("CREATE TEMP TABLE IF NOT EXISTS query_terms(term TEXT PRIMARY KEY)")
        self.db.execute("DELETE FROM query_terms")
        self.db.executemany("INSERT OR IGNORE INTO query_terms VALUES (?)",[(t,) for t in terms])
        return [r[0] for r in self.db.execute("""SELECT t.path FROM terms t JOIN query_terms q ON q.term=t.term
            JOIN files f ON f.path=t.path WHERE f.status='indexed'
            GROUP BY t.path ORDER BY count(*) DESC,t.path""")]

    def changed_files(self):
        return sorted(self.changed)
