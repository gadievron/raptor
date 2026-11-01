"""Durable, single-writer work inventory. Completion means attempted, not safe."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path

from core.json import dumps_canonical

from .model import digest


@contextmanager
def exclusive_session(path: Path):
    """Fail busy instead of dispatching duplicate paid work in another process."""
    path.parent.mkdir(parents=True,exist_ok=True)
    connection = sqlite3.connect(path,timeout=0,isolation_level=None)
    try:
        try:
            connection.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as exc:
            raise RuntimeError("cross-entry work is already held by another worker") from exc
        yield
    finally:
        connection.rollback()
        connection.close()


class WorkQueue:
    def __init__(self, out_dir: Path, namespace: str):
        self.db = sqlite3.connect(out_dir/"cross-entry-work.sqlite")
        self.db.row_factory = sqlite3.Row
        self.namespace = namespace
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS views (
                namespace TEXT, id TEXT, extra_file TEXT, fingerprint TEXT DEFAULT '',
                status TEXT DEFAULT 'pending', last_turn INTEGER DEFAULT 0, dependencies TEXT DEFAULT '{}',
                PRIMARY KEY(namespace,id));
            CREATE TABLE IF NOT EXISTS jobs (
                namespace TEXT, view_id TEXT, id TEXT, consumer TEXT, focus TEXT,
                status TEXT DEFAULT 'pending', attempts INTEGER DEFAULT 0, result TEXT DEFAULT '{}',
                PRIMARY KEY(namespace,view_id,id));
            CREATE TABLE IF NOT EXISTS reports (
                namespace TEXT, key TEXT, PRIMARY KEY(namespace,key));
            CREATE TABLE IF NOT EXISTS acknowledgements (
                namespace TEXT, view_id TEXT, job_id TEXT, evidence TEXT,
                PRIMARY KEY(namespace,view_id,job_id,evidence));
            CREATE TABLE IF NOT EXISTS query_tokens (
                namespace TEXT,term TEXT,PRIMARY KEY(namespace,term));
            CREATE TABLE IF NOT EXISTS report_requests (
                namespace TEXT,key TEXT,request TEXT,PRIMARY KEY(namespace,key));
        """)

    def close(self):
        self.db.close()

    def add_reports(self, keys):
        self.db.executemany("INSERT OR IGNORE INTO reports VALUES (?,?)",[(self.namespace,k) for k in keys])
        self.db.commit()

    def add_requests(self, requests):
        for value in requests:
            if value.get("file") and value.get("name"):
                request = {k:value[k] for k in ("file","name","line_start","line_end","qualified_name") if k in value}
                key = f"{request['file']}:{request['name']}"
                self.db.execute("INSERT OR REPLACE INTO report_requests VALUES (?,?,?)",(self.namespace,key,dumps_canonical(request)))
        self.db.commit()

    def requests(self):
        import json
        return [json.loads(r[0]) for r in self.db.execute("SELECT request FROM report_requests WHERE namespace=? ORDER BY key",(self.namespace,))]

    def add_views(self, files):
        files = list(files)
        self.db.executemany("INSERT OR IGNORE INTO views(namespace,id,extra_file) VALUES (?,?,?)",
                            [(self.namespace,digest(p)[:24],p) for p in files])
        self.db.commit()
        for path in files:
            self.db.execute("UPDATE views SET status='pending',fingerprint='' WHERE namespace=? AND extra_file=? AND status='obsolete'",
                            (self.namespace,path))
        self.db.commit()

    def invalidate_files(self, changed):
        import json
        for row in self.db.execute("SELECT id,dependencies FROM views WHERE namespace=?",(self.namespace,)).fetchall():
            if set(json.loads(row["dependencies"])) & set(changed):
                self.db.execute("UPDATE views SET status='pending',fingerprint='' WHERE namespace=? AND id=?",(self.namespace,row["id"]))
        self.db.commit()

    def next_view(self):
        row = self.db.execute("SELECT * FROM views WHERE namespace=? AND status='pending' ORDER BY last_turn,extra_file LIMIT 1",
                              (self.namespace,)).fetchone()
        if row is None:
            return None
        turn = self.db.execute("SELECT coalesce(max(last_turn),0)+1 FROM views WHERE namespace=?",(self.namespace,)).fetchone()[0]
        self.db.execute("UPDATE views SET last_turn=? WHERE namespace=? AND id=?",(turn,self.namespace,row["id"]))
        self.db.commit()
        return dict(row)

    def bind_view(self, view, fingerprint, dependencies):
        row = self.db.execute("SELECT fingerprint FROM views WHERE namespace=? AND id=?",(self.namespace,view)).fetchone()
        if row is not None and row[0] != fingerprint:
            self.db.execute("DELETE FROM jobs WHERE namespace=? AND view_id=?",(self.namespace,view))
            self.db.execute("UPDATE views SET status='pending' WHERE namespace=? AND id=?",(self.namespace,view))
        self.db.execute("UPDATE views SET fingerprint=?,dependencies=? WHERE namespace=? AND id=?",
                        (fingerprint,dumps_canonical(dependencies),self.namespace,view))
        self.db.commit()

    def add_terms(self, terms):
        self.db.executemany("INSERT OR IGNORE INTO query_tokens VALUES (?,?)",[(self.namespace,t) for t in terms])
        self.db.commit()

    def terms(self):
        return {r[0] for r in self.db.execute("SELECT term FROM query_tokens WHERE namespace=?",(self.namespace,))}

    def add_jobs(self, view, descriptors):
        for consumer,focus in descriptors:
            job_id = digest([consumer,focus])[:24]
            self.db.execute("INSERT OR IGNORE INTO jobs(namespace,view_id,id,consumer,focus) VALUES (?,?,?,?,?)",
                            (self.namespace,view,job_id,consumer,focus))
        self.db.commit()

    def pending(self, view):
        return [dict(r) for r in self.db.execute("""SELECT * FROM jobs WHERE namespace=? AND view_id=?
            AND status NOT IN ('complete','prepared','not_applicable','blocked','obsolete')
            ORDER BY CASE status WHEN 'partial' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END,
                     CASE WHEN focus='' THEN 0 ELSE 1 END,attempts,id""",
            (self.namespace,view))]

    def finish(self, view, job_id, status, result=None):
        self.db.execute("UPDATE jobs SET status=?,attempts=attempts+1,result=? WHERE namespace=? AND view_id=? AND id=?",
                        (status,dumps_canonical(result or {}),self.namespace,view,job_id))
        self.db.commit()

    def complete_view_if_finished(self, view):
        pending = self.db.execute("SELECT count(*) FROM jobs WHERE namespace=? AND view_id=? AND status NOT IN ('complete','prepared','not_applicable','obsolete')",
                                  (self.namespace,view)).fetchone()[0]
        if self.undelivered(view):
            self.db.execute("UPDATE views SET status='pending' WHERE namespace=? AND id=?",(self.namespace,view))
            self.db.commit()
        elif not pending:
            self.db.execute("UPDATE views SET status='complete' WHERE namespace=? AND id=?",(self.namespace,view))
            self.db.commit()
        elif pending and not self.pending(view):
            self.db.execute("UPDATE views SET status='blocked' WHERE namespace=? AND id=?",(self.namespace,view))
            self.db.commit()

    def summary(self):
        import json
        counts = {r[0]:r[1] for r in self.db.execute("SELECT status,count(*) FROM jobs WHERE namespace=? GROUP BY status",(self.namespace,))}
        views = {r[0]:r[1] for r in self.db.execute("SELECT status,count(*) FROM views WHERE namespace=? GROUP BY status",(self.namespace,))}
        pending = sum(v for k,v in counts.items() if k not in {"complete","prepared","not_applicable","obsolete"})
        return {"jobs":counts,"views":views,"remaining_jobs":pending,
                "blocked_work":[{"view":r["view_id"],"consumer":r["consumer"],"focus":r["focus"],"detail":json.loads(r["result"])}
                                for r in self.db.execute("SELECT * FROM jobs WHERE namespace=? AND status='blocked'",(self.namespace,))],
                "remaining_views":sum(v for k,v in views.items() if k not in {"complete","obsolete"}),
                "undelivered_results":len(self.undelivered()),
                "report_keys":[r[0] for r in self.db.execute("SELECT key FROM reports WHERE namespace=? ORDER BY key",(self.namespace,))]}

    def undelivered(self, view=None):
        import json
        sql = "SELECT * FROM jobs WHERE namespace=? AND status IN ('complete','prepared')"
        params = [self.namespace]
        if view is not None:
            sql += " AND view_id=?"
            params.append(view)
        result = []
        for row in self.db.execute(sql+" ORDER BY rowid",params):
            value = json.loads(row["result"])
            evidence = value.get("key","")
            if evidence and not self.db.execute("SELECT 1 FROM acknowledgements WHERE namespace=? AND view_id=? AND job_id=? AND evidence=?",
                                               (self.namespace,row["view_id"],row["id"],evidence)).fetchone():
                result.append({**dict(row),"outcome":value,"evidence":evidence})
        return result

    def acknowledge(self, view, job, evidence):
        self.db.execute("INSERT OR IGNORE INTO acknowledgements VALUES (?,?,?,?)",(self.namespace,view,job,evidence))
        self.db.commit()
        self.complete_view_if_finished(view)

    def reconcile_views(self, files):
        active = set(files)
        for row in self.db.execute("SELECT id,extra_file,status FROM views WHERE namespace=?",(self.namespace,)).fetchall():
            if row["extra_file"] not in active:
                self.db.execute("UPDATE views SET status='obsolete' WHERE namespace=? AND id=?",(self.namespace,row["id"]))
                self.db.execute("UPDATE jobs SET status='obsolete' WHERE namespace=? AND view_id=?",(self.namespace,row["id"]))
        self.add_views(active)
        self.db.commit()


def pending_report_keys(out_dir: Path, *, selection_key=None, target=None):
    from core.json import load_json
    progress = load_json(Path(out_dir)/"cross-entry-progress.json")
    if not isinstance(progress,dict) or not progress.get("namespace"):
        return set()
    if selection_key is not None and progress.get("selection_key") != selection_key:
        return set()
    if target is not None and progress.get("target") != str(Path(target).resolve()):
        return set()
    queue = WorkQueue(Path(out_dir),progress["namespace"])
    try:
        return {key for key in progress.get("report_keys",[]) if isinstance(key,str)} if queue.undelivered() else set()
    finally:
        queue.close()


def acknowledge_delivery(out_dir: Path, receipt):
    if not isinstance(receipt,dict) or not all(isinstance(receipt.get(k),str) for k in ("namespace","view","job","evidence")):
        return
    queue = WorkQueue(Path(out_dir),receipt["namespace"])
    try:
        queue.acknowledge(receipt["view"],receipt["job"],receipt["evidence"])
    finally:
        queue.close()
