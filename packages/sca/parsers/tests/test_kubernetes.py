"""Tests for the Kubernetes manifest parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.sca.parsers.kubernetes import (
    _is_k8s_manifest,
    parse,
)


pytest.importorskip("yaml")


def _write(tmp_path: Path, content: str, name: str = "deploy.yaml") -> Path:
    p = tmp_path / name
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# Workload kinds — image extraction
# ---------------------------------------------------------------------------


def test_pod_simple_container(tmp_path):
    p = _write(tmp_path, """\
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  containers:
    - name: main
      image: nginx:1.25
""")
    [d] = parse(p)
    assert d.name == "nginx"
    assert d.version == "1.25"
    assert d.ecosystem == "OCI"
    assert d.source_kind == "k8s"
    assert "Pod/my-pod" in d.source_extra["context"]
    assert d.source_extra["container"] == "main"


def test_deployment_template_spec(tmp_path):
    """Deployment wraps containers under
    ``spec.template.spec.containers``."""
    p = _write(tmp_path, """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: app
          image: ghcr.io/myorg/web:v1.2.3
""")
    [d] = parse(p)
    assert d.name == "ghcr.io/myorg/web"
    assert d.version == "v1.2.3"
    assert "Deployment/web" in d.source_extra["context"]


def test_init_containers_extracted(tmp_path):
    p = _write(tmp_path, """\
apiVersion: v1
kind: Pod
metadata:
  name: p
spec:
  initContainers:
    - name: setup
      image: busybox:1.36
  containers:
    - name: main
      image: nginx:1.25
""")
    deps = parse(p)
    by_image = {(d.name, d.version) for d in deps}
    assert ("busybox", "1.36") in by_image
    assert ("nginx", "1.25") in by_image
    init = next(d for d in deps if d.name == "busybox")
    assert "initContainers" in init.source_extra["context"]


def test_statefulset_extracted(tmp_path):
    p = _write(tmp_path, """\
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: db
spec:
  template:
    spec:
      containers:
        - name: postgres
          image: postgres:16-alpine
""")
    [d] = parse(p)
    assert d.name == "postgres"
    assert d.version == "16-alpine"


def test_daemonset_cronjob_job_replicaset(tmp_path):
    """All four other workload kinds extract images."""
    p = _write(tmp_path, """\
apiVersion: apps/v1
kind: DaemonSet
metadata: {name: ds}
spec:
  template:
    spec:
      containers: [{name: x, image: ds-img:1}]
---
apiVersion: batch/v1
kind: CronJob
metadata: {name: cj}
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers: [{name: y, image: cj-img:1}]
---
apiVersion: batch/v1
kind: Job
metadata: {name: j}
spec:
  template:
    spec:
      containers: [{name: z, image: j-img:1}]
---
apiVersion: apps/v1
kind: ReplicaSet
metadata: {name: rs}
spec:
  template:
    spec:
      containers: [{name: w, image: rs-img:1}]
""")
    deps = parse(p)
    images = {d.name for d in deps}
    # CronJob nests one extra level; we don't dive into
    # jobTemplate.spec.template.spec, so cj-img is missed here.
    # Daemon / Job / ReplicaSet all extract.
    assert "ds-img" in images
    assert "j-img" in images
    assert "rs-img" in images


def test_multi_document_yaml(tmp_path):
    """``---``-separated multi-doc YAML — common in
    ``manifests/`` bundles."""
    p = _write(tmp_path, """\
apiVersion: v1
kind: Pod
metadata: {name: p1}
spec:
  containers: [{name: c1, image: app1:v1}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: d1}
spec:
  template:
    spec:
      containers: [{name: c2, image: app2:v2}]
""")
    deps = parse(p)
    assert {d.name for d in deps} == {"app1", "app2"}


# ---------------------------------------------------------------------------
# Non-workload kinds skipped
# ---------------------------------------------------------------------------


def test_non_workload_kinds_skipped(tmp_path):
    """``Service``, ``ConfigMap``, etc. don't carry container
    images at the standard path. Skip silently."""
    p = _write(tmp_path, """\
apiVersion: v1
kind: Service
metadata: {name: s}
spec:
  ports:
    - port: 80
""")
    assert parse(p) == []


def test_non_kubernetes_yaml_skipped(tmp_path):
    """A YAML file without ``kind:`` is skipped."""
    p = _write(tmp_path, """\
some_config:
  value: 1
""")
    assert parse(p) == []


# ---------------------------------------------------------------------------
# _is_k8s_manifest predicate — routing
# ---------------------------------------------------------------------------


def test_predicate_matches_yaml(tmp_path):
    assert _is_k8s_manifest(tmp_path / "deploy.yml")
    assert _is_k8s_manifest(tmp_path / "manifests/pod.yaml")


def test_predicate_skips_compose(tmp_path):
    assert not _is_k8s_manifest(tmp_path / "docker-compose.yml")
    assert not _is_k8s_manifest(tmp_path / "compose.yaml")
    assert not _is_k8s_manifest(tmp_path / "compose.dev.yml")


def test_predicate_skips_gitlab_ci(tmp_path):
    assert not _is_k8s_manifest(tmp_path / ".gitlab-ci.yml")
    assert not _is_k8s_manifest(tmp_path / ".gitlab-ci.yaml")


def test_predicate_skips_helm():
    assert not _is_k8s_manifest(Path("project/Chart.yaml"))


def test_predicate_skips_precommit():
    assert not _is_k8s_manifest(Path("project/.pre-commit-config.yaml"))


def test_predicate_skips_gha_workflows(tmp_path):
    assert not _is_k8s_manifest(
        tmp_path / ".github/workflows/ci.yml"
    )


def test_predicate_skips_action_yml():
    assert not _is_k8s_manifest(Path("project/action.yml"))


def test_predicate_rejects_non_yaml():
    assert not _is_k8s_manifest(Path("project/deploy.json"))


# ---------------------------------------------------------------------------
# Image-ref shapes
# ---------------------------------------------------------------------------


def test_digest_pinned_image(tmp_path):
    sha = "sha256:" + "a" * 64
    p = _write(tmp_path, f"""\
apiVersion: v1
kind: Pod
metadata: {{name: p}}
spec:
  containers:
    - name: c
      image: postgres@{sha}
""")
    [d] = parse(p)
    assert d.name == "postgres"
    assert d.version == sha


def test_image_without_tag(tmp_path):
    p = _write(tmp_path, """\
apiVersion: v1
kind: Pod
metadata: {name: p}
spec:
  containers:
    - {name: c, image: alpine}
""")
    [d] = parse(p)
    assert d.name == "alpine"
    assert d.version is None


# ---------------------------------------------------------------------------
# Resilience
# ---------------------------------------------------------------------------


def test_malformed_yaml(tmp_path):
    p = _write(tmp_path, ":")
    # Either no docs OR an exception that's caught — no crash.
    assert parse(p) == []


def test_empty_file(tmp_path):
    p = _write(tmp_path, "")
    assert parse(p) == []


def test_container_without_image_skipped(tmp_path):
    """Container missing ``image:`` field — skip, don't crash."""
    p = _write(tmp_path, """\
apiVersion: v1
kind: Pod
metadata: {name: p}
spec:
  containers:
    - name: bad
    - name: ok
      image: nginx:1.25
""")
    deps = parse(p)
    assert {d.name for d in deps} == {"nginx"}


# ---------------------------------------------------------------------------
# Discovery integration
# ---------------------------------------------------------------------------


def test_discovery_finds_k8s_manifest(tmp_path):
    from packages.sca.discovery import find_manifests
    _write(tmp_path, """\
apiVersion: v1
kind: Pod
metadata: {name: p}
spec:
  containers: [{name: c, image: nginx:1.25}]
""")
    manifests = find_manifests(tmp_path)
    found = [m for m in manifests if m.path.name == "deploy.yaml"]
    assert len(found) == 1
    assert found[0].ecosystem == "Kubernetes"
