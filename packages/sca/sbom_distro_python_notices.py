"""Associate Debian project notices with checksum-matched Python metadata."""
from copy import deepcopy
import re


_MISSING_NOTICE = "no associated notice candidate; licence text completeness is unverified"


def _project(value):
    return re.sub(r"[-_.]+", "-", value).lower()


def project_notices(artifact, record, artifacts, blobs):
    """Require one verified owner and an explicit project source in its notice.

    This associates retained texts; it neither inherits the Debian package's
    licence declaration nor decides whether its terms permit redistribution.
    """
    if artifact.get("type") != "python" or record["status"] == "notice_candidate_captured":
        return []
    context = record.get("distro_owner_context", {})
    owners = context.get("checksum_matched_notices", [])
    if context.get("unresolved_locations") or len(owners) != 1:
        return []
    owner = owners[0]
    project = _project(artifact["name"])
    parent = artifacts.get(owner["owner_package_id"], {})
    if parent.get("type") != "deb" or _project(parent.get("name", "")) != "python3-" + project:
        return []
    notices = [row for row in owner["files"]
               if row["path"] == "/usr/share/doc/" + parent["name"] + "/copyright"]
    if len(notices) != 1:
        return []
    text = blobs[notices[0]["sha256"]].decode("utf-8", errors="replace")
    # Source belongs to the project header, never a vendored dependency stanza.
    header = re.split(r"(?m)^Files:|^License:", text, maxsplit=1)[0]
    sources = re.findall(
        r"(?m)^(?:Source:[ \t]*|It was downloaded from[ \t]*\n)"
        r"https?://(?:pypi\.org|pypi\.python\.org)/(?:project|pypi)/([A-Za-z0-9_.-]+)/?[ \t]*$",
        header,
    )
    if len(sources) != 1 or _project(sources[0]) != project:
        return []
    result = deepcopy(owner["files"])
    for row in result:
        row["reasons"] = ["checksum_matched_debian_python_project_notice"]
    return result


def associate_project_notices(native, records, blobs, *, limit=100_000):
    """Close only the missing-own-notice gap; retain owner reference gaps."""
    artifacts = {artifact["id"]: artifact for artifact in native["artifacts"]}
    count = sum(len(record["files"]) for record in records)
    for record in records:
        notices = project_notices(artifacts[record["id"]], record, artifacts, blobs)
        if not notices:
            continue
        keys = {(row["path"], row["catalogue_layer_diff_id"]) for row in record["files"]}
        for row in notices:
            if (row["path"], row["catalogue_layer_diff_id"]) not in keys:
                count += 1
                if count > limit:
                    raise ValueError("project notice association budget exceeded")
                record["files"].append(row)
                keys.add((row["path"], row["catalogue_layer_diff_id"]))
        record["files"].sort(key=lambda row: (row["path"], row["catalogue_layer_diff_id"]))
        record["status"] = "notice_candidate_captured"
        record["gaps"] = [gap for gap in record["gaps"] if gap != _MISSING_NOTICE]
        for gap in record["distro_owner_context"]["checksum_matched_notices"][0]["owner_notice_gaps"]:
            if gap not in record["gaps"]:
                record["gaps"].append(gap)
