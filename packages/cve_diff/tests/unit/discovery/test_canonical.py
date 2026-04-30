from __future__ import annotations

import pytest

from cve_diff.discovery.canonical import apply_mirror, is_tracker, score


class TestApplyMirror:
    def test_maps_kernel_to_github(self) -> None:
        url = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux"
        assert apply_mirror(url) == "https://github.com/torvalds/linux"

    def test_maps_xz_to_github(self) -> None:
        assert apply_mirror("https://git.tukaani.org/xz.git") == "https://github.com/tukaani-project/xz"

    def test_passes_through_github(self) -> None:
        assert apply_mirror("https://github.com/curl/curl") == "https://github.com/curl/curl"


class TestIsTracker:
    @pytest.mark.parametrize(
        "url",
        [
            "https://github.com/trickest/cve",
            "https://github.com/CVEProject/cvelistv5",
            "https://github.com/nomi-sec/PoC-in-GitHub",
            "https://github.com/projectdiscovery/nuclei-templates",
            "https://github.com/witchcraze/NVD_CHECK",
        ],
    )
    def test_flags_known_trackers(self, url: str) -> None:
        assert is_tracker(url) is True

    @pytest.mark.parametrize(
        "url",
        [
            "https://github.com/curl/curl",
            "https://github.com/openssh/openssh-portable",
            "https://github.com/tukaani-project/xz",
            "https://github.com/torvalds/linux",
        ],
    )
    def test_allows_real_repos(self, url: str) -> None:
        assert is_tracker(url) is False


class TestScore:
    def test_github_source_repo(self) -> None:
        assert score("https://github.com/curl/curl") == 100

    def test_tracker_is_zero(self) -> None:
        assert score("https://github.com/trickest/cve") == 0

    def test_non_github_after_mirror(self) -> None:
        """Mirror mapping pulls kernel.org onto GitHub → 100."""
        assert score("https://git.kernel.org/linux") == 100

    def test_unknown_non_github(self) -> None:
        assert score("https://example.com/foo.git") == 50

    def test_empty_is_zero(self) -> None:
        assert score("") == 0
