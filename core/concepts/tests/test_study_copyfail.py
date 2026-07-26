"""Test that study-prep produces correct items for CopyFail ground truth."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

RAPTOR_DIR = Path(__file__).resolve().parents[3]
STUDY_PREP = str(RAPTOR_DIR / "libexec" / "raptor-study-prep")
TARGET = Path("/tmp/copyfail-audit/target")


@pytest.mark.skipif(not TARGET.is_dir(), reason="CopyFail target not set up")
class TestStudyPrepCopyFail:
    def test_concept_seeded_items_cover_key_functions(self, tmp_path: Path) -> None:
        """With aliasing concepts seeded, prep extracts items for the bug-site functions."""
        env = os.environ.copy()
        env["_RAPTOR_TRUSTED"] = "1"
        result = subprocess.run(
            [sys.executable, STUDY_PREP, str(TARGET), str(tmp_path),
             "--concept", "scatterlist_page_ownership,in_place_crypto_aliasing"],
            env=env, capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, result.stderr

        study_list = tmp_path / "study-list.json"
        assert study_list.is_file()
        data = json.loads(study_list.read_text())
        items = data.get("items", [])

        # The study items should reference the key functions/types
        all_text = json.dumps(items).lower()
        # Must find scatterlist-related items
        assert "scatterlist" in all_text or "sg_page" in all_text or "sg_set_page" in all_text
        # Must find the function where aliasing happens
        assert (
            "_aead_recvmsg" in all_text
            or "memcpy_sglist" in all_text
            or "aead_request_set_crypt" in all_text
        )

    def test_identifier_seeded_extracts_aead_recvmsg(self, tmp_path: Path) -> None:
        """With _aead_recvmsg as identifier seed, prep extracts it directly."""
        env = os.environ.copy()
        env["_RAPTOR_TRUSTED"] = "1"
        result = subprocess.run(
            [sys.executable, STUDY_PREP, str(TARGET), str(tmp_path),
             "--identifier", "_aead_recvmsg,af_alg_pull_tsgl"],
            env=env, capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, result.stderr

        study_list = tmp_path / "study-list.json"
        data = json.loads(study_list.read_text())
        items = data.get("items", [])
        item_names = [i.get("name", "").lower() for i in items]

        assert any("_aead_recvmsg" in n for n in item_names)
