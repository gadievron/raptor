"""The embedded Java scripts compile on BOTH comment-API generations.

Newer Ghidra has the ``CommentType`` enum; older supported releases
have ``int`` constants on ``CodeUnit``. The scripts used the enum
UNCONDITIONALLY: on any supported Ghidra predating it the postScript
failed to COMPILE — killing the whole sandboxed export/import on the
default lane — while ``check_ghidra_version``'s floor passed it, and
while the package's own Python side hedges the same split with
triplicated ImportError fallbacks. The scripts now bind the comment
API reflectively; these tests compile the import script against stub
APIs of each generation (no Ghidra install needed) and pin the
export script's structure.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from packages.ghidra.export_script_java import EXPORT_SCRIPT_JAVA
from packages.ghidra.import_script_java import IMPORT_SCRIPT_JAVA

_STATIC_IMPORT = "import ghidra.program.model.listing.CommentType;"

_GSON_STUBS = {
    "com/google/gson/JsonElement.java": """
package com.google.gson;
public class JsonElement {
    public JsonObject getAsJsonObject() { return null; }
    public boolean isJsonNull() { return true; }
    public long getAsLong() { return 0; }
    public String getAsString() { return null; }
}
""",
    "com/google/gson/JsonObject.java": """
package com.google.gson;
public class JsonObject extends JsonElement {
    public boolean has(String k) { return false; }
    public JsonElement get(String k) { return null; }
    public JsonArray getAsJsonArray(String k) { return null; }
}
""",
    "com/google/gson/JsonArray.java": """
package com.google.gson;
public class JsonArray extends JsonElement
        implements Iterable<JsonElement> {
    public java.util.Iterator<JsonElement> iterator() { return null; }
}
""",
    "com/google/gson/JsonParser.java": """
package com.google.gson;
public class JsonParser {
    public static JsonElement parseReader(java.io.Reader r) {
        return null;
    }
}
""",
}

_GHIDRA_COMMON_STUBS = {
    "ghidra/app/script/GhidraScript.java": """
package ghidra.app.script;
public abstract class GhidraScript {
    public ghidra.program.model.listing.Program currentProgram;
    public String[] getScriptArgs() { return new String[0]; }
    public void println(String s) {}
    public void printerr(String s) {}
    public abstract void run() throws Exception;
}
""",
    "ghidra/program/model/address/Address.java": """
package ghidra.program.model.address;
public class Address {
    public long getOffset() { return 0; }
}
""",
    "ghidra/program/model/address/AddressSpace.java": """
package ghidra.program.model.address;
public class AddressSpace {
    public Address getAddress(long a) { return null; }
}
""",
    "ghidra/program/model/address/AddressFactory.java": """
package ghidra.program.model.address;
public class AddressFactory {
    public AddressSpace getDefaultAddressSpace() { return null; }
}
""",
    "ghidra/program/model/address/AddressSetView.java": """
package ghidra.program.model.address;
public interface AddressSetView {}
""",
    "ghidra/program/model/listing/Program.java": """
package ghidra.program.model.listing;
public class Program {
    public Listing getListing() { return null; }
    public ghidra.program.model.address.AddressFactory
            getAddressFactory() { return null; }
    public FunctionManager getFunctionManager() { return null; }
    public BookmarkManager getBookmarkManager() { return null; }
}
""",
    "ghidra/program/model/listing/Listing.java": """
package ghidra.program.model.listing;
public class Listing {
    public CodeUnit getCodeUnitAt(
            ghidra.program.model.address.Address a) { return null; }
    public java.util.List<Function> getGlobalFunctions(String n) {
        return null;
    }
}
""",
    "ghidra/program/model/listing/Function.java": """
package ghidra.program.model.listing;
public class Function {
    public ghidra.program.model.address.Address getEntryPoint() {
        return null;
    }
    public String getName() { return null; }
}
""",
    "ghidra/program/model/listing/FunctionManager.java": """
package ghidra.program.model.listing;
public class FunctionManager {
    public Function getFunctionAt(
            ghidra.program.model.address.Address a) { return null; }
    public Function createFunction(
            String n, ghidra.program.model.address.Address a,
            ghidra.program.model.address.AddressSetView body,
            ghidra.program.model.symbol.SourceType s)
            throws ghidra.util.exception.InvalidInputException,
            ghidra.program.database.function
                .OverlappingFunctionException {
        return null;
    }
}
""",
    "ghidra/program/model/listing/BookmarkManager.java": """
package ghidra.program.model.listing;
public class BookmarkManager {
    public void setBookmark(
            ghidra.program.model.address.Address a,
            String t, String c, String m) {}
}
""",
    "ghidra/program/model/symbol/SourceType.java": """
package ghidra.program.model.symbol;
public enum SourceType { USER_DEFINED }
""",
    "ghidra/util/exception/InvalidInputException.java": """
package ghidra.util.exception;
public class InvalidInputException extends Exception {}
""",
    "ghidra/program/database/function/OverlappingFunctionException.java": """
package ghidra.program.database.function;
public class OverlappingFunctionException extends Exception {}
""",
}

# Old generation: int constants + int-taking accessors, NO CommentType.
_CODEUNIT_OLD = """
package ghidra.program.model.listing;
public class CodeUnit {
    public static final int EOL_COMMENT = 0;
    public static final int PLATE_COMMENT = 1;
    public static final int PRE_COMMENT = 2;
    public static final int POST_COMMENT = 3;
    public ghidra.program.model.address.Address getAddress() {
        return null;
    }
    public String getComment(int t) { return null; }
    public void setComment(int t, String s) {}
}
"""

# New generation: CommentType enum accessors, NO int constants.
_CODEUNIT_NEW = """
package ghidra.program.model.listing;
public class CodeUnit {
    public ghidra.program.model.address.Address getAddress() {
        return null;
    }
    public String getComment(CommentType t) { return null; }
    public void setComment(CommentType t, String s) {}
}
"""

_COMMENT_TYPE = """
package ghidra.program.model.listing;
public enum CommentType { EOL, PLATE, PRE, POST }
"""


def _compile_import_script(tmp_path: Path, *, new_api: bool) -> None:
    stubs = dict(_GSON_STUBS)
    stubs.update(_GHIDRA_COMMON_STUBS)
    stubs["ghidra/program/model/listing/CodeUnit.java"] = (
        _CODEUNIT_NEW if new_api else _CODEUNIT_OLD
    )
    if new_api:
        stubs["ghidra/program/model/listing/CommentType.java"] = (
            _COMMENT_TYPE
        )
    root = tmp_path / ("new" if new_api else "old")
    for rel, src in stubs.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(src, encoding="utf-8")
    script = root / "ImportRaptor.java"
    script.write_text(IMPORT_SCRIPT_JAVA, encoding="utf-8")
    files = [str(p) for p in sorted(root.rglob("*.java"))]
    proc = subprocess.run(
        ["javac", "-d", str(root / "out"), *files],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, (
        f"import script does not compile against the "
        f"{'CommentType-enum' if new_api else 'int-constant'} "
        f"generation:\n{proc.stderr[:4000]}"
    )


@pytest.mark.skipif(shutil.which("javac") is None,
                    reason="javac not available")
class TestImportScriptCompilesOnBothGenerations:
    def test_compiles_without_comment_type_enum(self, tmp_path):
        _compile_import_script(tmp_path, new_api=False)

    def test_compiles_with_comment_type_enum_only(self, tmp_path):
        _compile_import_script(tmp_path, new_api=True)


class TestNoStaticCommentApiReferences:
    @staticmethod
    def _flat(java_src: str) -> str:
        return " ".join(java_src.split())

    def test_import_script_has_no_static_comment_type(self):
        assert _STATIC_IMPORT not in IMPORT_SCRIPT_JAVA
        flat = self._flat(IMPORT_SCRIPT_JAVA)
        assert "reflect.Method" in flat
        assert 'getMethod("getComment", int.class)' in flat
        assert 'getMethod("getComment", ct)' in flat
        assert 'getMethod( "setComment", int.class, String.class)' in flat
        assert 'getMethod( "setComment", ct, String.class)' in flat

    def test_export_script_has_no_static_comment_type(self):
        assert _STATIC_IMPORT not in EXPORT_SCRIPT_JAVA
        assert "CommentType[]" not in EXPORT_SCRIPT_JAVA
        flat = self._flat(EXPORT_SCRIPT_JAVA)
        assert 'getMethod("getComment", int.class)' in flat
        assert 'getMethod("getComment", ct)' in flat
