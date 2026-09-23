"""Java GhidraScript for export — works on Ghidra 11 and 12.

This module contains the Java source as a string constant.  At runtime,
:mod:`packages.ghidra.headless` writes it to a tempfile and passes it
to ``analyzeHeadless -postScript``.

Java scripts compile at load time inside Ghidra's JVM — no Jython or
PyGhidra dependency.  The script uses Gson (bundled with Ghidra) for
JSON output.
"""

EXPORT_SCRIPT_JAVA = r'''
// RAPTOR Ghidra export script — extracts RE data to JSON.
// Invoked via: analyzeHeadless ... -postScript ExportRaptor.java <output.json>
// @category RAPTOR

import com.google.gson.*;
import com.google.gson.stream.JsonWriter;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;
import ghidra.program.model.data.AbstractStringDataType;

public class ExportRaptor extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) {
            printerr("ExportRaptor requires an output path argument");
            return;
        }
        String outputPath = args[0];
        boolean doDecomp = args.length > 1 && "decomp".equals(args[1]);

        Program program = currentProgram;
        println("RAPTOR: exporting from " + program.getName());

        JsonObject root = new JsonObject();
        root.addProperty("source_tool", "ghidra");
        root.addProperty("binary_path", program.getExecutablePath());

        String arch = program.getLanguage().getLanguageDescription().getProcessor() +
                "/" + program.getLanguage().getLanguageDescription().getSize();
        root.addProperty("architecture", arch);

        // Metadata
        JsonObject meta = new JsonObject();
        meta.addProperty("program_name", program.getName());
        Object ghidraVer = program.getMetadata().get("Ghidra Version");
        meta.addProperty("ghidra_version", ghidraVer != null ? ghidraVer.toString() : "");
        meta.addProperty("language_id", program.getLanguageID().toString());
        meta.addProperty("compiler_spec", program.getCompilerSpec().getCompilerSpecID().toString());
        meta.addProperty("image_base", program.getImageBase().getOffset());
        root.add("metadata", meta);

        // Functions
        println("RAPTOR: exporting functions" + (doDecomp ? " (with decompilation)..." : "..."));
        JsonArray functions = exportFunctions(program, doDecomp);
        root.add("functions", functions);
        println("RAPTOR: " + functions.size() + " functions");

        // XRefs
        println("RAPTOR: exporting xrefs...");
        JsonArray xrefs = exportXrefs(program);
        root.add("xrefs", xrefs);
        println("RAPTOR: " + xrefs.size() + " xrefs");

        // Types
        println("RAPTOR: exporting types...");
        JsonArray types = exportTypes(program);
        root.add("types", types);
        println("RAPTOR: " + types.size() + " types");

        // Comments
        println("RAPTOR: exporting comments...");
        JsonArray comments = exportComments(program);
        root.add("comments", comments);
        println("RAPTOR: " + comments.size() + " comments");

        // Segments
        println("RAPTOR: exporting segments...");
        root.add("segments", exportSegments(program));

        // Imports / Exports
        println("RAPTOR: exporting imports/exports...");
        root.add("imports", exportImports(program));
        root.add("exports", exportExports(program));

        // Strings
        println("RAPTOR: exporting strings...");
        root.add("strings", exportStrings(program));

        // Bookmarks
        println("RAPTOR: exporting bookmarks...");
        root.add("bookmarks", exportBookmarks(program));

        // Write JSON
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        try (FileWriter fw = new FileWriter(outputPath)) {
            gson.toJson(root, fw);
        }
        println("RAPTOR: export complete -> " + outputPath);
    }

    private JsonArray exportFunctions(Program program, boolean doDecomp) throws Exception {
        JsonArray arr = new JsonArray();
        FunctionManager fm = program.getFunctionManager();

        DecompInterface decomp = null;
        if (doDecomp) {
            try {
                decomp = new DecompInterface();
                decomp.openProgram(program);
            } catch (Exception e) {
                decomp = null;
            }
        }

        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function func = it.next();
            Address entry = func.getEntryPoint();
            String name = func.getName();

            SourceType symSource = func.getSymbol().getSource();
            boolean isAuto = symSource == SourceType.ANALYSIS
                    || name.startsWith("FUN_");

            // Raw symbol source, exported alongside the conflated
            // isAuto flag: DEFAULT (tool placeholder), ANALYSIS
            // (FunctionID / demangler), IMPORTED (debug info or
            // symbol table), USER_DEFINED (analyst rename). The
            // Python parser mints the name-provenance tag from this.
            String symSourceName;
            if (symSource == SourceType.DEFAULT) {
                symSourceName = "default";
            } else if (symSource == SourceType.ANALYSIS) {
                symSourceName = "analysis";
            } else if (symSource == SourceType.IMPORTED) {
                symSourceName = "imported";
            } else if (symSource == SourceType.USER_DEFINED) {
                symSourceName = "user_defined";
            } else {
                symSourceName = symSource.toString();
            }

            JsonObject f = new JsonObject();
            f.addProperty("name", name);
            f.addProperty("address", entry.getOffset());
            f.addProperty("size", func.getBody().getNumAddresses());
            f.addProperty("source_tool", "ghidra");
            f.addProperty("is_auto_named", isAuto);
            f.addProperty("symbol_source", symSourceName);
            f.addProperty("is_thunk", func.isThunk());
            f.addProperty("is_external", func.isExternal());

            try {
                String sig = func.getSignature().getPrototypeString();
                if (sig != null) f.addProperty("signature", sig);
            } catch (Exception e) { /* skip */ }

            try {
                if (func.getCallingConvention() != null) {
                    f.addProperty("calling_convention",
                            func.getCallingConvention().getName());
                }
            } catch (Exception e) { /* skip */ }

            if (decomp != null && !func.isExternal() && !func.isThunk()) {
                try {
                    DecompileResults result = decomp.decompileFunction(func, 30, monitor);
                    if (result != null && result.decompileCompleted()) {
                        ghidra.app.decompiler.DecompiledFunction df = result.getDecompiledFunction();
                        if (df != null) {
                            String c = df.getC();
                            if (c != null) f.addProperty("decompilation", c);
                        }
                    }
                } catch (Exception e) { /* skip */ }
            }

            arr.add(f);
        }

        if (decomp != null) {
            try { decomp.dispose(); } catch (Exception e) { /* skip */ }
        }
        return arr;
    }

    private JsonArray exportXrefs(Program program) {
        JsonArray arr = new JsonArray();
        ReferenceManager rm = program.getReferenceManager();
        FunctionManager fm = program.getFunctionManager();
        Set<String> seen = new HashSet<>();

        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function func = it.next();
            AddressSetView body = func.getBody();
            AddressIterator addrIt = body.getAddresses(true);
            while (addrIt.hasNext()) {
                Address addr = addrIt.next();
                for (Reference ref : rm.getReferencesFrom(addr)) {
                    Address toAddr = ref.getToAddress();
                    if (toAddr == null || !toAddr.isMemoryAddress()) continue;

                    String kind = "data";
                    if (ref.getReferenceType().isCall()) kind = "call";

                    String key = addr.getOffset() + ":" + toAddr.getOffset() + ":" + kind;
                    if (seen.add(key)) {
                        JsonObject x = new JsonObject();
                        x.addProperty("from_addr", addr.getOffset());
                        x.addProperty("to_addr", toAddr.getOffset());
                        x.addProperty("kind", kind);
                        x.addProperty("source_tool", "ghidra");
                        arr.add(x);
                    }
                }
            }
        }
        return arr;
    }

    private JsonArray exportTypes(Program program) {
        JsonArray arr = new JsonArray();
        DataTypeManager dtm = program.getDataTypeManager();
        Iterator<DataType> it = dtm.getAllDataTypes();
        while (it.hasNext() && !monitor.isCancelled()) {
            DataType dt = it.next();
            JsonObject t = new JsonObject();
            t.addProperty("name", dt.getName());
            t.addProperty("source_tool", "ghidra");

            if (dt instanceof Structure) {
                t.addProperty("kind", "struct");
                t.addProperty("size", dt.getLength());
                JsonArray fields = new JsonArray();
                for (DataTypeComponent comp : ((Structure) dt).getComponents()) {
                    JsonObject field = new JsonObject();
                    field.addProperty("name", comp.getFieldName() != null ? comp.getFieldName() : "");
                    field.addProperty("offset", comp.getOffset());
                    field.addProperty("type", comp.getDataType().getName());
                    field.addProperty("size", comp.getLength());
                    fields.add(field);
                }
                t.add("fields", fields);
                arr.add(t);
            } else if (dt instanceof ghidra.program.model.data.Enum) {
                t.addProperty("kind", "enum");
                t.addProperty("size", dt.getLength());
                arr.add(t);
            } else if (dt instanceof TypeDef) {
                t.addProperty("kind", "typedef");
                t.addProperty("size", dt.getLength());
                arr.add(t);
            } else if (dt instanceof FunctionDefinition) {
                t.addProperty("kind", "function_sig");
                arr.add(t);
            }
        }
        return arr;
    }

    private JsonArray exportComments(Program program) throws Exception {
        JsonArray arr = new JsonArray();
        Listing listing = program.getListing();
        FunctionManager fm = program.getFunctionManager();

        String[] kindNames = {"eol", "plate", "pre", "post"};
        // Comment API via reflection: newer Ghidra has the CommentType
        // enum (getComment(CommentType)); older releases have int
        // constants on CodeUnit (getComment(int)). A STATIC reference
        // to either generation fails to COMPILE on the other, killing
        // the whole sandboxed export while the version gate passes it
        // — reflection compiles everywhere and binds at run time
        // (same split the Python side handles with ImportError
        // fallbacks in bridge/session/server_worker).
        Object[] typeArgs = new Object[4];
        java.lang.reflect.Method getComment;
        try {
            Class<?> ct = Class.forName(
                "ghidra.program.model.listing.CommentType");
            String[] enumNames = {"EOL", "PLATE", "PRE", "POST"};
            for (int i = 0; i < 4; i++) {
                typeArgs[i] = ct.getField(enumNames[i]).get(null);
            }
            getComment = CodeUnit.class.getMethod("getComment", ct);
        } catch (ReflectiveOperationException e) {
            String[] fieldNames = {"EOL_COMMENT", "PLATE_COMMENT",
                                   "PRE_COMMENT", "POST_COMMENT"};
            for (int i = 0; i < 4; i++) {
                typeArgs[i] = CodeUnit.class.getField(fieldNames[i])
                    .get(null);
            }
            getComment = CodeUnit.class.getMethod("getComment",
                                                  int.class);
        }

        CodeUnitIterator it = listing.getCodeUnits(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            CodeUnit cu = it.next();
            Address addr = cu.getAddress();
            Function func = fm.getFunctionContaining(addr);
            String funcName = func != null ? func.getName() : null;

            for (int i = 0; i < 4; i++) {
                String text = (String) getComment.invoke(cu, typeArgs[i]);
                if (text != null) {
                    JsonObject c = new JsonObject();
                    c.addProperty("address", addr.getOffset());
                    if (funcName != null) c.addProperty("function", funcName);
                    c.addProperty("kind", kindNames[i]);
                    c.addProperty("text", text);
                    c.addProperty("source_tool", "ghidra");
                    arr.add(c);
                }
            }
        }
        return arr;
    }

    private JsonArray exportSegments(Program program) {
        JsonArray arr = new JsonArray();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            StringBuilder perms = new StringBuilder();
            perms.append(block.isRead() ? "r" : "-");
            perms.append(block.isWrite() ? "w" : "-");
            perms.append(block.isExecute() ? "x" : "-");

            JsonObject s = new JsonObject();
            s.addProperty("name", block.getName());
            s.addProperty("start", block.getStart().getOffset());
            s.addProperty("end", block.getEnd().getOffset());
            s.addProperty("permissions", perms.toString());
            arr.add(s);
        }
        return arr;
    }

    private JsonArray exportImports(Program program) {
        JsonArray arr = new JsonArray();
        SymbolTable st = program.getSymbolTable();
        SymbolIterator it = st.getExternalSymbols();
        while (it.hasNext()) {
            Symbol sym = it.next();
            JsonObject imp = new JsonObject();
            imp.addProperty("name", sym.getName());

            long addr = 0;
            try {
                Reference[] refs = sym.getReferences();
                if (refs.length > 0) {
                    addr = refs[0].getFromAddress().getOffset();
                }
            } catch (Exception e) { /* skip */ }
            imp.addProperty("address", addr);

            try {
                Object obj = sym.getObject();
                if (obj instanceof ExternalLocation) {
                    String lib = ((ExternalLocation) obj).getLibraryName();
                    if (lib != null) imp.addProperty("library", lib);
                }
            } catch (Exception e) { /* skip */ }

            arr.add(imp);
        }
        return arr;
    }

    private JsonArray exportExports(Program program) {
        JsonArray arr = new JsonArray();
        SymbolTable st = program.getSymbolTable();
        SymbolIterator it = st.getSymbolIterator(true);
        while (it.hasNext()) {
            Symbol sym = it.next();
            if (sym.isExternalEntryPoint()) {
                JsonObject exp = new JsonObject();
                exp.addProperty("name", sym.getName());
                exp.addProperty("address", sym.getAddress().getOffset());
                arr.add(exp);
            }
        }
        return arr;
    }

    private JsonArray exportStrings(Program program) {
        JsonArray arr = new JsonArray();
        Listing listing = program.getListing();
        DataIterator it = listing.getDefinedData(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Data data = it.next();
            DataType dt = data.getDataType();
            if (dt instanceof AbstractStringDataType) {
                try {
                    JsonObject s = new JsonObject();
                    s.addProperty("address", data.getAddress().getOffset());
                    s.addProperty("value", data.getDefaultValueRepresentation());
                    arr.add(s);
                } catch (Exception e) { /* skip */ }
            }
        }
        return arr;
    }

    private JsonArray exportBookmarks(Program program) {
        JsonArray arr = new JsonArray();
        BookmarkManager bm = program.getBookmarkManager();
        Iterator<Bookmark> it = bm.getBookmarksIterator();
        while (it.hasNext()) {
            if (monitor.isCancelled()) break;
            Bookmark b = it.next();
            JsonObject bk = new JsonObject();
            bk.addProperty("address", b.getAddress().getOffset());
            bk.addProperty("category", b.getCategory());
            bk.addProperty("comment", b.getComment());
            bk.addProperty("type", b.getTypeString());
            arr.add(bk);
        }
        return arr;
    }
}
'''
