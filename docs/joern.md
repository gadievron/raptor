# Joern analysis

RAPTOR uses Joern for code-property graphs, taint analysis and reachability
checks. Other analysis tools can continue when Joern is unavailable, but a
failed or unavailable Joern check does not establish that the target is safe.

## Requirements

Install Joern 4.0.458 or newer, including its parser, and the JDK required by
that Joern release. Make `joern` available on PATH.

Homebrew installations are supported on macOS. RAPTOR automatically selects
Joern's Homebrew JDK dependency when JAVA_HOME is unset; no system JDK
registration or sudo is needed. Set JAVA_HOME before starting RAPTOR if you
want to select another compatible JDK. An invalid explicit JAVA_HOME causes
an error.

Joern runs with operating-system protection enabled. Linux requires usable
Landlock ABI 4 or newer and libseccomp. macOS requires Seatbelt. RAPTOR refuses
to start a Joern worker if its required protection is unavailable. Workers can
write their own scratch files but cannot modify the RAPTOR installation or
make outbound network connections.

## Running analyses

RAPTOR starts Joern when an analysis needs it and stops it when it is no
longer in use. Compatible analyses of the same graph can share a Java process;
finishing one analysis does not stop a process another analysis is using.
Different graphs, different memory settings, or separate protected sessions
can require separate Java processes. On macOS, separate RAPTOR processes do
not share a Joern process.

RAPTOR checks its memory budget before starting another Joern process. If it
reports insufficient capacity, wait for other analyses to finish or reduce
concurrency. An explicitly requested heap size is not silently reduced.
Actual memory use can exceed the Java heap size.

Keep the target source unchanged during analysis. Changing languages,
compilation flags, analysis scope or the Joern installation can require a
fresh graph build. The first analysis after an upgrade may also rebuild its
cached graph.

Custom Scala queries must leave the graph unchanged. Do not rely on variables
defined by one query remaining available to later queries.

## Temporary storage

To choose where Joern puts temporary files, set RAPTOR_WORK_DIR to an existing,
private, writable directory before starting RAPTOR. If RAPTOR_WORK_DIR is unset,
Joern uses TMPDIR when supplied; otherwise it uses the system temporary
directory. On macOS, the default is the operating system's private user
temporary directory, not public `/tmp`.

Keep the selected directory available until all analyses have finished. This
also applies when invoking RAPTOR helpers directly or through another wrapper.
An unusable explicitly selected directory produces an error rather than
silently switching elsewhere. If macOS reports that a socket path is too long,
select a shorter private path using RAPTOR_WORK_DIR.

## Troubleshooting and updates

- **Joern or Java unavailable:** check that `joern` is on PATH, its parser is
  installed, and the selected JDK is compatible. Check JAVA_HOME if you set it.
- **Required protection unavailable:** enable the operating-system support
  listed above and install libseccomp on Linux. Joern will remain unavailable
  until its protection can engage.
- **Query interrupted or timed out:** rerun the affected analysis. Cancelling
  an active query may also interrupt other work sharing that Java process.
  Interrupted work is incomplete evidence.
- **Cleanup could not be verified:** RAPTOR reports and retains the affected
  files. Stop all RAPTOR and Joern processes before removing the reported
  scratch directory.
- **Damaged memory-accounting state:** stop all RAPTOR and Joern processes
  before resetting both `joern-heap-ledger.json` and its sibling directory
  `joern-heap-ledger.json.leases`. These are under `$XDG_DATA_HOME/raptor`, or
  `~/.local/share/raptor` when XDG_DATA_HOME is unset. Do not delete them while
  analyses are running.

Stop running RAPTOR analyses and Joern processes before updating RAPTOR or
Joern.
