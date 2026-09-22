<?php
function convert_image_safe() {
    $file = escapeshellarg($_GET['file']);
    exec("convert " . $file . " out.png");
}
function head_lines_safe() {
    $n = intval($_POST['n']);
    system("head -n " . $n . " /var/log/app.log");
}
function cast_pid_safe() {
    $pid = (int) $_GET['pid'];
    exec("kill -0 " . $pid);
}
function fixed_command() {
    exec("uptime");
}
function proc_open_argv_array() {
    // The rule's own recommended remediation: argv array, no shell —
    // must stay silent.
    $file = $_GET['file'];
    $spec = [0 => ["pipe", "r"], 1 => ["pipe", "w"]];
    return proc_open(["convert", $file, "out.png"], $spec, $pipes);
}
function helper_indirection() {
    // Documented FN: taint through a helper wrapping the superglobal
    // read is invisible to single-function taint — silent by design
    // (one of the narrow-shape gaps recorded on the pre-existing
    // CWE-88 coverage row in core/audit/tool_coverage.py).
    exec("tar czf /tmp/b.tgz " . fetch_param('dir'));
}
