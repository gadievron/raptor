<?php
function load_fixed() {
    include 'modules/home.php';
}
function load_page_module_safe() {
    $page = basename($_GET['page']);
    include 'modules/' . $page . '.php';
}
function load_allowlisted() {
    $page = $_GET['page'];
    if (!in_array($page, ['home', 'about'], true)) {
        $page = 'home';
    }
    include 'modules/' . $page . '.php';
}
function load_mapped() {
    $pages = ['home' => 'modules/home.php', 'about' => 'modules/about.php'];
    $key = $_GET['page'];
    if (!array_key_exists($key, $pages)) {
        return;
    }
    include $pages[$key];
}
function load_switched() {
    switch ($_GET['view']) {
        case 'compact':
            include 'modules/compact.php';
            break;
        default:
            include 'modules/default.php';
    }
}
function read_param($key) {
    return $_GET[$key];
}
function helper_indirection_launder() {
    // Documented FN: the superglobal read lives in a helper — taint
    // is single-function, so the call-site value is untainted
    // (semgrep intraprocedurality). Committed as the executable
    // record of the shape: CWE-22 carries a PRE-EXISTING semgrep
    // coverage row (core/audit/tool_coverage.py), so a silent rule
    // resolves the class clean — an accepted, test-pinned
    // consequence (test_tool_coverage.py names this mode).
    include 'modules/' . read_param('page') . '.php';
}
function file_read_out_of_scope() {
    // Documented FN by scope: read/write file-op traversal
    // (fopen/file_get_contents/readfile) is the generic CWE-22
    // file-op shape, deliberately outside this rule's
    // include/require sink scope (stated in-rule). Same accepted
    // clean-when-silent consequence as above.
    $name = $_GET['attachment'];
    return file_get_contents('attachments/' . $name);
}
