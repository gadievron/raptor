<?php
function load_fixed() {
    include 'modules/home.php';
}
function load_page_module_safe() {
    $page = basename($_GET['page']);
    include 'modules/' . $page . '.php';
}
function load_page_module_safe_qualified() {
    $page = \basename($_GET['page']);
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
    // Out-of-scope shape pin: the superglobal read lives in a helper
    // and the taint engine is single-function, so the call-site
    // value is untainted. Flips when a matching shape lands.
    // Class-level silence adjudication is pinned in
    // test_tool_coverage.py (dark-preserved: CWE-22 carries
    // dark_verify, keeping the witness channel armed).
    include 'modules/' . read_param('page') . '.php';
}
function file_read_out_of_scope() {
    // Out-of-scope shape pin: read/write file-op traversal
    // (fopen/file_get_contents/readfile) is the generic CWE-22
    // file-op shape, outside this rule's include/require sink scope
    // (see rule scope). Same adjudication pin as above.
    $name = $_GET['attachment'];
    return file_get_contents('attachments/' . $name);
}
