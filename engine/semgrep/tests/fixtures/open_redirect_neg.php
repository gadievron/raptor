<?php
function fixed_hop() {
    header('Location: /index.php');
}
function allowlist_hop() {
    $next = $_GET['next'];
    if (!in_array($next, ['/home.php', '/about.php'], true)) {
        $next = '/home.php';
    }
    header('Location: ' . $next);
}
function map_hop() {
    $pages = ['home' => '/home.php', 'about' => '/about.php'];
    $key = $_GET['page'];
    if (!array_key_exists($key, $pages)) {
        return;
    }
    header('Location: ' . $pages[$key]);
}
function encoded_param_hop() {
    header('Location: /view.php?item=' . rawurlencode($_GET['item']));
}
function other_header_out_of_scope() {
    header('X-Requested-Page: ' . $_GET['page']);
}
function request_host() {
    return $_SERVER['HTTP_HOST'];
}
function helper_indirection_launder() {
    // Documented FN: the host-header read lives in a helper — taint
    // is single-function, so the returned base URL is untainted at
    // the call site (semgrep intraprocedurality). Committed as the
    // executable record of the shape: CWE-601 carries a PRE-EXISTING
    // semgrep coverage row (core/audit/tool_coverage.py), so a
    // silent rule resolves the class clean — an accepted,
    // test-pinned consequence (test_tool_coverage.py names this
    // mode).
    header('Location: http://' . request_host() . '/home.php');
}
function refresh_header_out_of_scope() {
    // Documented FN by scope: the anchor is the Location: literal
    // only, so a Refresh-header redirect stays silent (stated
    // in-rule). Same accepted clean-when-silent consequence as the
    // helper shape above.
    header('Refresh: 0; url=' . $_GET['next']);
}
function meta_refresh_out_of_scope() {
    // Documented FN by scope: markup/script redirects are not
    // header() sinks (stated in-rule) — they belong to the
    // output-encoding families. Same accepted clean-when-silent
    // consequence as above.
    echo '<meta http-equiv="refresh" content="0; url=' . urlencode($_GET['next']) . '">';
}
