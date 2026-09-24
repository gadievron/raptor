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
function fixed_target_tainted_response_code() {
    // The sinks focus header()'s FIRST argument: taint arriving in a
    // later argument must never confirm a fixed-target redirect.
    header('Location: /done.php', true, $_GET['code']);
}
function other_header_out_of_scope() {
    header('X-Requested-Page: ' . $_GET['page']);
}
function request_host() {
    return $_SERVER['HTTP_HOST'];
}
function helper_indirection_launder() {
    // Out-of-scope shape pin: the host-header read lives in a helper
    // and the taint engine is single-function, so the returned base
    // URL is untainted at the call site. Flips when a matching shape
    // lands. Class-level silence adjudication is pinned in
    // test_tool_coverage.py (dark-preserved: CWE-601 carries
    // dark_verify, keeping the witness channel armed).
    header('Location: http://' . request_host() . '/home.php');
}
function split_name_literal_launder() {
    // Out-of-scope shape pin: the anchor takes the header name in
    // ONE literal — the split 'Loca' . 'tion: ' spelling is a
    // different shape. Flips when a matching shape lands. Same
    // adjudication pin as above.
    header('Loca' . 'tion: ' . $_GET['next']);
}
function multi_hop_variable_launder() {
    // Out-of-scope shape pin: the variable form is one-hop — the
    // multi-statement assembly is a different shape. Flips when a
    // matching shape lands. Same adjudication pin as above.
    $loc = 'Location: ';
    $loc = $loc . $_GET['next'];
    header($loc);
}
function refresh_header_out_of_scope() {
    // Out-of-scope shape pin: the sink anchor is the Location:
    // literal; Refresh-header redirects are a different response
    // shape (see rule scope). Same adjudication pin as above.
    header('Refresh: 0; url=' . $_GET['next']);
}
function meta_refresh_out_of_scope() {
    // Out-of-scope shape pin: markup/script redirects are not
    // header() sinks — they belong to the output-encoding families.
    // Same adjudication pin as above.
    echo '<meta http-equiv="refresh" content="0; url=' . urlencode($_GET['next']) . '">';
}
