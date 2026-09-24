<?php
function load_prefs_safe() {
    $prefs = unserialize($_COOKIE['prefs'], ['allowed_classes' => false]);
    return $prefs;
}
function load_state_json() {
    $state = json_decode($_POST['state'], true);
    return $state;
}
function load_local_config($path) {
    $cfg = unserialize(file_get_contents($path));
    return $cfg;
}
function read_cookie($key) {
    return $_COOKIE[$key];
}
function helper_indirection_launder() {
    // Documented FN: the superglobal read lives in a helper — taint
    // is single-function, so the call-site value is untainted
    // (semgrep intraprocedurality). Committed as the executable
    // record of the shape: CWE-502 carries a PRE-EXISTING semgrep
    // coverage row (core/audit/tool_coverage.py), so a silent rule
    // resolves the class clean — an accepted, test-pinned
    // consequence (test_tool_coverage.py names this mode).
    $prefs = unserialize(read_cookie('prefs'));
    return $prefs;
}
function permissive_options_launder() {
    // Documented FN: the two-arg form is out of the one-arg sink
    // scope, so a PERMISSIVE options array stays silent — the rule
    // cannot value-analyse the array, and its own remediation is the
    // same call shape with 'allowed_classes' => false. Same accepted
    // clean-when-silent consequence as above.
    $obj = unserialize($_COOKIE['prefs'], ['allowed_classes' => true]);
    return $obj;
}
