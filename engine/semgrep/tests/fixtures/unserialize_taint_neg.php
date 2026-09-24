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
    // Out-of-scope shape pin: the superglobal read lives in a helper
    // and the taint engine is single-function, so the call-site
    // value is untainted. Flips when a matching shape lands.
    // Class-level silence adjudication is pinned in
    // test_tool_coverage.py (dark-preserved: CWE-502 carries
    // dark_verify, keeping the witness channel armed).
    $prefs = unserialize(read_cookie('prefs'));
    return $prefs;
}
function gadget_class_list_launder() {
    // Out-of-scope shape pin: options arrays participate only in the
    // literal 'allowed_classes' => true spelling (see rule scope).
    // Flips when a matching shape lands. Same adjudication pin as
    // above.
    return unserialize($_COOKIE['prefs'], ['allowed_classes' => [Extension_Loader::class]]);
}
