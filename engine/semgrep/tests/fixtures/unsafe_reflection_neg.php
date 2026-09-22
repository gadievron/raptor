<?php
function dispatch_action_safe() {
    $fn = $_GET['action'];
    if (!in_array($fn, ['list_items', 'show_item'], true)) {
        die("bad action");
    }
    $fn("payload");
}
function fixed_callback() {
    $handler = 'render_page';
    call_user_func($handler, $_GET['page']);
}
function fixed_class() {
    $obj = new Controller($_POST['arg']);
    return $obj->handle();
}
function map_lookup_safe() {
    $handlers = ['a' => 'handle_a', 'b' => 'handle_b'];
    $key = $_GET['k'];
    if (!array_key_exists($key, $handlers)) {
        return null;
    }
    $fn = $handlers[$key];
    $fn("payload");
}
function blocklist_polarity_launder() {
    // Documented FN: the rule cannot see branch polarity — this
    // membership check ABORTS ON MATCH (a blocklist), so passthru
    // and friends still get through, yet the in_array clears taint.
    // Kept executable because gate resolution keeps CWE-470
    // dark-when-silent (core/audit/tool_coverage.py), so the silence
    // cannot resolve the claim clean.
    $fn = $_GET['action'];
    if (in_array($fn, ['system', 'exec'], true)) {
        die("blocked");
    }
    $fn("payload");
}
