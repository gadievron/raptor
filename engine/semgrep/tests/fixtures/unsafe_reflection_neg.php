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
