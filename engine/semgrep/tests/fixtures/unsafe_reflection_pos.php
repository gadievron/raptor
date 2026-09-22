<?php
function dispatch_action() {
    $fn = $_GET['action'];
    $fn("payload");
}
function cb_dispatch() {
    $handler = $_POST['handler'];
    call_user_func($handler, "arg");
}
function cb_array_dispatch() {
    $handler = $_POST['handler'];
    call_user_func_array($handler, ["arg"]);
}
function make_object() {
    $cls = $_REQUEST['type'];
    $obj = new $cls("ctor");
    return $obj;
}
function method_dispatch($svc) {
    $m = $_GET['op'];
    return $svc->$m();
}
