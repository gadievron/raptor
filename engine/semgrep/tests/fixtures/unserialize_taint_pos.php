<?php
function load_prefs() {
    $prefs = unserialize($_COOKIE['prefs']);
    return $prefs;
}
function load_state() {
    $raw = $_POST['state'];
    $state = unserialize($raw);
    return $state;
}
function load_nested_field() {
    $obj = unserialize($_REQUEST['form']['payload']);
    return $obj;
}
function load_encoded() {
    $obj = unserialize(base64_decode($_GET['blob']));
    return $obj;
}
function load_qualified() {
    return \unserialize($_COOKIE['prefs']);
}
function load_suppressed() {
    return @unserialize($_COOKIE['prefs']);
}
function load_permissive_options() {
    return unserialize($_COOKIE['prefs'], ['allowed_classes' => true]);
}
function load_permissive_extra_keys() {
    return unserialize($_COOKIE['prefs'], ['allowed_classes' => true, 'max_depth' => 128]);
}
function load_permissive_legacy_array() {
    return unserialize($_COOKIE['prefs'], array('allowed_classes' => true));
}
