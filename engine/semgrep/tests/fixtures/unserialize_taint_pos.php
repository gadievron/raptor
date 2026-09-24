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
