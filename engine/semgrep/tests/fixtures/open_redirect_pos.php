<?php
function after_login_hop() {
    $next = $_GET['next'];
    header('Location: ' . $next);
    exit;
}
function host_echo_bounce() {
    header('Location: http://' . $_SERVER['HTTP_HOST'] . '/login.php');
}
function forwarded_host_bounce() {
    $base = $_SERVER['HTTP_X_FORWARDED_HOST'];
    header("Location: https://" . $base . "/index.php");
}
function self_step_redirect() {
    header('Location: ' . $_SERVER['PHP_SELF'] . '?step=2');
}
function interpolated_hop() {
    $target = $_REQUEST['target'];
    header("Location: $target");
}
function uri_echo_loop() {
    header('Location: ' . $_SERVER['REQUEST_URI']);
}
