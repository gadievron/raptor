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
function uppercase_name_hop() {
    header('LOCATION: ' . $_GET['next']);
}
function mixed_case_no_space_hop() {
    header('LoCaTiOn:' . $_GET['next']);
}
function sprintf_hop() {
    header(sprintf('Location: %s', $_GET['next']));
}
function variable_one_hop() {
    $loc = 'Location: ' . $_GET['next'];
    header($loc);
}
function referer_bounce() {
    header('Location: ' . $_SERVER['HTTP_REFERER']);
}
function qualified_hop() {
    \header('Location: ' . $_GET['next']);
}
