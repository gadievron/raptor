<?php
function convert_image_safe() {
    $file = escapeshellarg($_GET['file']);
    exec("convert " . $file . " out.png");
}
function head_lines_safe() {
    $n = intval($_POST['n']);
    system("head -n " . $n . " /var/log/app.log");
}
function cast_pid_safe() {
    $pid = (int) $_GET['pid'];
    exec("kill -0 " . $pid);
}
function fixed_command() {
    exec("uptime");
}
