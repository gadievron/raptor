<?php
function convert_image() {
    $file = $_GET['file'];
    exec("convert " . $file . " out.png");
}
function grep_logs() {
    $pattern = escapeshellcmd($_POST['q']);
    system("grep " . $pattern . " /var/log/app.log");
}
function tail_unit() {
    $unit = $_REQUEST['unit'];
    $fh = popen("journalctl -u " . $unit, "r");
    return $fh;
}
function backup_dir() {
    $dir = $_GET['dir'];
    return shell_exec("tar czf /tmp/backup.tgz " . $dir);
}
