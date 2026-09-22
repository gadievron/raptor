<?php
function smtp_rcpt_safe($host) {
    $rcpt = str_replace(["\r", "\n"], '', $_GET['rcpt']);
    $sock = fsockopen($host, 25);
    fwrite($sock, "RCPT TO:<" . $rcpt . ">\r\n");
    fclose($sock);
}
function nntp_group_safe() {
    $group = preg_replace('/[\r\n]+/', '', $_POST['group']);
    $conn = stream_socket_client("tcp://news.example:119");
    fputs($conn, "GROUP " . $group . "\r\n");
}
function ftp_port_safe() {
    $port = intval($_GET['port']);
    $sock = fsockopen("ftp.example", 21);
    fwrite($sock, "PORT 10,0,0,1,0," . $port . "\r\n");
}
function log_note_not_a_socket() {
    $note = $_GET['note'];
    $fp = fopen("/var/log/app.log", "a");
    fwrite($fp, $note . "\n");
}
function fixed_command($host) {
    $sock = fsockopen($host, 25);
    fwrite($sock, "QUIT\r\n");
}
