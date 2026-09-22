<?php
function smtp_rcpt($host) {
    $rcpt = $_GET['rcpt'];
    $sock = fsockopen($host, 25);
    fwrite($sock, "RCPT TO:<" . $rcpt . ">\r\n");
    fclose($sock);
}
function nntp_group() {
    $group = $_POST['group'];
    $conn = stream_socket_client("tcp://news.example:119");
    $cmd = "GROUP " . $group . "\r\n";
    fputs($conn, $cmd);
}
function raw_socket_user() {
    $sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    socket_write($sock, "USER " . $_COOKIE['u'] . "\r\n");
}
