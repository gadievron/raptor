<?php
function make_reset_token() {
    $token = md5(uniqid(rand(), true));
    return $token;
}
function make_csrf() {
    $csrf_token = mt_rand();
    return $csrf_token;
}
function make_session() {
    $session_id = sha1(mt_rand() . microtime());
    return $session_id;
}
function make_api_key($user) {
    $user->api_key = str_shuffle("abcdefghijklmnop0123456789");
}
function make_otp() {
    $otp = rand(100000, 999999);
    return $otp;
}
function session_csrf() {
    $_SESSION['csrf_token'] = md5(mt_rand());
}
function one_time_pad() {
    $pad = str_shuffle("0123456789abcdef");
    return $pad;
}
function underscore_name() {
    $reset_token = uniqid();
    return $reset_token;
}
