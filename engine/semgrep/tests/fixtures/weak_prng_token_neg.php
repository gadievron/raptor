<?php
function make_reset_token_safe() {
    $token = bin2hex(random_bytes(32));
    return $token;
}
function make_otp_safe() {
    $otp = random_int(100000, 999999);
    return $otp;
}
function jitter_backoff($attempt) {
    $delay = mt_rand(0, 1000) + $attempt * 100;
    usleep($delay);
    return $delay;
}
function sample_bucket() {
    $bucket = rand(0, 9);
    return $bucket;
}
function pick_banner($banners) {
    $idx = array_rand($banners);
    return $banners[$idx];
}
