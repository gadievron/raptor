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
function anchor_substring_lookalikes() {
    // Letter-run continuations of the anchors are not the anchors:
    // "reset" inside preset, "pad" inside notepad/keypad.
    $preset = array_rand(['a' => 1, 'b' => 2]);
    $notepad = str_shuffle("abc");
    $keypad_layout = str_shuffle("123456789");
    return [$preset, $notepad, $keypad_layout];
}
function property_pad_excluded($frame) {
    // 'pad' is a variable-rule anchor only; the property rule
    // excludes it on purpose (padding fields on wire structs), and
    // the variable rule's full anchor must not reach through the
    // property lvalue.
    $frame->pad = mt_rand(1, 8);
    return $frame;
}
function intermediate_hop() {
    // Documented FN: the PRNG value hops through a neutral name
    // before the anchored store — invisible to the assignment-shaped
    // pattern, silent by design (the class stays dark in gate
    // resolution, so silence never resolves it clean).
    $r = mt_rand();
    $csrf_token = $r;
    return $csrf_token;
}
