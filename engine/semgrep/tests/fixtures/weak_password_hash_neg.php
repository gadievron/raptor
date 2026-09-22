<?php
function store_user_safe($db, $user) {
    $hash = password_hash($_POST['password'], PASSWORD_DEFAULT);
    $db->insert($user, $hash);
}
function etag_for($content) {
    return md5($content);
}
function cache_key_for($url) {
    $key = sha1($url . "v2");
    return $key;
}
function file_checksum($path) {
    return md5(file_get_contents($path));
}
function passthrough_digest($passthrough) {
    return md5($passthrough);
}
function strong_algo($password) {
    return hash("sha256", $password);
}
function neutral_name_launder() {
    // Documented FN: the password hops to a neutral name before the
    // digest — invisible to the name-anchored pattern, silent by
    // design (one of the narrow-shape gaps recorded on the
    // pre-existing CWE-327 coverage row in core/audit/tool_coverage.py).
    $p = $_POST['password'];
    return md5($p);
}
