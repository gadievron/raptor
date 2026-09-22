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
