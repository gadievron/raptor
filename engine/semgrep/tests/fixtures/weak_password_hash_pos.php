<?php
function store_user($db, $user) {
    $password_hash = md5($_POST['password']);
    $db->insert($user, $password_hash);
}
function check_login($db, $user, $password) {
    $row = $db->find($user);
    return $row['pw'] === sha1($password);
}
function legacy_digest($passwd) {
    return hash("md5", $passwd, false);
}
function uppercase_algo($passwd) {
    return hash("MD5", $passwd);
}
function underscore_name($user_password) {
    return md5($user_password);
}
function store_row($row) {
    $row['password'] = sha1($row['input']);
    return $row;
}
