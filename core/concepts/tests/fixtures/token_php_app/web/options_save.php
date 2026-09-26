<?php
// Skip-path entry: the check runs only on one branch — a token-SKIP
// path exists. The map reports the call (conditional), and no
// consumer may treat "enforced" as suppression-grade because of
// exactly this shape.
require_once __DIR__ . '/../lib/guard.php';

if (!isset($_GET['quick'])) {
    om_verify_request_stamp();
}

$opt = isset($_POST['opt']) ? $_POST['opt'] : '';
om_load_data($opt);

echo 'options saved';
