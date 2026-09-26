<?php
// Enforced entry: direct call to the check function before any output.
require_once __DIR__ . '/../lib/guard.php';

om_verify_request_stamp();

$pref = isset($_POST['pref']) ? $_POST['pref'] : '';
om_load_data($pref);

echo 'saved';
