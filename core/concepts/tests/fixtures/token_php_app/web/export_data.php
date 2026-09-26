<?php
// Unenforced entry: state-changing action, no token check anywhere.
require_once __DIR__ . '/../lib/guard.php';

$what = isset($_GET['what']) ? $_GET['what'] : 'all';
om_load_data($what);

echo 'exported';
