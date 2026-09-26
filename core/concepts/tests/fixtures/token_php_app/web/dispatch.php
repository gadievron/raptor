<?php
// Dynamic-dispatch entry: the pre-output call target is computed at
// runtime — static projection must answer UNKNOWN, never enforced.
require_once __DIR__ . '/../lib/guard.php';

$handler = 'om_' . (isset($_GET['a']) ? $_GET['a'] : 'noop') . '_action';
$handler();

echo 'dispatched';
