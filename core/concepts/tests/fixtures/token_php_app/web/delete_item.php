<?php
// Indirect entry: enforcement reaches the check through the
// om_require_valid_request wrapper (one call-graph hop).
require_once __DIR__ . '/../lib/guard.php';

om_require_valid_request();

$id = isset($_POST['id']) ? $_POST['id'] : '';
om_load_data($id);

echo 'deleted';
