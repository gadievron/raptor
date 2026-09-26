<?php
// Post-output entry: the check is called only AFTER output has begun,
// so the pre-output prefix contains no enforcement — the projection
// must not credit it.
require_once __DIR__ . '/../lib/guard.php';

echo 'starting';

om_verify_request_stamp();
om_load_data('late');
