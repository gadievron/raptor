<?php
// Synthetic request-token guard library for the token-map fixture app.
// The idiom deliberately does NOT use the seed spellings alone: the
// enforcing function is om_verify_request_stamp (no "csrf" in the
// name) so tests can pin that identification is learned, not
// pattern-matched from the discovery seeds.

function om_issue_stamp() {
    // Decoy: token-shaped NAME (matches the *token*/*nonce* discovery
    // seed shape via om_token_value below) but only MINTS the value —
    // never enforces. A name-seed-driven map would wrongly credit it.
    $_SESSION['om_stamp'] = bin2hex(random_bytes(16));
    return $_SESSION['om_stamp'];
}

function om_token_value() {
    // Decoy #2: reads the stored value for form rendering.
    return isset($_SESSION['om_stamp']) ? $_SESSION['om_stamp'] : '';
}

function om_verify_request_stamp() {
    // THE enforcement idiom: compare and abort on mismatch.
    if (!isset($_POST['om_stamp']) || !isset($_SESSION['om_stamp'])) {
        http_response_code(403);
        die('bad request stamp');
    }
    if (!hash_equals($_SESSION['om_stamp'], $_POST['om_stamp'])) {
        http_response_code(403);
        die('bad request stamp');
    }
    return true;
}

function om_require_valid_request() {
    // Indirection layer: entries calling this are enforced one hop
    // away from the check itself.
    om_verify_request_stamp();
}

function om_load_data($key) {
    return 'data:' . $key;
}
