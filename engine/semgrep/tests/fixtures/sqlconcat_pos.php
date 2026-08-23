<?php
function assemble($db, $name, $id) {
    $q = "SELECT * FROM users WHERE name = '" . $name . "'";
    $q2 = "DELETE FROM t WHERE id = " . $id . " AND owner = " . $name;
    return $q . $q2;
}
?>
