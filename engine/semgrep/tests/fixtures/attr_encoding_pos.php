<?php
function render_link() {
    echo "<a href='" . htmlspecialchars($_GET['url'], ENT_COMPAT) . "'>link</a>";
}
function render_title() {
    echo "<input value='" . htmlspecialchars($_POST['title'], ENT_NOQUOTES) . "'>";
}
function render_alt() {
    echo '<img alt="' . htmlspecialchars($_GET['alt'], ENT_NOQUOTES) . '">';
}
function render_alt_html5() {
    echo '<img alt="' . htmlspecialchars($_GET['alt'], ENT_NOQUOTES | ENT_HTML5) . '">';
}
