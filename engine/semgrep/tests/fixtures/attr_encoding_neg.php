<?php
function render_link_safe() {
    echo "<a href='" . htmlspecialchars($_GET['url'], ENT_QUOTES) . "'>link</a>";
}
function render_body_text_context() {
    echo "<p>" . htmlspecialchars($_POST['body'], ENT_NOQUOTES) . "</p>";
}
function render_alt_quotes_html5() {
    echo '<img alt="' . htmlspecialchars($_GET['alt'], ENT_QUOTES | ENT_HTML5) . '">';
}
function render_compat_double_quote_ok() {
    echo '<img alt="' . htmlspecialchars($_GET['alt'], ENT_COMPAT) . '">';
}
function render_default_flags() {
    echo "<a href='" . htmlspecialchars($_GET['url']) . "'>link</a>";
}
