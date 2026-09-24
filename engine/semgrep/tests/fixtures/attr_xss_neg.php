<?php
function render_color_badge_safe() {
    $color = htmlspecialchars($_POST['color'], ENT_QUOTES);
    echo "<font color='" . $color . "'>sample</font>";
}
function render_color_badge_safe_qualified() {
    $color = \htmlspecialchars($_POST['color'], ENT_QUOTES);
    echo "<font color='" . $color . "'>sample</font>";
}
function render_style_cell_safe() {
    $bg = htmlspecialchars($_GET['bg'], ENT_QUOTES);
    echo "<td style='background: " . $bg . ";'>cell</td>";
}
function render_width_safe() {
    echo "<img src='pic.png' width=" . intval($_GET['w']) . ">";
}
function render_interpolated_safe() {
    $c = htmlspecialchars($_POST['color'], ENT_QUOTES);
    echo "<font color='{$c}'>sample</font>";
}
function render_fixed_theme() {
    $theme = 'navy';
    echo "<font color='" . $theme . "'>sample</font>";
}
function build_config_line() {
    $v = $_GET['v'];
    $line = "option=" . $v;
    return $line;
}
function template_pipeline_launder() {
    // Out-of-scope shape pin: opener and value meet through a printf
    // template, so no literal is adjacent to the tainted value —
    // outside the concatenation/interpolation sink shapes. Flips
    // when a matching shape lands. Class-level silence adjudication
    // is pinned in test_tool_coverage.py (armed-clean: CWE-79
    // carries no dark_verify key).
    printf("<font color='%s'>sample</font>", $_POST['color']);
}
function multi_argument_echo_launder() {
    // Out-of-scope shape pin: the interpolation sink matches
    // echo/print of ONE string expression — the comma form is a
    // different statement shape. Flips when a matching shape lands.
    // Same adjudication pin as above.
    echo "<font color='", $_POST['color'], "'>sample</font>";
}
function unquoted_interpolation_launder() {
    // Out-of-scope shape pin: interpolation is matched in the
    // single-quoted opener position only. Flips when a matching
    // shape lands. Same adjudication pin as above.
    echo "<img src='pic.png' width=$_GET[w]>";
}
function double_quoted_attr_out_of_scope() {
    // Out-of-scope shape pin: double-quoted attributes belong to the
    // generic echo-XSS class, which this quote-breakout subset does
    // not claim (see rule scope). Same adjudication pin as above.
    echo '<a href="' . $_GET['u'] . '">go</a>';
}
function single_quote_delimited_launder() {
    // Out-of-scope shape pin: the opener is a single-quote-delimited
    // PHP literal with an escaped quote — outside the
    // double-quote-delimited anchor classes (the
    // php/attr-encoding.yaml delimiter restriction). Flips when a
    // matching shape lands. Same adjudication pin as above.
    echo '<font color=\'' . $_POST['color'] . '\'>x</font>';
}
function legacy_flagless_launder() {
    // Sanitizer-decision pin: flagless htmlspecialchars clears taint
    // — since PHP 8.1 the default flags include ENT_QUOTES, and
    // flagging the flagless call would FP on every modern codebase
    // (the php/attr-encoding.yaml precedent).
    echo "<font color='" . htmlspecialchars($_POST['color']) . "'>x</font>";
}
