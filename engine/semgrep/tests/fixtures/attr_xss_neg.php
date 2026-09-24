<?php
function render_color_badge_safe() {
    $color = htmlspecialchars($_POST['color'], ENT_QUOTES);
    echo "<font color='" . $color . "'>sample</font>";
}
function render_style_cell_safe() {
    $bg = htmlspecialchars($_GET['bg'], ENT_QUOTES);
    echo "<td style='background: " . $bg . ";'>cell</td>";
}
function render_width_safe() {
    echo "<img src='pic.png' width=" . intval($_GET['w']) . ">";
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
    // Documented FN: opener and value meet through a printf template,
    // not a concatenation — no literal is adjacent to the tainted
    // value, so the sink anchor cannot see it (the full-html-pipeline
    // residual: sprintf/heredoc/template functions are all this
    // shape). Committed as the executable record: CWE-79 carries a
    // PRE-EXISTING semgrep coverage row
    // (core/audit/tool_coverage.py), so a silent rule resolves the
    // class clean — an accepted, test-pinned consequence
    // (test_tool_coverage.py names this mode).
    printf("<font color='%s'>sample</font>", $_POST['color']);
}
function double_quoted_attr_out_of_scope() {
    // Documented FN by scope: double-quoted attributes are the
    // generic echo-XSS class, deliberately outside this narrow
    // quote-breakout subset (stated in-rule). Same accepted
    // clean-when-silent consequence as above.
    echo '<a href="' . $_GET['u'] . '">go</a>';
}
function legacy_flagless_launder() {
    // Documented FN: flagless htmlspecialchars clears taint, but
    // before PHP 8.1 the default flags leave single quotes unencoded
    // — on legacy runtimes this breakout survives encoding. Flagging
    // the flagless call would FP on every modern codebase (the
    // php/attr-encoding.yaml precedent).
    echo "<font color='" . htmlspecialchars($_POST['color']) . "'>x</font>";
}
