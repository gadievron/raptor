<?php
function render_color_badge() {
    $color = $_POST['color'];
    echo "<font color='" . $color . "'>sample</font>";
}
function render_style_cell() {
    $bg = $_GET['bg'];
    $row = "<td style='background: " . $bg . ";'>cell</td>";
    echo $row;
}
function render_width() {
    echo "<img src='pic.png' width=" . $_GET['w'] . ">";
}
function render_sort_link() {
    echo "<a class='sort' href='view.php?order=" . $_REQUEST['order'] . "'>sort</a>";
}
function render_prefixed_row($rowstart) {
    echo $rowstart . "<td style='background: " . $_GET['bg'] . ";'>cell</td>";
}
function render_interpolated_hop() {
    $c = $_POST['color'];
    echo "<font color='{$c}'>sample</font>";
}
function render_interpolated_direct() {
    echo "<font color='{$_POST['color']}'>sample</font>";
}
function render_interpolated_bare() {
    $c = $_POST['color'];
    echo "<font color='$c'>sample</font>";
}
function print_interpolated_cell() {
    print "<td class='{$_GET['cls']}'>cell</td>";
}
