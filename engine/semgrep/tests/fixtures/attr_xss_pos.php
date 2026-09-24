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
