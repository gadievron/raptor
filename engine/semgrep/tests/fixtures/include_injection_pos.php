<?php
function load_page_module() {
    $page = $_GET['page'];
    include 'modules/' . $page . '.php';
}
function load_theme_config() {
    include_once "themes/" . $_COOKIE['theme'] . "/config.php";
}
function load_plugin() {
    $plugin = $_REQUEST['plugin'];
    require "plugins/$plugin/setup.php";
}
function load_locale_strings() {
    $lang = $_POST['lang'];
    $path = 'locale/' . $lang . '/strings.php';
    require_once $path;
}
function stripping_still_fires() {
    // Deliberate positive: single-pass sequence stripping is
    // bypassable (....// survives one round), so the broken
    // remediation must keep firing (stated in-rule).
    $page = str_replace('..', '', $_GET['page']);
    include 'modules/' . $page . '.php';
}
