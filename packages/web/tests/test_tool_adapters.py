from packages.web.tool_adapters import web_tool_adapter, web_tool_adapter_report


def test_adapter_catalogue_marks_selected_tools_and_risk():
    report = web_tool_adapter_report(["ffuf", "nuclei"])
    by_id = {item["id"]: item for item in report}

    assert by_id["raptor-web-oracle"]["role"] == "validator"
    assert by_id["ffuf"]["selected"] is True
    assert by_id["nuclei"]["risk"] == "active"
    assert by_id["sqlmap"]["risk"] == "intrusive"


def test_unknown_adapter_is_rejected():
    try:
        web_tool_adapter("made-up-tool")
    except KeyError as exc:
        assert "Unknown web tool adapter" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("unknown adapter should fail")

