package fixtures;
import java.io.InputStream;
import javax.xml.parsers.*;
import javax.xml.XMLConstants;

public class XxeCases {
    static final String DOCTYPE = "http://apache.org/xml/features/disallow-doctype-decl";
    static final String GENERAL = "http://xml.org/sax/features/external-general-entities";
    static final String PARAMETER = "http://xml.org/sax/features/external-parameter-entities";
    static final String LOAD = "http://apache.org/xml/features/nonvalidating/load-external-dtd";
    static class OtherParser { void parse(InputStream input) { } }
    public void unsafe_raw(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.newDocumentBuilder().parse(input);
    }
    public void unsafe_chained_factory(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(input);
    }
    public void unsafe_reverted_load(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(GENERAL, false);
        factory.setFeature(PARAMETER, false);
        factory.setFeature(LOAD, false);
        factory.setFeature(LOAD, true);
        factory.newDocumentBuilder().parse(input);
    }
    public void unsafe_stored(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(input);
    }
    public void unsafe_late_doctype(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        factory.setFeature(DOCTYPE, true);
        builder.parse(input);
    }
    public void unsafe_late_attribute(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        builder.parse(input);
    }
    public void unsafe_late_features(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        factory.setFeature(GENERAL, false);
        factory.setFeature(PARAMETER, false);
        factory.setFeature(LOAD, false);
        builder.parse(input);
    }
    public void unsafe_conditional_doctype(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        if (flag) factory.setFeature(DOCTYPE, true);
        factory.newDocumentBuilder().parse(input);
    }
    public void unsafe_conditional_attribute(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        if (flag) factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.newDocumentBuilder().parse(input);
    }
    public void unsafe_conditional_load(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(GENERAL, false);
        factory.setFeature(PARAMETER, false);
        if (flag) factory.setFeature(LOAD, false);
        factory.newDocumentBuilder().parse(input);
    }
    public void unsafe_caught_failure(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        try { factory.setFeature(DOCTYPE, true); } catch (ParserConfigurationException ignored) { }
        factory.newDocumentBuilder().parse(input);
    }
    public void unsafe_general_only(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(GENERAL, false);
        factory.newDocumentBuilder().parse(input);
    }
    public void unsafe_both_entities(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(GENERAL, false);
        factory.setFeature(PARAMETER, false);
        factory.newDocumentBuilder().parse(input);
    }
    public void unsafe_reverted_doctype(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(DOCTYPE, true);
        factory.setFeature(DOCTYPE, false);
        factory.newDocumentBuilder().parse(input);
    }
    public void unsafe_reverted_attribute(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
        factory.newDocumentBuilder().parse(input);
    }
    public void unsafe_conditional_revert(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(DOCTYPE, true);
        if (flag) factory.setFeature(DOCTYPE, false);
        factory.newDocumentBuilder().parse(input);
    }
    public void unsafe_dynamic_value(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(DOCTYPE, true);
        factory.setFeature(DOCTYPE, flag);
        factory.newDocumentBuilder().parse(input);
    }
    public void unsafe_dynamic_property(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(DOCTYPE, true);
        factory.setFeature(property, false);
        factory.newDocumentBuilder().parse(input);
    }
    public void unsafe_other_factory(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilderFactory other = DocumentBuilderFactory.newInstance();
        other.setFeature(DOCTYPE, true);
        factory.newDocumentBuilder().parse(input);
    }
    public void unsafe_factory_reassigned(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(DOCTYPE, true);
        factory = DocumentBuilderFactory.newInstance();
        factory.newDocumentBuilder().parse(input);
    }
    public void unsafe_builder_alias(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        DocumentBuilder alias = builder;
        alias.parse(input);
    }
    public void unsafe_weaken_through_alias(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(DOCTYPE, true);
        DocumentBuilderFactory alias = factory;
        alias.setFeature(DOCTYPE, false);
        factory.newDocumentBuilder().parse(input);
    }
    public void unsafe_merged_alias(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(DOCTYPE, true);
        DocumentBuilderFactory alias = flag ? factory : DocumentBuilderFactory.newInstance();
        alias.setFeature(DOCTYPE, false);
        factory.newDocumentBuilder().parse(input);
    }
    public void unsafe_builder_reassigned(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(DOCTYPE, true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        DocumentBuilderFactory other = DocumentBuilderFactory.newInstance();
        builder = other.newDocumentBuilder();
        builder.parse(input);
    }
    public void safe_doctype(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(DOCTYPE, true);
        factory.newDocumentBuilder().parse(input);
    }
    public void safe_attribute(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.newDocumentBuilder().parse(input);
    }
    public void safe_attribute_literal(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setAttribute("http://javax.xml.XMLConstants/property/accessExternalDTD", "");
        factory.newDocumentBuilder().parse(input);
    }
    public void safe_three_features(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(GENERAL, false);
        factory.setFeature(PARAMETER, false);
        factory.setFeature(LOAD, false);
        factory.newDocumentBuilder().parse(input);
    }
    public void unsafe_validating(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(GENERAL, false);
        factory.setFeature(PARAMETER, false);
        factory.setFeature(LOAD, false);
        factory.setValidating(true);
        factory.newDocumentBuilder().parse(input);
    }
    public void unsafe_unknown_validation(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(GENERAL, false);
        factory.setFeature(PARAMETER, false);
        factory.setFeature(LOAD, false);
        factory.setValidating(flag);
        factory.newDocumentBuilder().parse(input);
    }
    public void safe_disabled_validation(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(GENERAL, false);
        factory.setFeature(PARAMETER, false);
        factory.setFeature(LOAD, false);
        factory.setValidating(true);
        factory.setValidating(false);
        factory.newDocumentBuilder().parse(input);
    }
    public void safe_validating_doctype(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setValidating(true);
        factory.setFeature(DOCTYPE, true);
        factory.newDocumentBuilder().parse(input);
    }
    public void safe_validating_attribute(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setValidating(true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.newDocumentBuilder().parse(input);
    }
    public void safe_factory_alias(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilderFactory alias = factory;
        alias.setFeature(DOCTYPE, true);
        factory.newDocumentBuilder().parse(input);
    }
    public void safe_builder_alias(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(DOCTYPE, true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        DocumentBuilder alias = builder;
        alias.parse(input);
    }
    public void safe_constants(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        final String key = DOCTYPE;
        final boolean enabled = true;
        factory.setFeature(key, enabled);
        factory.newDocumentBuilder().parse(input);
    }
    public void safe_guard_exit(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        if (!flag) return;
        factory.setFeature(DOCTYPE, true);
        factory.newDocumentBuilder().parse(input);
    }
    public void safe_catch_exit(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        try { factory.setFeature(DOCTYPE, true); } catch (ParserConfigurationException ignored) { return; }
        factory.newDocumentBuilder().parse(input);
    }
    public void safe_rehardened(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(DOCTYPE, false);
        factory.setFeature(DOCTYPE, true);
        factory.newDocumentBuilder().parse(input);
    }
    public void safe_weakened_after_creation(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(DOCTYPE, true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        factory.setFeature(DOCTYPE, false);
        builder.parse(input);
    }
    public void safe_unrelated_revert(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(DOCTYPE, true);
        DocumentBuilderFactory other = DocumentBuilderFactory.newInstance();
        other.setFeature(DOCTYPE, false);
        factory.newDocumentBuilder().parse(input);
    }
    public void safe_other_parse(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        OtherParser parser = new OtherParser();
        parser.parse(input);
    }
    public void safe_unused(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
    }
    public void safe_chained_factory(InputStream input, boolean flag, String property) throws Exception {
        DocumentBuilderFactory.newInstance().newDocumentBuilder();
    }
}
