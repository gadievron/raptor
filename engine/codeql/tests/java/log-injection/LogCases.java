package fixtures;
import javax.servlet.http.HttpServletRequest;
import java.util.logging.Level;
public class LogCases {
  public void unsafe_raw(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(value);
  }
  public void unsafe_noop(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(value.replace("\r", "\r").replace("\n", "\n"));
  }
  public void unsafe_reinject(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(value.replace("\n", "").replace("\r", "\n"));
  }
  public void unsafe_single(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(value.replace("\r", ""));
  }
  public void unsafe_pair(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(value.replace("\r\n", ""));
  }
  public void unsafe_regex_pair(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(value.replaceAll("\\r\\n", ""));
  }
  public void unsafe_regex_anchored(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(value.replaceAll("^[\\r\\n]", ""));
  }
  public void unsafe_regex_mentions(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(value.replaceAll("never\\r.*\\n", ""));
  }
  public void unsafe_regex_quoted(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(value.replaceAll("\\Q[\\r\\n]\\E", ""));
  }
  public void unsafe_backref(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(value.replaceAll("[\\r\\n]", "$0"));
  }
  public void unsafe_regex_reinject(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(value.replaceAll("[\\r\\n]", "\n"));
  }
  public void unsafe_regex_dynamic(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(value.replaceAll("[\\r\\n]", request.getParameter("replacement")));
  }
  public void unsafe_broken_chain(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(value.replace("\n", "").concat("\n").replace("\r", ""));
  }
  public void unsafe_recontaminate(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(value.replace("\n", "").replace("\r", "") + request.getParameter("suffix"));
  }
  public void unsafe_alias(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    String alias = value; String safe = value.replace("\n", "").replace("\r", ""); jul.info(alias);
  }
  public void unsafe_conditional(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    if (request.getParameter("clean") != null) { value = value.replace("\n", "").replace("\r", ""); } jul.info(value);
  }
  public void unsafe_fake_replace(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(new FakeString(value).replace("\n", "").replace("\r", "").toString());
  }
  public void unsafe_fake_encoder(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(Encode.forJava(value));
  }
  public void unsafe_jul_level(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.log(Level.WARNING, value);
  }
  public void unsafe_jul_argument(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.log(Level.INFO, "User: {0}", value);
  }
  public void unsafe_jul_array(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.log(Level.INFO, "User: {0}", new Object[]{value});
  }
  public void unsafe_slf4j_message(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    slf.info(value);
  }
  public void unsafe_slf4j_argument(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    slf.info("User: {}", value);
  }
  public void unsafe_slf4j_second_argument(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    slf.info("{} {}", "fixed", value);
  }
  public void unsafe_slf4j_varargs(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    slf.info("{} {} {}", "a", "b", value);
  }
  public void unsafe_slf4j_array(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    slf.info("{} {}", new Object[]{"fixed", value});
  }
  public void unsafe_slf4j_marker_message(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    slf.info(marker, value);
  }
  public void unsafe_slf4j_marker_argument(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    slf.info(marker, "User: {}", value);
  }
  public void unsafe_log4j_argument(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    log4j.info("User: {}", value);
  }
  public void unsafe_commons(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    commons.info(value);
  }
  public void safe_strings(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(value.replace("\r", "").replace("\n", ""));
  }
  public void safe_reverse(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(value.replace("\n", " ").replace("\r", "_"));
  }
  public void safe_chars(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(value.replace('\r', '_').replace('\n', '_'));
  }
  public void safe_normalize(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(value.replace("\r", "\n").replace("\n", ""));
  }
  public void safe_normalize_reverse(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(value.replace("\n", "\r").replace("\r", ""));
  }
  public void safe_regex(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(value.replaceAll("[\\r\\n]", ""));
  }
  public void safe_regex_reverse(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(value.replaceAll("[\\n\\r]", "_"));
  }
  public void safe_regex_alternation(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(value.replaceAll("\\n|\\r", ""));
  }
  public void safe_regex_raw(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(value.replaceAll("[\r\n]", ""));
  }
  public void safe_regex_plus(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(value.replaceAll("[\\r\\n]+", ""));
  }
  public void safe_constant(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    final String CR="\r", LF="\n", SPACE=" "; jul.info(value.replace(CR, SPACE).replace(LF, SPACE));
  }
  public void safe_slf4j_argument(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    slf.info("User: {}", value.replace("\r", "").replace("\n", ""));
  }
  public void safe_jul_argument(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.log(Level.INFO, "User: {0}", value.replace("\r", "").replace("\n", ""));
  }
  public void safe_literal(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info("fixed");
  }
  public void safe_slf4j_unused(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    slf.info("fixed", value);
  }
  public void safe_slf4j_unused_second(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    slf.info("{}", "fixed", value);
  }
  public void safe_slf4j_escaped(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    slf.info("\\{}", value);
  }
  public void safe_slf4j_unused_array(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    slf.info("{}", new Object[]{"fixed", value});
  }
  public void safe_slf4j_unused_varargs(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    slf.info("{}", "fixed", "fixed", value);
  }
  public void safe_jul_unused(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.log(Level.INFO, "fixed", value);
  }
  public void safe_numeric(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    slf.info("{}", Integer.parseInt(value));
  }
  public void unsafe_slf4j_doubleescaped(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    slf.info("\\\\{}", value);
  }
  public void unsafe_slf4j_after_escaped(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    slf.info("\\{} {}", value);
  }
  public void unsafe_character(HttpServletRequest request, java.util.logging.Logger jul, org.slf4j.Logger slf, org.slf4j.Marker marker, org.apache.logging.log4j.Logger log4j, org.apache.commons.logging.Log commons) {
    String value = request.getParameter("value");
    jul.info(String.valueOf(value.charAt(0)));
  }
  static class FakeString {
    String value; FakeString(String v) { value=v; }
    FakeString replace(String a, String b) { return this; }
    public String toString() { return value; }
  }
  static class Encode { static String forJava(String value) { return value; } }
}
