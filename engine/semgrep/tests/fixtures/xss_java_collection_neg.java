import java.util.HashMap;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class xss_java_collection_neg {
    public void overwrittenAfterGet(HttpServletRequest request,
                                    HttpServletResponse response)
            throws java.io.IOException {
        String param = request.getHeader("Referer");
        HashMap<String, Object> map = new HashMap<String, Object>();
        map.put("keyB", param);
        String bar = (String) map.get("keyB");
        bar = "constant-now";
        // ok: raptor.injection.xss.taint.java
        response.getWriter().println(bar);
    }

    public void constantsOnly(HttpServletRequest request,
                              HttpServletResponse response)
            throws java.io.IOException {
        HashMap<String, Object> map = new HashMap<String, Object>();
        map.put("keyA", "a-Value");
        String bar = (String) map.get("keyA");
        // ok: raptor.injection.xss.taint.java
        response.getWriter().println(bar);
    }

    public void encodedThroughMap(HttpServletRequest request,
                                  HttpServletResponse response)
            throws java.io.IOException {
        String param = request.getParameter("q");
        HashMap<String, Object> map = new HashMap<String, Object>();
        map.put("k", org.owasp.encoder.Encode.forHtml(param));
        String bar = (String) map.get("k");
        // ok: raptor.injection.xss.taint.java
        response.getWriter().println(bar);
    }
}
