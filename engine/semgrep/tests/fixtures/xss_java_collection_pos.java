import java.util.HashMap;
import java.util.ArrayList;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class xss_java_collection_pos {
    public void mapRoundTrip(HttpServletRequest request,
                             HttpServletResponse response)
            throws java.io.IOException {
        String param = request.getHeader("Referer");
        String bar = "safe!";
        HashMap<String, Object> map = new HashMap<String, Object>();
        map.put("keyA", "a-Value");
        map.put("keyB", param);
        bar = (String) map.get("keyB");
        // ruleid: raptor.injection.xss.taint.java
        response.getWriter().println(bar);
    }

    public void formatSink(HttpServletRequest request,
                           HttpServletResponse response)
            throws java.io.IOException {
        String param = request.getParameter("q");
        Object[] obj = {"a", "b"};
        // ruleid: raptor.injection.xss.taint.java
        response.getWriter().format(java.util.Locale.US, param, obj);
    }

    public void listRoundTrip(HttpServletRequest request,
                              HttpServletResponse response)
            throws java.io.IOException {
        String param = request.getParameter("q");
        ArrayList<String> list = new ArrayList<String>();
        list.add(param);
        String bar = list.get(0);
        // ruleid: raptor.injection.xss.taint.java
        response.getWriter().println(bar);
    }
}
