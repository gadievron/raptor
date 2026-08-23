import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.owasp.encoder.Encode;

public class xss_java_printf_neg {
    public void encodedFmt(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String bar = Encode.forHtml(request.getParameter("p"));
        Object[] obj = {"a", "b"};
        // silent: format string HTML-encoded
        response.getWriter().printf(java.util.Locale.US, bar, obj);
    }

    public void constantAll(HttpServletRequest request, HttpServletResponse response) throws Exception {
        Object[] obj = {"a", "b"};
        // silent: nothing tainted anywhere
        response.getWriter().printf("Formatted like: %1$s and %2$s.", obj);
        java.io.PrintWriter out = response.getWriter();
        out.format(java.util.Locale.US, "const %s", obj);
    }

    public void encodedArray(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = Encode.forHtml(request.getParameter("p"));
        Object[] obj = {"a", param};
        // silent: element encoded before entering the array
        response.getWriter().printf("Formatted like: %1$s and %2$s.", obj);
    }
}
