import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class xss_java_printf_pos {
    public void fmtTaint(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String bar = request.getParameter("p");
        Object[] obj = {"a", "b"};
        // must-fire: tainted format string, Locale-first printf spelling
        response.getWriter().printf(java.util.Locale.US, bar, obj);
    }

    public void arrayTaint(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String[] values = request.getParameterValues("p");
        String param = values[0];
        // taint rides the array-initializer element into the varargs
        Object[] obj = {"a", param};
        // must-fire: constant format, tainted varargs array
        response.getWriter().printf("Formatted like: %1$s and %2$s.", obj);
    }

    public void fqnWriter(HttpServletRequest request, HttpServletResponse response) throws Exception {
        java.util.Map<String, String[]> map = request.getParameterMap();
        String param = map.get("p")[0];
        java.io.PrintWriter out = response.getWriter();
        // must-fire: FQN-declared PrintWriter local, format spelling
        out.format(java.util.Locale.US, param, new Object[] {"x"});
    }
}
