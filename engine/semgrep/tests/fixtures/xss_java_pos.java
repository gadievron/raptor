import java.io.PrintWriter;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class xss_java_pos extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("input");
        PrintWriter out = response.getWriter();

        // unencoded request data straight into the response body
        out.println(param);
        response.getWriter().write("<div>" + request.getHeader("X-Name") + "</div>");

        // offset/length write variant — same unencoded body write
        String p2 = request.getParameter("p2");
        response.getWriter().write(p2, 0, p2.length());
    }

    public void enumHeaderToWriter(javax.servlet.http.HttpServletRequest request,
                                   javax.servlet.http.HttpServletResponse response)
            throws java.io.IOException {
        String param = "";
        java.util.Enumeration<String> headers = request.getHeaders("X-Custom");
        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement();
        }
        response.getWriter().println(param);
    }
}
