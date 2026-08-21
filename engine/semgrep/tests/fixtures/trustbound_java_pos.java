import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class trustbound_java_pos extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String param = request.getParameter("input");

        // tainted value into the session via the chained form
        request.getSession().setAttribute("userValue", param);

        // tainted value through a typed session variable
        HttpSession session = request.getSession(true);
        session.setAttribute("stored", param);

        // tainted KEY is also a boundary violation
        session.setAttribute(param, "constant");

        // deprecated API spelling
        session.putValue("legacy", param);

        // chained legacy variant
        request.getSession().putValue(param, "flag");

        // application scope
        getServletContext().setAttribute("appWide", request.getHeader("X-Custom"));
    }

    public void paramNamesToSession(javax.servlet.http.HttpServletRequest request) {
        java.util.Enumeration<String> names = request.getParameterNames();
        String name = (String) names.nextElement();
        request.getSession().setAttribute("stored", name);
    }
}
