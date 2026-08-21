import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class trustbound_java_neg extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(true);

        // constant writes cross no trust boundary
        session.setAttribute("role", "anonymous");
        session.putValue("theme", "dark");
        getServletContext().setAttribute("bootTime", Long.valueOf(0L));

        // internally derived value, not request data
        int visits = computeVisits();
        session.setAttribute("visits", Integer.valueOf(visits));
    }

    private int computeVisits() {
        return 1;
    }
}
