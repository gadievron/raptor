import org.owasp.encoder.Encode;
import javax.servlet.http.HttpServletRequest;

// b27 honesty pin: transparency must never launder taint — the same
// conduit shape with the UNSANITIZED request value must not suppress.
// (The Encode import keeps the catalog non-empty so the finding
// reaches the value-bound gate rather than the catalog-empty return;
// the sanitizer is never called on the flowing value.)
public class ConduitTainted {
    public void handle(HttpServletRequest request,
                       java.io.PrintWriter out) {
        String x = request.getParameter("q");
        String unused = Encode.forHtml("static");
        String bar = new Pass().through(x);
        out.println(bar);
    }

    private class Pass {
        public String through(String p) {
            return p;
        }
    }
}
