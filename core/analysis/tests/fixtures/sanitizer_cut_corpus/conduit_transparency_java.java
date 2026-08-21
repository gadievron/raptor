import org.owasp.encoder.Encode;
import javax.servlet.http.HttpServletRequest;

// b27 regression pin: a conduit helper (provably returns its
// parameter unchanged) is value-transparent — the sanitized value's
// identity survives the hop, and the gate's vertex-cut argument
// carries through the conduit call site.
public class ConduitTransparency {
    public void handle(HttpServletRequest request,
                       java.io.PrintWriter out) {
        String x = request.getParameter("q");
        String clean = Encode.forHtml(x);
        String bar = new Pass().through(clean);
        out.println(bar);
    }

    private class Pass {
        public String through(String p) {
            return p;
        }
    }
}
