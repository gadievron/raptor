// Straight-line sanitize-then-sink — the genuinely-safe Java shape.
//
// Java-leg verdict: suppress.
//
// Encode.forHtml resolves to org.owasp.encoder.Encode.forHtml via the
// file's explicit import; the cleaned value y exclusively reaches the
// sink argument.
import org.owasp.encoder.Encode;

public class StraightLineSafe {
    public void handle(String x, java.io.PrintWriter out) {
        String y = Encode.forHtml(x);
        out.println(y);
    }
}
