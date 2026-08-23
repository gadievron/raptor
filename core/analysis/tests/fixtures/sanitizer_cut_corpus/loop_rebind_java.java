// Loop rebind — the b11 exclusivity shape in Java: the sanitized
// value is rebound to unsanitized loop items on some iterations;
// both definitions reach the sink.
//
// Java-leg verdict: candidate_only (never suppress).
import org.owasp.encoder.Encode;

public class LoopRebind {
    public void handle(String x, String[] items, java.io.PrintWriter out) {
        String y = Encode.forHtml(x);
        for (String i : items) {
            y = i;
        }
        out.println(y);
    }
}
