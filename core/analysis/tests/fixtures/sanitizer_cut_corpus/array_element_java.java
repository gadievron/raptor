import org.owasp.encoder.Encode;

public class ArrayElement {
    // Expected verdict: suppress (b19 element-exclusive sanitizer
    // definitions — the tracked local array's only write to the
    // consumed element is a catalog sanitizer call; the one-scalar-hop
    // copy is exact because Java locals are unaliasable).
    public void handle(String x, java.io.PrintWriter out) {
        String[] values = new String[2];
        values[0] = Encode.forHtml(x);
        String bar = values[0];
        out.println(bar);
    }
}
