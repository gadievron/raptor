import org.owasp.encoder.Encode;

public class WrapperHelper {
    // Expected verdict: suppress WITH the b19 wrapper-summary
    // synthetic binding (the private static helper's return is
    // provably the catalog sanitizer applied to its argument);
    // candidate_only/no_suppress without it.
    private static String doSomething(String param) {
        return Encode.forHtml(param);
    }

    public void handle(String x, java.io.PrintWriter out) {
        String bar = doSomething(x);
        out.println(bar);
    }
}
