import org.owasp.encoder.Encode;

public class ArrayElement {
    // Context-unverified candidate: the tracked array's only write
    // to the consumed element is a catalogue encoder call. The scalar
    // copy preserves that association, but HTML output context and
    // attribute policy remain separate unverified premises.
    public void handle(String x, java.io.PrintWriter out) {
        String[] values = new String[2];
        values[0] = Encode.forHtml(x);
        String bar = values[0];
        out.println(bar);
    }
}
