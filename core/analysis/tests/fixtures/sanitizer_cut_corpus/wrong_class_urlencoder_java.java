// Wrong-class sanitizer — URLEncoder is a URL/form encoder, not an
// HTML sanitizer; it is deliberately absent from the xss catalog
// (class assignment must be semantically honest).
//
// Java-leg verdict: no_suppress.
import java.net.URLEncoder;

public class WrongClassUrlEncoder {
    public void handle(String x, java.io.PrintWriter out) throws Exception {
        String y = URLEncoder.encode(x, "UTF-8");
        out.println(y);
    }
}
