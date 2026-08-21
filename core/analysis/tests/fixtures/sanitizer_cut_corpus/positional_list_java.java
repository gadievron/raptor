// Positional list simulation — the OWASP safe/vulnerable twin pair:
// remove(0) shifts the list, so get(1) reads the trailing safe
// constant while get(0) would read the tainted element. The b34
// simulation proves the safe read; the tainted twin lives in the
// precision corpus (pos_remove_shift_tainted_read).
//
// Java-leg verdict: suppress (constant sink argument via positional
// resolution).
import java.util.ArrayList;

public class PositionalList {
    public void handle(String x, java.io.PrintWriter out) {
        ArrayList<String> l = new ArrayList<String>();
        l.add("safe");
        l.add(x);
        l.add("moresafe");
        l.remove(0);
        String bar = l.get(1);
        out.println(bar);
    }
}
