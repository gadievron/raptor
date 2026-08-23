// Must-stay-silent: constant arrays through the same sink spellings.
import javax.servlet.http.HttpServletRequest;

public class CmdiExecArrayNeg {
    public void one(HttpServletRequest request) throws Exception {
        String[] args = {"ls", "-la"};
        Runtime r = Runtime.getRuntime();
        r.exec(args);
    }

    public void two(HttpServletRequest request) throws Exception {
        String[] env = {"foo=bar", "baz=qux"};
        Runtime r = Runtime.getRuntime();
        r.exec("ls -la", env);
    }
}
