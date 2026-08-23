// Must-fire: the measured OWASP miss shapes — variable-receiver exec,
// tainted env array, and tainted array initializers.
import javax.servlet.http.HttpServletRequest;

public class CmdiExecArrayPos {
    public void one(HttpServletRequest request) throws Exception {
        // shape 1: tainted env array via variable receiver (00173)
        String bar = request.getHeader("h");
        String[] argsEnv = {bar};
        Runtime r = Runtime.getRuntime();
        r.exec("ls", argsEnv); // ruleid: raptor.injection.command.taint.java
    }

    public void two(HttpServletRequest request) throws Exception {
        // shape 2: tainted array initializer to the command arg (00407)
        String bar = request.getParameter("p");
        String[] args = {"sh", "-c", "ls " + bar};
        Runtime r = Runtime.getRuntime();
        r.exec(args); // ruleid: raptor.injection.command.taint.java
    }

    public void three(HttpServletRequest request) throws Exception {
        // shape 3: new String[] form with constant env (00407 unix branch)
        String bar = request.getParameter("p");
        String[] args = new String[] {"sh", "-c", "ls " + bar};
        String[] env = {"foo=bar"};
        Runtime r = Runtime.getRuntime();
        r.exec(args, env); // ruleid: raptor.injection.command.taint.java
    }
}
