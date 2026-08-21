import java.io.PrintWriter;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.owasp.encoder.Encode;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;

public class xss_java_encoder_neg extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("input");
        PrintWriter out = response.getWriter();

        // OWASP Java Encoder, short import
        out.println(Encode.forHtml(param));

        // OWASP Java Encoder, fully qualified inline
        out.println(org.owasp.encoder.Encode.forHtml(request.getHeader("X-Name")));

        // ESAPI chained singleton (the OWASP Benchmark idiom)
        out.println(ESAPI.encoder().encodeForHTML(param));

        // ESAPI through a typed Encoder reference
        Encoder enc = ESAPI.encoder();
        response.getWriter().write(enc.encodeForHTML(param));

        // ESAPI chained singleton, fully qualified inline (no import
        // to normalise against — a distinct spelling to the matcher)
        out.println(org.owasp.esapi.ESAPI.encoder().encodeForHTML(param));
    }
}
