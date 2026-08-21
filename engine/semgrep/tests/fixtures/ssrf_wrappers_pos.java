import javax.servlet.http.HttpServletRequest;
import java.net.URL;

public class Fetcher {
    void fetchRemote(HttpServletRequest request) throws Exception {
        String host = request.getParameter("host");
        StringBuilder sb = new StringBuilder();
        sb.append("http://");
        sb.append(host);
        sb.append("/data");
        URL u = new URL(sb.toString());
        u.openConnection();
    }
}
