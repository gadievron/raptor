import java.net.URL;

public class Fetcher {
    void fetchFixed() throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("http://internal.invalid");
        sb.append("/data");
        URL u = new URL(sb.toString());
        u.openConnection();
    }
}
