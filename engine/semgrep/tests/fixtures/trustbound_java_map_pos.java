import javax.servlet.http.HttpServletRequest;

public class trustbound_java_map_pos {
    public void store(HttpServletRequest request) {
        java.util.Map<String, String[]> map = request.getParameterMap();
        String param = "";
        if (!map.isEmpty()) {
            String[] values = map.get("p");
            if (values != null) param = values[0];
        }
        // must-fire: parameter-map data stored into the session
        request.getSession().setAttribute(param, "10340");
    }
}
