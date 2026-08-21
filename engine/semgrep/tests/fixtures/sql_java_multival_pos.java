import java.sql.Connection;
import javax.servlet.http.HttpServletRequest;

public class sql_java_multival_pos {
    public void call(HttpServletRequest request, Connection connection) throws Exception {
        String[] values = request.getParameterValues("p");
        String param = values[0];
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("k", param);
        String bar = (String) map.get("k");
        String sql = "{call " + bar + "}";
        // must-fire: multi-value source reaches prepareCall
        java.sql.CallableStatement statement = connection.prepareCall(sql);
        statement.executeQuery();
    }

    public void mapSource(HttpServletRequest request, Connection connection) throws Exception {
        java.util.Map<String, String[]> map = request.getParameterMap();
        String param = map.get("p")[0];
        // must-fire: parameter-map source reaches Statement execution
        java.sql.Statement st = connection.createStatement();
        st.executeQuery("select * from t where c='" + param + "'");
    }
}
