package fixtures;

import java.sql.Connection;
import java.sql.PreparedStatement;
import javax.servlet.http.HttpServletRequest;

// Must-stay-silent cases: parameterised queries are the safe form —
// the SQL text is constant, taint flows only into bind arguments.
public class sqli_java_param_neg {

    public void parameterised(HttpServletRequest request,
                              Connection connection) throws Exception {
        String param = request.getParameter("id");
        PreparedStatement ps = connection.prepareStatement(
                "SELECT * from USERS where USERNAME=? and ROLE=?");
        ps.setString(1, param);
        ps.setString(2, "user");
        ps.executeQuery();
    }

    public void constantQueryUntypedReceiver() {
        String sql = "SELECT count(*) from USERS";
        Helpers.JDBC.queryForMap(sql);
    }

    public void constantConcat(Connection connection) throws Exception {
        String table = "USERS";
        String sql = "SELECT * from " + table;
        connection.prepareStatement(sql);
        // constant-derived concat: nothing tainted reaches the text
    }
}
