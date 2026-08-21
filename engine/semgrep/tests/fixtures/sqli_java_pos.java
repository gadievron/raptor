package fixtures;

import java.sql.Connection;
import java.sql.CallableStatement;
import java.sql.Statement;
import java.util.Enumeration;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// Must-fire cases for raptor.injection.sql.taint.java.
public class sqli_java_pos {

    // Untyped distinctive Spring-JDBC name: receiver is a cross-file
    // static field whose type is not syntactically resolvable.
    public void untypedQueryForMap(HttpServletRequest request) {
        String param = request.getParameter("id");
        String sql = "SELECT * from USERS where USERNAME='" + param + "'";
        Helpers.JDBC.queryForMap(sql);
    }

    // Tainted SQL text prepared via prepareCall then executed.
    public void preparedCallTaint(HttpServletRequest request,
                                  Connection connection) throws Exception {
        String param = request.getParameter("id");
        String sql = "{call verifyUser('" + param + "')}";
        CallableStatement statement = connection.prepareCall(sql);
        statement.executeQuery();
    }

    // Header-enumeration source into a classic Statement sink.
    public void enumHeaderSource(HttpServletRequest request,
                                 Statement stmt) throws Exception {
        String param = "";
        Enumeration<String> headers = request.getHeaders("X-Custom");
        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement();
        }
        stmt.executeQuery("SELECT id from T where name='" + param + "'");
    }

    // Parameter-NAME enumeration is attacker-chosen request data.
    public void paramNamesSource(HttpServletRequest request,
                                 Statement stmt) throws Exception {
        Enumeration<String> names = request.getParameterNames();
        String name = (String) names.nextElement();
        stmt.execute("DELETE from T where col='" + name + "'");
    }
}
