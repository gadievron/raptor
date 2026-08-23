import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServletRequest;

public class ldap_java_pos {
    public void search(HttpServletRequest request, DirContext ctx) throws Exception {
        String[] values = request.getParameterValues("uid");
        String param = values[0];
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("k", param);
        String bar = (String) map.get("k");
        String filter = "(&(objectclass=person)(uid=" + bar + "))";
        SearchControls sc = new SearchControls();
        // must-fire: tainted filter into DirContext.search
        ctx.search("ou=users,ou=system", filter, sc);
    }
}
