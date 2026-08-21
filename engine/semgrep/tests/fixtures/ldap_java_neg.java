import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServletRequest;
import org.owasp.esapi.ESAPI;

public class ldap_java_neg {
    public void searchEscaped(HttpServletRequest request, DirContext ctx) throws Exception {
        String param = ESAPI.encoder().encodeForLDAP(request.getParameter("uid"));
        String filter = "(&(objectclass=person)(uid=" + param + "))";
        SearchControls sc = new SearchControls();
        // silent: filter value LDAP-escaped
        ctx.search("ou=users,ou=system", filter, sc);
    }

    public void searchConstant(DirContext ctx) throws Exception {
        SearchControls sc = new SearchControls();
        // silent: constant filter, tainted base is not the filter arg
        ctx.search("ou=users,ou=system", "(objectclass=person)", sc);
    }
}
