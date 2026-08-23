import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;

public class xpath_java_neg {
    public void constantQuery(org.w3c.dom.Document doc) throws Exception {
        XPath xp = XPathFactory.newInstance().newXPath();
        // silent: constant expression
        xp.compile("/Employees/Employee[@emplid='E1']").evaluate(doc, javax.xml.xpath.XPathConstants.NODESET);
    }

    public void escapedQuery(HttpServletRequest request, org.w3c.dom.Document doc) throws Exception {
        String bar = org.owasp.esapi.ESAPI.encoder().encodeForXPath(request.getParameter("emplid"));
        XPath xp = XPathFactory.newInstance().newXPath();
        // silent: value XPath-escaped
        xp.compile("/Employees/Employee[@emplid='" + bar + "']").evaluate(doc, javax.xml.xpath.XPathConstants.NODESET);
    }
}
