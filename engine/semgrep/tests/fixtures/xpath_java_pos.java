import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;

public class xpath_java_pos {
    public void query(HttpServletRequest request, org.w3c.dom.Document doc) throws Exception {
        String bar = request.getParameter("emplid");
        XPath xp = XPathFactory.newInstance().newXPath();
        String expression = "/Employees/Employee[@emplid='" + bar + "']";
        // must-fire: tainted expression compiled
        xp.compile(expression).evaluate(doc, javax.xml.xpath.XPathConstants.NODESET);
    }
}
