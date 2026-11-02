package fixtures;
import java.io.*;
import javax.servlet.http.HttpServletRequest;

public class DeserCases {
    public void unsafe_raw(HttpServletRequest request) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(request.getInputStream());
        stream.readObject();
    }
    public void unsafe_chained(HttpServletRequest request) throws Exception {
        new ObjectInputStream(request.getInputStream()).readObject();
    }
    public void unsafe_late(HttpServletRequest request) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(request.getInputStream());
        stream.readObject();
        stream.setObjectInputFilter(ObjectInputFilter.Config.createFilter("java.lang.String;!*"));
    }
    public void unsafe_conditional(HttpServletRequest request, boolean filter) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(request.getInputStream());
        if (filter) stream.setObjectInputFilter(ObjectInputFilter.Config.createFilter("java.lang.String;!*"));
        stream.readObject();
    }
    public void unsafe_allow_all(HttpServletRequest request) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(request.getInputStream());
        stream.setObjectInputFilter(info -> ObjectInputFilter.Status.ALLOWED);
        stream.readObject();
    }
    public void unsafe_undecided(HttpServletRequest request) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(request.getInputStream());
        stream.setObjectInputFilter(info -> ObjectInputFilter.Status.UNDECIDED);
        stream.readObject();
    }
    public void unsafe_null_filter(HttpServletRequest request) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(request.getInputStream());
        stream.setObjectInputFilter(null);
        stream.readObject();
    }
    public void unsafe_allow_pattern(HttpServletRequest request) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(request.getInputStream());
        stream.setObjectInputFilter(ObjectInputFilter.Config.createFilter("*;!*"));
        stream.readObject();
    }
    public void unsafe_denylist(HttpServletRequest request) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(request.getInputStream());
        stream.setObjectInputFilter(ObjectInputFilter.Config.createFilter("!example.Bad"));
        stream.readObject();
    }
    public void unsafe_limit_only(HttpServletRequest request) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(request.getInputStream());
        stream.setObjectInputFilter(ObjectInputFilter.Config.createFilter("maxdepth=20"));
        stream.readObject();
    }
    public void unsafe_unknown(HttpServletRequest request, ObjectInputFilter policy) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(request.getInputStream());
        stream.setObjectInputFilter(policy);
        stream.readObject();
    }
    public void unsafe_other_stream(HttpServletRequest request) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(request.getInputStream());
        ObjectInputStream other = new ObjectInputStream(new ByteArrayInputStream(new byte[0]));
        other.setObjectInputFilter(ObjectInputFilter.Config.createFilter("java.lang.String;!*"));
        stream.readObject();
    }
    public void unsafe_reassigned(HttpServletRequest request) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(new ByteArrayInputStream(new byte[0]));
        stream.setObjectInputFilter(ObjectInputFilter.Config.createFilter("java.lang.String;!*"));
        stream = new ObjectInputStream(request.getInputStream());
        stream.readObject();
    }
    public void unsafe_merged_policy(HttpServletRequest request, boolean flag) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(request.getInputStream());
        ObjectInputFilter policy = ObjectInputFilter.Config.createFilter("java.lang.String;!*");
        if (flag) policy = info -> ObjectInputFilter.Status.ALLOWED;
        stream.setObjectInputFilter(policy);
        stream.readObject();
    }
    public void unsafe_caught_failure(HttpServletRequest request) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(request.getInputStream());
        try {
            stream.setObjectInputFilter(ObjectInputFilter.Config.createFilter("java.lang.String;!*"));
        } catch (SecurityException denied) { }
        stream.readObject();
    }
    public void unsafe_alias(HttpServletRequest request) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(request.getInputStream());
        ObjectInputStream alias = stream;
        alias.readUnshared();
    }
    public void safe_before(HttpServletRequest request) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(request.getInputStream());
        stream.setObjectInputFilter(ObjectInputFilter.Config.createFilter("java.lang.String;!*"));
        stream.readObject();
    }
    public void safe_alias(HttpServletRequest request) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(request.getInputStream());
        ObjectInputStream alias = stream;
        alias.setObjectInputFilter(ObjectInputFilter.Config.createFilter("java.lang.String;!*"));
        stream.readUnshared();
    }
    public void safe_policy_local(HttpServletRequest request) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(request.getInputStream());
        final String pattern = "java.lang.String;java.lang.Integer;!*";
        ObjectInputFilter policy = ObjectInputFilter.Config.createFilter(pattern);
        stream.setObjectInputFilter(policy);
        stream.readObject();
    }
    public void safe_reject_all(HttpServletRequest request) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(request.getInputStream());
        stream.setObjectInputFilter(ObjectInputFilter.Config.createFilter("!*"));
        stream.readObject();
    }
    public void safe_branch_exits(HttpServletRequest request, boolean filter) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(request.getInputStream());
        if (!filter) return;
        stream.setObjectInputFilter(ObjectInputFilter.Config.createFilter("java.lang.String;!*"));
        stream.readObject();
    }
    public void safe_local(HttpServletRequest request) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(new ByteArrayInputStream(new byte[0]));
        stream.readObject();
    }
    public void safe_no_read(HttpServletRequest request) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(request.getInputStream());
    }
}
