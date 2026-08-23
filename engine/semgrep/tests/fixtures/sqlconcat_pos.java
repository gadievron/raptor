class SqlConcatPos {
    void assemble(java.sql.Statement st, String name) throws Exception {
        String q = "SELECT * FROM users WHERE name = '" + name + "'";
        st.executeQuery(q);
    }

    void inline(java.sql.Statement st, String id) throws Exception {
        st.executeQuery("select id from accounts where owner = " + id);
    }
}
