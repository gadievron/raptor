class SqlConcatWsPos {
    void leadingSpace(java.sql.Statement st, String name) throws Exception {
        String q = " SELECT * FROM users WHERE name = '" + name + "'";
        st.executeQuery(q);
    }

    void leadingNewline(java.sql.Statement st, String id) throws Exception {
        String q = "\n  select id from accounts where owner = " + id;
        st.executeQuery(q);
    }
}
