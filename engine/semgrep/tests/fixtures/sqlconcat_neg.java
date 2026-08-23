class SqlConcatNeg {
    void parameterised(java.sql.Connection c, String uid) throws Exception {
        java.sql.PreparedStatement ps =
            c.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, uid);
        ps.executeQuery();
    }

    String nonSql(String name) {
        return "hello " + name;
    }
}
