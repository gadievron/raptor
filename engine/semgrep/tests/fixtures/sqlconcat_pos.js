function assemble(db, name) {
  const q = "SELECT * FROM users WHERE name = '" + name + "'";
  db.query("INSERT INTO audit VALUES (" + name + ")");
  return q;
}
