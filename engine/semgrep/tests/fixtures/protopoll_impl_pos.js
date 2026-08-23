function deepMerge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object" && source[key] !== null) {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

app.post("/prefs", (req, res) => {
  const path1 = req.query.section;
  const path2 = req.query.name;
  settings[path1][path2] = req.body.value;
  res.send("ok");
});
