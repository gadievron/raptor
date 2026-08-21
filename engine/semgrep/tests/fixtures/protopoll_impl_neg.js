function safeMerge(target, source) {
  for (const key in source) {
    if (key === "__proto__" || key === "constructor") continue;
    if (typeof source[key] === "object" && source[key] !== null) {
      if (!target[key]) target[key] = {};
      safeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

app.post("/prefs", (req, res) => {
  const section = "display";
  settings[section]["theme"] = req.body.value;
  res.send("ok");
});
