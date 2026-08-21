app.get("/status", async (req, res) => {
  const u = new URL("http://upstream.invalid/health");
  u.searchParams.set("format", "json");
  const r = await fetch(u);
  res.send(await r.text());
});
