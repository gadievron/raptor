const express = require("express");
const app = express();

app.get("/proxy", async (req, res) => {
  const u = new URL("http://upstream.invalid/lookup");
  u.searchParams.set("callback", req.query.target);
  u.href = req.query.target;
  const r = await fetch(u);
  res.send(await r.text());
});
