const serialize = require("node-serialize");

app.post("/load", (req, res) => {
  const obj = serialize.unserialize(req.body.data);
  res.json(obj);
});

const ns = require("node-serialize");
function fromCookie(raw) {
  return ns.unserialize(raw);
}
