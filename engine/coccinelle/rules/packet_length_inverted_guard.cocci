// packet_length_inverted_guard.cocci — inverted packet-length rejection.
// Require a wire read from an skb, ntohl decoding, an skb-derived budget,
// rejection of lengths below that budget to a negative-return/abort label,
// and a known range consumer.
// Evidence is correlated within one function definition, in source order.
// Any other bound comparison, reassignment, address escape, or helper taking
// the decoded length before consumption refuses the candidate. This is a
// detection lead: budget/offset arithmetic and cross-function preconditions
// still need review. Deliberately misses helper-split decoders and aliases.
// rxgk_decrypt_skb's in/out length feeds skb_to_sgvec before decryption
// (net/rxrpc/rxgk_common.h); this is an explicit API contract model.
// Covers CWE-20 / CWE-125.
// @role: detection

@initialize:python@
@@
_packet_evidence = {}

def packet_record(kind, positions, **values):
    for pos in positions:
        key = (str(pos.file), str(pos.current_element), int(pos.current_element_line))
        record = {item: str(value) for item, value in values.items()}
        record.update(line=int(pos.line), col=int(pos.column))
        _packet_evidence.setdefault(key, {}).setdefault(kind, []).append(record)

@budget@
identifier skb, remaining;
expression initial;
type T;
position p;
@@
(
T remaining@p = skb->len - initial;
|
remaining@p = skb->len - initial;
)

@script:python@
p << budget.p;
skb << budget.skb;
remaining << budget.remaining;
@@
packet_record("budget", p, skb=skb, remaining=remaining)

@read@
identifier skb, wire;
expression offset;
position p;
@@
skb_copy_bits@p(skb, offset, &wire, sizeof(wire))

@script:python@
p << read.p;
skb << read.skb;
wire << read.wire;
@@
packet_record("read", p, skb=skb, wire=wire)

@decode@
identifier length, wire;
type T;
position p;
@@
(
length@p = ntohl(wire);
|
T length@p = ntohl(wire);
)

@script:python@
p << decode.p;
length << decode.length;
wire << decode.wire;
@@
packet_record("decode", p, length=length, wire=wire)

@reject@
identifier length, remaining, bad;
position p;
@@
if (length < remaining) goto bad@p;

@script:python@
p << reject.p;
length << reject.length;
remaining << reject.remaining;
bad << reject.bad;
@@
packet_record("reject", p, length=length, remaining=remaining, bad=bad)

@error_return@
identifier bad;
expression error;
position p;
@@
bad@p: return -error;

@script:python@
p << error_return.p;
bad << error_return.bad;
@@
packet_record("error", p, bad=bad)

@abort_label@
identifier bad, out;
expression ret;
position p;
@@
bad@p:
ret = rxrpc_abort_conn(...);
goto out;

@script:python@
p << abort_label.p;
bad << abort_label.bad;
@@
packet_record("error", p, bad=bad)

@bounds@
identifier reject.length;
expression limit;
position p;
@@
(
length@p > limit
|
length@p >= limit
|
length@p <= limit
|
length@p == limit
|
length@p != limit
)

@script:python@
p << bounds.p;
length << reject.length;
@@
packet_record("bounds", p, length=length)

@consume@
identifier skb, length;
expression offset, sg, a, b, ec;
position p;
@@
(
skb_to_sgvec@p(skb, sg, offset, length)
|
skb_to_sgvec_nomark@p(skb, sg, offset, length)
|
rxgk_decrypt_skb@p(a, b, skb, &offset, &length, &ec)
)

@script:python@
p << consume.p;
skb << consume.skb;
length << consume.length;
@@
packet_record("consume", p, skb=skb, length=length)

@write@
identifier item;
expression value;
position p;
@@
(
item@p = value
|
item@p += value
|
item@p -= value
|
item@p *= value
|
item@p /= value
|
item@p %= value
|
item@p &= value
|
item@p |= value
|
item@p ^= value
|
item@p <<= value
|
item@p >>= value
|
item@p++
|
item@p--
)

@script:python@
p << write.p;
item << write.item;
@@
packet_record("write", p, item=item)

@reset@
identifier item;
expression value;
position p;
@@
item@p = value

@script:python@
p << reset.p;
item << reset.item;
@@
packet_record("reset", p, item=item)

@escape@
identifier item, call;
position p;
@@
call(..., &item@p, ...)

@script:python@
p << escape.p;
item << escape.item;
call << escape.call;
@@
packet_record("escape", p, item=item, via=call)

@alias@
identifier item;
expression dest;
position p;
@@
dest = &item@p

@script:python@
p << alias.p;
item << alias.item;
@@
packet_record("escape", p, item=item, via="alias")

@helper@
identifier call, item;
position p;
@@
call@p(..., item, ...)

@script:python@
p << helper.p;
item << helper.item;
call << helper.call;
@@
packet_record("helper", p, item=item, call=call)

@finalize:python@
@@
import json, sys

def at(event):
    return event["line"], event["col"]

for (file, function, start), events in _packet_evidence.items():
    emitted = set()
    for guard in events.get("reject", []):
        length, remaining = guard["length"], guard["remaining"]
        if not any(e["bad"] == guard["bad"] for e in events.get("error", [])):
            continue
        for sink in events.get("consume", []):
            if sink["length"] != length or at(sink) <= at(guard):
                continue
            decodes = [d for d in events.get("decode", [])
                       if d["length"] == length and at(d) < at(guard)]
            if not decodes:
                continue
            decoded = max(decodes, key=at)
            reads = [r for r in events.get("read", [])
                     if r["skb"] == sink["skb"] and r["wire"] == decoded["wire"]
                     and at(r) < at(decoded)]
            budgets = [b for b in events.get("budget", [])
                       if b["skb"] == sink["skb"] and b["remaining"] == remaining
                       and at(b) < at(guard)]
            if not reads or not budgets:
                continue
            read = max(reads, key=at)
            if any(e["item"] == decoded["wire"] and e["via"] != "skb_copy_bits"
                   and at(e) < at(decoded) for e in events.get("escape", [])):
                continue
            budget = max(budgets, key=at)
            if any(w["item"] == decoded["wire"] and at(read) < at(w) < at(decoded)
                   for w in events.get("write", [])):
                continue
            if any(w["item"] == remaining and at(budget) < at(w) < at(sink)
                   for w in events.get("reset", [])):
                continue
            if any(w["item"] == sink["skb"] and min(at(read), at(budget)) < at(w) < at(sink)
                   for w in events.get("write", [])):
                continue
            # Refuse alternative validation, even if its path dominance cannot
            # be established. Precision takes precedence over this recall.
            if any(b["length"] == length
                   and at(decoded) < at(b) < at(sink) for b in events.get("bounds", [])):
                continue
            if any(w["item"] == length and at(decoded) < at(w) < at(sink)
                   for w in events.get("write", [])):
                continue
            if any(w["item"] in (length, remaining, sink["skb"])
                   and at(guard) < at(w) < at(sink) for w in events.get("write", [])):
                continue
            if any(e["item"] in (length, remaining, sink["skb"])
                   and at(e) < at(sink) for e in events.get("escape", [])):
                continue
            if any(h["item"] == length and at(decoded) < at(h) < at(sink)
                   for h in events.get("helper", [])):
                continue
            location = at(guard)
            if location in emitted:
                continue
            emitted.add(location)
            result = {"file": file, "line": guard["line"], "col": guard["col"],
                      "rule": "packet_length_inverted_guard",
                      "message": "Packet-derived length is rejected when smaller than the skb-derived budget, then reaches an skb range consumer. Review the upper-bound check and buffer window."}
            sys.stderr.write("COCCIRESULT:" + json.dumps(result) + "\n")
