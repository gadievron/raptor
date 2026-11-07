"""Prove conservative bitwise result intervals in the promoted integer frame."""

from core.smt_solver import z3


def bitwise_domain(model, operator, kind, domains):
    """A mask may bound signed inputs without assuming they are nonnegative.

    Integer promotions and usual arithmetic conversions are resolved by the
    caller. Only bounds proved over the full independent operand domains are
    returned. Unknown/timeouts consume the shared prefix budget and decline.
    """
    minimum = -(1 << (kind.width - 1)) if kind.signed else 0
    maximum = (1 << (kind.width - (1 if kind.signed else 0))) - 1
    nonnegative = [high for low, high in domains if low >= 0]
    if operator == "&" and nonnegative:
        low, high = 0, min(nonnegative)
    elif len(nonnegative) == 2:
        low, high = 0, (1 << max(nonnegative).bit_length()) - 1
    else:
        # All bit patterns already fit the converted integer frame. No
        # tighter sign/range claim is needed to admit this defined operation.
        return minimum, maximum
    if low == minimum and high == maximum:
        return low, high
    a, b = (
        z3.FreshConst(z3.BitVecSort(kind.width), prefix="prefix_bits") for _ in range(2)
    )
    result = {"&": a & b, "|": a | b, "^": a ^ b}[operator]
    outside = (
        z3.Or(result < low, result > high)
        if kind.signed
        else z3.Or(z3.ULT(result, low), z3.UGT(result, high))
    )
    inputs = [(a, *domains[0], kind.signed), (b, *domains[1], kind.signed)]
    return (low, high) if model.proofs.impossible(outside, inputs) else None
