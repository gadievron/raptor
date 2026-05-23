/*
 * axis1_adversarial_planted_wur_noop.c — adversarial fixture per
 * design exit criterion.
 *
 * An attacker plants __attribute__((warn_unused_result)) on a
 * no-op function. Source_intel axis-1 trusts the annotation
 * literally and fires EXPLOITABLE on unchecked-return findings.
 * Ground truth: function is a no-op so the unchecked return is
 * harmless (FP). The disagreement documents the
 * adversarial-tolerance gap.
 *
 * Mitigation (future): source_intel could require additional
 * evidence (function size, body complexity, recent annotation
 * history) before trusting WUR for verdict. Not implemented in
 * Phase 1.5 — the gap is documented as known limitation.
 */
/* Forward declaration with attribute — cocci attrs rule matches
 * the declaration form. Real-world code style. */
__attribute__((warn_unused_result))
int noop_wur(void);

int noop_wur(void)  /* attacker planted WUR; body is a no-op */
{
	return 0;
}

int caller(void)
{
	noop_wur();  /* unchecked — but the function is a no-op */
	return 0;
}
