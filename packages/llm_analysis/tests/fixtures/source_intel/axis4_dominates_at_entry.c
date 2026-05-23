/*
 * axis4_dominates_at_entry.c — unconditional capable(CAP_SYS_ADMIN)
 * at function entry. DOMINATES grade via _classify_call_site_grade
 * (depth 1, no preceding return). With DOMINATES + cap_line<sink_line,
 * the cap dominates regardless of distance — even 60+ lines away.
 */
#include <stddef.h>
extern int capable(int);
#define CAP_SYS_ADMIN 21
#define EPERM 1
void *memcpy(void *, const void *, unsigned long);

int op_dom_cap(const char *user, unsigned long len)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	int v0 = 0;
	int v1 = 0;
	int v2 = 0;
	int v3 = 0;
	int v4 = 0;
	int v5 = 0;
	int v6 = 0;
	int v7 = 0;
	int v8 = 0;
	int v9 = 0;
	int v10 = 0;
	int v11 = 0;
	int v12 = 0;
	int v13 = 0;
	int v14 = 0;
	int v15 = 0;
	int v16 = 0;
	int v17 = 0;
	int v18 = 0;
	int v19 = 0;
	int v20 = 0;
	int v21 = 0;
	int v22 = 0;
	int v23 = 0;
	int v24 = 0;
	int v25 = 0;
	int v26 = 0;
	int v27 = 0;
	int v28 = 0;
	int v29 = 0;
	int v30 = 0;
	int v31 = 0;
	int v32 = 0;
	int v33 = 0;
	int v34 = 0;
	int v35 = 0;
	int v36 = 0;
	int v37 = 0;
	int v38 = 0;
	int v39 = 0;
	int v40 = 0;
	int v41 = 0;
	int v42 = 0;
	int v43 = 0;
	int v44 = 0;
	int v45 = 0;
	int v46 = 0;
	int v47 = 0;
	int v48 = 0;
	int v49 = 0;
	int v50 = 0;
	int v51 = 0;
	int v52 = 0;
	int v53 = 0;
	int v54 = 0;
	int v55 = 0;
	int v56 = 0;
	int v57 = 0;
	int v58 = 0;
	int v59 = 0;

	char buf[64];
	memcpy(buf, user, len);  /* far from cap check — old gate would miss */
	return 0;
}
