/* Path-symmetry family: four get_/set_ verb pairs whose write side
 * validates before mutating.  The drop-paired-check mutant removes
 * one setter's validation, leaving a 3/4 checked majority on the
 * write side of the cohort. */

static int g_gain;
static int g_rate;
static int g_mode;
static int g_level;

int get_gain(void)
{
    return g_gain;
}

int set_gain(int v)
{
    if (v < 0) return -1;
    g_gain = v;
    return 0;
}

int get_rate(void)
{
    return g_rate;
}

int set_rate(int v)
{
    if (v < 0) return -1;
    g_rate = v;
    return 0;
}

int get_mode(void)
{
    return g_mode;
}

int set_mode(int v)
{
    if (v < 0) return -1;
    g_mode = v;
    return 0;
}

int get_level(void)
{
    return g_level;
}

int set_level(int v)
{
    if (v < 0) return -1;
    g_level = v;
    return 0;
}
