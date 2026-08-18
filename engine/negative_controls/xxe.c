/* Negative control: "xxe" keyword family (C).
 *
 * libxml2 parse with network access disabled and entity substitution
 * left at its safe default (no opt-in flag, no global substitution
 * toggle). The unsafe-shape pattern must not match.
 */
#include <libxml/parser.h>

xmlDocPtr parse_manifest(const char *path)
{
    /* NONET blocks external fetches; entity substitution stays off
     * because the opt-in parse flag is deliberately absent. */
    return xmlReadFile(path, NULL, XML_PARSE_NONET);
}
