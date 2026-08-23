/* Negative control: "ssrf" keyword family (C).
 *
 * libcurl fetch with a compile-time constant URL — no user data
 * reaches CURLOPT_URL. The unsafe-shape pattern (concatenation /
 * argv / buffer flowing into CURLOPT_URL) must not match.
 */
#include <curl/curl.h>

#define STATUS_URL "https://api.example.com/status"

int fetch_status(void)
{
    CURL *curl = curl_easy_init();
    CURLcode rc;

    if (!curl) {
        return -1;
    }
    curl_easy_setopt(curl, CURLOPT_URL, STATUS_URL);
    rc = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    return rc == CURLE_OK ? 0 : -1;
}
