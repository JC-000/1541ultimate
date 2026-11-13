/*
 * Host side tests for the certificate date policy of the control module's recovery.
 *
 *   make -C target/pc/linux/recoverydates test
 *
 * The real software/u64ctrl/main/recovery_dates.h is compiled here.
 */
#include <stdio.h>
#include "recovery_dates.h"

static int failures;
static int checks;

static void check(int condition, const char *what)
{
    checks++;
    if (!condition) {
        failures++;
        printf("  FAIL  %s\n", what);
    } else {
        printf("  ok    %s\n", what);
    }
}

// mbedTLS: BADCERT_EXPIRED 0x01, REVOKED 0x02, CN_MISMATCH 0x04, NOT_TRUSTED 0x08, BADCRL_NOT_TRUSTED 0x10
#define OTHER_FLAGS 0x1Eu

int main(void)
{
    const int64_t good = RECOVERY_CLOCK_FLOOR + 1000;

    printf("The clock\n");
    check(!recovery_clock_valid(false, good), "SNTP has not run: not valid, whatever time() says");
    check(!recovery_clock_valid(true, 0), "SNTP says it ran but time() is 1970: not valid");
    check(!recovery_clock_valid(true, RECOVERY_CLOCK_FLOOR - 1), "one second before 2024-01-01: not valid");
    check(recovery_clock_valid(true, RECOVERY_CLOCK_FLOOR), "2024-01-01 with SNTP: valid");
    check(recovery_clock_valid(true, good), "later with SNTP: valid");

    printf("Unknown clock: only the date flags go\n");
    check(recovery_date_policy(RECOVERY_X509_BADCERT_FUTURE, false) == 0, "not yet valid is cleared");
    check(recovery_date_policy(RECOVERY_X509_BADCERT_EXPIRED, false) == 0, "expired is cleared");
    check(recovery_date_policy(RECOVERY_X509_BADCRL_FUTURE | RECOVERY_X509_BADCRL_EXPIRED, false) == 0,
          "the CRL date flags are cleared");
    check(recovery_date_policy(RECOVERY_X509_DATE_FLAGS | OTHER_FLAGS, false) == OTHER_FLAGS,
          "untrusted, revoked, name mismatch and CRL-untrusted stay");
    check(recovery_date_policy(OTHER_FLAGS, false) == OTHER_FLAGS, "no date flag: unchanged");
    check(recovery_date_policy(0, false) == 0, "no flags: none");
    check(recovery_date_policy(0x8000u | RECOVERY_X509_BADCERT_FUTURE, false) == 0x8000u, "flags outside the set stay");

    printf("Valid clock: dates count\n");
    check(recovery_date_policy(RECOVERY_X509_BADCERT_EXPIRED, true) == RECOVERY_X509_BADCERT_EXPIRED, "expired stays");
    check(recovery_date_policy(RECOVERY_X509_BADCERT_FUTURE, true) == RECOVERY_X509_BADCERT_FUTURE, "not yet valid stays");
    check(recovery_date_policy(RECOVERY_X509_DATE_FLAGS | OTHER_FLAGS, true) == (RECOVERY_X509_DATE_FLAGS | OTHER_FLAGS),
          "all flags stay");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
