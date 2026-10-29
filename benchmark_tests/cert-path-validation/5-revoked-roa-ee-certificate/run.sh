#!/bin/sh

# ca1.crl correctly revokes roa1-1.roa's EE certificate only.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../common.sh"

generate_repository
ROA_EE_SERIAL=$(cms_ee_serial "$CPV_ROA")
assert_crl_revokes_serial "$CPV_CA1_CRL" "$ROA_EE_SERIAL"

run_rp
check_roa1_1_rejected
