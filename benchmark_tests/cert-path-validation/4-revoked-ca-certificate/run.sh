#!/bin/sh

# ta.crl correctly revokes ca1.cer, so the entire ca1 branch is invalid.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../common.sh"

generate_repository
CA1_SERIAL=$(certificate_serial "$CPV_CA1")
assert_crl_revokes_serial "$CPV_TA_CRL" "$CA1_SERIAL"

run_rp
check_ca1_branch_rejected
