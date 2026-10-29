#!/bin/sh

# ca1.crl correctly revokes ca1.mft's EE certificate, invalidating the branch.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../common.sh"

generate_repository
MFT_EE_SERIAL=$(cms_ee_serial "$CPV_MFT")
assert_crl_revokes_serial "$CPV_CA1_CRL" "$MFT_EE_SERIAL"

run_rp
check_ca1_branch_rejected
