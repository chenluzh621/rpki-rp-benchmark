#!/bin/sh

# Keep one digestAlgorithms entry, but replace the required SHA-256 OID with
# SHA-512, which is not allowed by the RPKI CMS profile.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../../cms-signature/common.sh"
. "$SRCDIR/../common.sh"

prepare_valid_roa
mutate_signed_data_digest_algorithms illegal
publish_mutated_roa

run_rp
check_only_target_roa_rejected
