#!/bin/sh

# Duplicate the valid SHA-256 AlgorithmIdentifier in SignedData.digestAlgorithms.
# The resulting SET has two entries although the RPKI CMS profile requires one.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../../cms-signature/common.sh"
. "$SRCDIR/../common.sh"

prepare_valid_roa
mutate_signed_data_digest_algorithms multiple
publish_mutated_roa

run_rp
check_only_target_roa_rejected
