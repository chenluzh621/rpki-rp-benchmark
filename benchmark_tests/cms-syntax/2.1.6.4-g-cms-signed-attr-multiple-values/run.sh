#!/bin/sh

. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../2.1.6.4-common.sh"

prepare_roa_with_signed_attrs_mutation content-type-multiple-values
run_rp
check_only_target_roa_rejected
