#!/bin/sh

# ca1.cer's DistributionPointName uses nameRelativeToCRLIssuer.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../../der-decoding/common.sh"
. "$SRCDIR/../4.8.6-common.sh"

crldp_mutate_ca name-relative
crldp_check_rejected_branch
