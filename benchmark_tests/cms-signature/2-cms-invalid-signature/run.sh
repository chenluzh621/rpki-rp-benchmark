#!/bin/sh

# Corrupt only SignerInfo.signature after repository generation.  Every other
# byte, including the encapsulated ROA payload and EE certificate, stays fixed.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../common.sh"

prepare_valid_roa

# The layout assertion in prepare_valid_roa() proves that the final 256 bytes
# are the CMS signature OCTET STRING.  Flip one bit in its final byte.
perl - "$ROA" <<'PERL'
use strict;
use warnings;

my ($path) = @ARGV;
open my $input, '<:raw', $path or die "Cannot open $path: $!\n";
local $/;
my $roa = <$input>;
close $input;
die "ROA is too short to contain a 256-byte signature\n"
	if length($roa) < 256;
substr($roa, -1, 1) = chr(ord(substr($roa, -1, 1)) ^ 0x01);

open my $output, '>:raw', $path or die "Cannot write $path: $!\n";
print {$output} $roa;
close $output;
PERL
test "$?" -eq 0 || fail "Cannot mutate roa1-1.roa CMS signature"

# Prove that the signature mutation changed exactly the last file byte.
cmp -l "$CMS_WORK/original.roa" "$ROA" > "$CMS_WORK/file-diff.txt"
test "$(wc -l < "$CMS_WORK/file-diff.txt")" -eq 1 \
	|| fail "The signature mutation changed more than one ROA byte"
ROA_SIZE=$(wc -c < "$ROA")
DIFF_OFFSET=$(awk 'NR == 1 { print $1 }' "$CMS_WORK/file-diff.txt")
test "$DIFF_OFFSET" -eq "$ROA_SIZE" \
	|| fail "The signature mutation did not change the final signature byte"

# Decode while suppressing signature checks and prove that eContent is exactly
# identical to the original payload.
openssl cms -verify -binary -inform DER -in "$ROA" -noverify -nosigs \
	-out "$CMS_WORK/mutated-content.der" \
	> "$CMS_WORK/mutated-content-extract.log" 2>&1 \
	|| fail "Cannot extract eContent after the signature-only mutation"
cmp -s "$CMS_WORK/original-content.der" "$CMS_WORK/mutated-content.der" \
	|| fail "The signature-only mutation unexpectedly changed ROA eContent"

assert_invalid_cms_signature
publish_mutated_roa

run_rp
check_only_target_roa_rejected
