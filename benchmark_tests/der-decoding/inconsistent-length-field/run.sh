#!/bin/sh

# Verify that a CMS ContentInfo whose outer length exceeds the available
# payload is rejected, while the other objects remain valid.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../common.sh"

ROA="sandbox/rsyncd/content/$TEST/ca1/roa1-1.roa"
MANIFEST="sandbox/rsyncd/content/$TEST/ca1/ca1.mft"
SNAPSHOT="sandbox/apache2/content/$TEST/snapshot.xml"
NOTIFICATION="sandbox/apache2/content/$TEST/notification.xml"
MUTATED_ROA="$SANDBOX/roa1-1.mutated"

# Reuse the valid baseline RD and deterministic test key pool.
unset BARRY_GENERATE_KEYS
run_barry "../../baseline/rd"

ORIGINAL_ROA_HASH=$(sha256sum "$ROA" | cut -d' ' -f1)
ORIGINAL_ROA_SIZE=$(wc -c < "$ROA")

# Parse the outer TLV dynamically because URI lengths make the generated ROA
# size test-name-dependent. Increase only the declared content length by one;
# do not truncate or append any bytes.
perl - "$ROA" > "$MUTATED_ROA" <<'PERL'
use strict;
use warnings;

my ($path) = @ARGV;
open my $input, '<:raw', $path or die "Cannot open $path: $!\n";
local $/;
my $data = <$input>;
close $input;

die "ROA is too short for an ASN.1 TLV\n" if length($data) < 2;
die "ContentInfo does not start with SEQUENCE\n"
	if unpack('C', substr($data, 0, 1)) != 0x30;

my $first = unpack('C', substr($data, 1, 1));
my ($octets, $header_size, $declared_length);
if (($first & 0x80) == 0) {
	$octets = 0;
	$header_size = 2;
	$declared_length = $first;
} else {
	$octets = $first & 0x7f;
	die "Outer length is indefinite or too wide\n"
		if $octets == 0 || $octets > 4;
	die "ROA ends inside its outer length field\n"
		if length($data) < 2 + $octets;
	$header_size = 2 + $octets;
	$declared_length = 0;
	for my $byte (unpack('C*', substr($data, 2, $octets))) {
		$declared_length = ($declared_length << 8) | $byte;
	}
}

my $actual_length = length($data) - $header_size;
die "Outer length $declared_length does not match payload $actual_length\n"
	if $declared_length != $actual_length;

my $new_length = $declared_length + 1;
if ($octets == 0) {
	die "Incremented length no longer fits short form\n" if $new_length >= 128;
	substr($data, 1, 1, pack('C', $new_length));
} else {
	die "Incremented length no longer fits existing field\n"
		if $new_length >= 256 ** $octets;
	my @encoded;
	for my $index (reverse(0 .. $octets - 1)) {
		push @encoded, ($new_length >> (8 * $index)) & 0xff;
	}
	substr($data, 2, $octets, pack('C*', @encoded));
}

binmode STDOUT;
print $data;
PERL
test "$?" -eq 0 || fail "Cannot mutate the outer ASN.1 length in $ROA"
test "$(wc -c < "$MUTATED_ROA")" -eq "$ORIGINAL_ROA_SIZE" \
	|| fail "Changing the ASN.1 length unexpectedly changed the ROA size"

if openssl asn1parse -inform DER -in "$MUTATED_ROA" \
	> "$SANDBOX/asn1-parse.log" 2>&1; then
	fail "The inconsistent outer length was unexpectedly accepted"
fi

mv "$MUTATED_ROA" "$ROA"
MUTATED_ROA_HASH=$(sha256sum "$ROA" | cut -d' ' -f1)

# Keep the manifest and RRDP metadata consistent so ASN.1 decoding is the
# only reason to reject this ROA.
rehash_and_resign_manifest \
	"$MANIFEST" "$ORIGINAL_ROA_HASH" "$MUTATED_ROA_HASH"
replace_snapshot_object "$SNAPSHOT" \
	"rsync://localhost:8873/rpki/$TEST/ca1/roa1-1.roa" "$ROA"
replace_snapshot_object "$SNAPSHOT" \
	"rsync://localhost:8873/rpki/$TEST/ca1/ca1.mft" "$MANIFEST"
realign_snapshot_hash "$SNAPSHOT" "$NOTIFICATION"

run_rp

# Only the VRP contributed by roa1-1.roa must disappear.
check_vrps \
	"10.1.2.0/24-24 => AS64502" \
	"10.2.1.0/24-24 => AS64503" \
	"10.2.2.0/24-24 => AS64504"

check_http_requests \
	"/$TEST/ta.cer 200" \
	"/$TEST/notification.xml 200" \
	"/$TEST/snapshot.xml 200"
check_rsync_requests
