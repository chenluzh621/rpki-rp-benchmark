#!/bin/sh

# ca1.cer's AKI contains the forbidden authorityCertIssuer field.
# BaRRy does not expose that field, so convert an equal-length DER sentinel,
# re-sign ca1.cer, and update the enclosing repository metadata.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../../der-decoding/common.sh"

CA="sandbox/rsyncd/content/$TEST/ta/ca1.cer"
TA="sandbox/rsyncd/content/$TEST/ta.cer"
MANIFEST="sandbox/rsyncd/content/$TEST/ta/ta.mft"
SNAPSHOT="sandbox/apache2/content/$TEST/snapshot.xml"
NOTIFICATION="sandbox/apache2/content/$TEST/notification.xml"
WORK="$SANDBOX/certificate-update"

# Deterministic keys are needed to re-sign the mutated CA and TA manifest.
unset BARRY_GENERATE_KEYS
run_barry
mkdir -p "$WORK"

ORIGINAL_CA_HASH=$(sha256sum "$CA" | cut -d' ' -f1)

# RD encodes authorityCertSerialNumber as the six bytes
#   82 04 82 02 74 61
# where the four content bytes form GeneralNames { dNSName "ta" }.
# Change only the outer [2] primitive tag to the [1] constructed tag used by
# authorityCertIssuer. All DER lengths therefore remain unchanged.
perl - "$CA" "$WORK/ca-issuer-mutated.cer" "$WORK/tbs.der" <<'PERL'
use strict;
use warnings;

my ($input, $output, $tbs_output) = @ARGV;
open my $fh, '<:raw', $input or die "Cannot open $input: $!\n";
local $/;
my $cert = <$fh>;
close $fh;

sub tlv {
	my ($data, $offset) = @_;
	my $first = ord(substr($data, $offset + 1, 1));
	my ($header, $length);
	if ($first < 128) {
		$header = 2;
		$length = $first;
	} else {
		my $count = $first & 0x7f;
		die "Unsupported DER length\n" if $count < 1 || $count > 4;
		$header = 2 + $count;
		$length = 0;
		for my $i (0 .. $count - 1) {
			$length = ($length << 8)
			    | ord(substr($data, $offset + 2 + $i, 1));
		}
	}
	return ($header, $length, $header + $length);
}

my $needle = "\x82\x04\x82\x02ta";
my $count = 0;
my $position = -1;
my $search = 0;
while (($search = index($cert, $needle, $search)) >= 0) {
	$count++;
	$position = $search;
	$search++;
}
die "Expected one AKI sentinel, found $count\n" if $count != 1;
substr($cert, $position, 1, "\xa1");

my ($outer_header, undef, undef) = tlv($cert, 0);
my $tbs_offset = $outer_header;
die "TBSCertificate is not a SEQUENCE\n"
	if ord(substr($cert, $tbs_offset, 1)) != 0x30;
my (undef, undef, $tbs_total) = tlv($cert, $tbs_offset);

open my $out, '>:raw', $output or die "Cannot open $output: $!\n";
print {$out} $cert;
close $out;
open my $tbs, '>:raw', $tbs_output
	or die "Cannot open $tbs_output: $!\n";
print {$tbs} substr($cert, $tbs_offset, $tbs_total);
close $tbs;
PERL
test "$?" -eq 0 || fail "Cannot add authorityCertIssuer to ca1.cer"

# Find the TA private key, which is the issuer key for ca1.cer.
TA_KEY_HASH=$(openssl x509 -inform DER -in "$TA" -pubkey -noout \
	| openssl pkey -pubin -outform DER 2> /dev/null \
	| sha256sum | cut -d' ' -f1)
TA_KEY=""
for KEY_FILE in "${BARRY_KEYS_PATH:-custom/keys}"/*.pem; do
	KEY_HASH=$(openssl pkey -in "$KEY_FILE" -pubout -outform DER \
		2> /dev/null | sha256sum | cut -d' ' -f1)
	if test "$KEY_HASH" = "$TA_KEY_HASH"; then
		TA_KEY="$KEY_FILE"
		break
	fi
done
test -n "$TA_KEY" || fail "Cannot find the TA private key"

openssl dgst -sha256 -sign "$TA_KEY" -out "$WORK/signature.bin" \
	"$WORK/tbs.der" || fail "Cannot re-sign ca1.cer's TBSCertificate"

# Replace the outer certificate signature. The key and all DER lengths remain
# unchanged, so only the signature payload needs replacement.
perl - "$WORK/ca-issuer-mutated.cer" "$WORK/signature.bin" \
	"$WORK/resigned-ca.cer" <<'PERL'
use strict;
use warnings;

my ($cert_path, $sig_path, $output) = @ARGV;
sub read_all {
	my ($path) = @_;
	open my $fh, '<:raw', $path or die "Cannot open $path: $!\n";
	local $/;
	my $data = <$fh>;
	close $fh;
	return $data;
}
sub tlv {
	my ($data, $offset) = @_;
	my $first = ord(substr($data, $offset + 1, 1));
	my ($header, $length);
	if ($first < 128) {
		$header = 2;
		$length = $first;
	} else {
		my $count = $first & 0x7f;
		die "Unsupported DER length\n" if $count < 1 || $count > 4;
		$header = 2 + $count;
		$length = 0;
		for my $i (0 .. $count - 1) {
			$length = ($length << 8)
			    | ord(substr($data, $offset + 2 + $i, 1));
		}
	}
	return ($header, $length, $header + $length);
}

my $cert = read_all($cert_path);
my $signature = read_all($sig_path);
my ($outer_header, undef, undef) = tlv($cert, 0);
my $offset = $outer_header;
for (1 .. 2) {
	my (undef, undef, $total) = tlv($cert, $offset);
	$offset += $total;
}
die "Certificate signature is not a BIT STRING\n"
	if ord(substr($cert, $offset, 1)) != 0x03;
my ($sig_header, $sig_length, undef) = tlv($cert, $offset);
die "Unexpected unused-bits value\n"
	if ord(substr($cert, $offset + $sig_header, 1)) != 0;
die "New signature has the wrong size\n"
	if length($signature) != $sig_length - 1;
substr($cert, $offset + $sig_header + 1, length($signature), $signature);

open my $out, '>:raw', $output or die "Cannot open $output: $!\n";
print {$out} $cert;
close $out;
PERL
test "$?" -eq 0 || fail "Cannot install ca1.cer's new signature"

mv "$WORK/resigned-ca.cer" "$CA"
MUTATED_CA_HASH=$(sha256sum "$CA" | cut -d' ' -f1)

# Confirm valid DER, the intended AKI member, and the new certificate signature.
openssl x509 -inform DER -in "$CA" -noout -text \
	> "$WORK/certificate.txt" 2>&1 \
	|| fail "Mutated ca1.cer is not valid DER"
grep -Fq "DNS:ta" "$WORK/certificate.txt" \
	|| fail "ca1.cer does not contain authorityCertIssuer dNSName ta"
openssl x509 -inform DER -in "$TA" -pubkey -noout > "$WORK/ta-public.pem"
openssl dgst -sha256 -verify "$WORK/ta-public.pem" \
	-signature "$WORK/signature.bin" "$WORK/tbs.der" \
	> "$WORK/verify.log" 2>&1 \
	|| fail "The re-signed ca1.cer does not verify"

# ca1.cer is listed on the TA manifest; keep the repository and RRDP metadata
# consistent so authorityCertIssuer is the only validation defect.
rehash_and_resign_manifest \
	"$MANIFEST" "$ORIGINAL_CA_HASH" "$MUTATED_CA_HASH"
replace_snapshot_object "$SNAPSHOT" \
	"rsync://localhost:8873/rpki/$TEST/ta/ca1.cer" "$CA"
replace_snapshot_object "$SNAPSHOT" \
	"rsync://localhost:8873/rpki/$TEST/ta/ta.mft" "$MANIFEST"
realign_snapshot_hash "$SNAPSHOT" "$NOTIFICATION"

run_rp

check_vrps \
	"10.2.1.0/24-24 => AS64503" \
	"10.2.2.0/24-24 => AS64504"

check_http_requests \
	"/$TEST/ta.cer 200" \
	"/$TEST/notification.xml 200" \
	"/$TEST/snapshot.xml 200"

check_rsync_requests
