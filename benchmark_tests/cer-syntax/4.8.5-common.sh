# Shared helpers for inserting a non-critical Extended Key Usage extension
# into an already generated certificate without changing any DER lengths.

eku_mutate_certificate() {
	EKU_INPUT="$1"
	EKU_OUTPUT="$2"
	EKU_TBS_OUTPUT="$3"

	perl - "$EKU_INPUT" "$EKU_OUTPUT" "$EKU_TBS_OUTPUT" <<'PERL'
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

# Non-critical Certificate Policies placeholder:
#   extnID    2.5.29.32
#   extnValue SEQUENCE { SEQUENCE { 1.3.6.1.5.5.7.14.2 } }
my $old = pack('H*',
    '0603551d20040e300c300a06082b06010505070e02');

# Equal-length, non-critical Extended Key Usage extension:
#   extnID    2.5.29.37
#   extnValue SEQUENCE { 1.3.6.1.5.5.7.3.1.1.1 }
my $new = pack('H*',
    '0603551d25040e300c060a2b060105050703010101');

die "EKU replacement changes DER length\n" if length($old) != length($new);
my $count = ($cert =~ s/\Q$old\E/$new/g);
die "Expected one EKU placeholder, found $count\n" if $count != 1;

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
	test "$?" -eq 0 || fail "Cannot convert EKU placeholder in $EKU_INPUT"
}

eku_resign_certificate() {
	EKU_MUTATED_CERT="$1"
	EKU_TBS="$2"
	EKU_ISSUER_CERT="$3"
	EKU_SIGNATURE="$4"
	EKU_SIGNED_CERT="$5"
	EKU_PUBLIC_KEY="$6"

	EKU_ISSUER_KEY_HASH=$(openssl x509 -inform DER -in "$EKU_ISSUER_CERT" \
		-pubkey -noout | openssl pkey -pubin -outform DER \
		2> /dev/null | sha256sum | cut -d' ' -f1)
	EKU_ISSUER_KEY=""
	for EKU_KEY_FILE in "${BARRY_KEYS_PATH:-custom/keys}"/*.pem; do
		EKU_KEY_HASH=$(openssl pkey -in "$EKU_KEY_FILE" -pubout \
			-outform DER 2> /dev/null | sha256sum | cut -d' ' -f1)
		if test "$EKU_KEY_HASH" = "$EKU_ISSUER_KEY_HASH"; then
			EKU_ISSUER_KEY="$EKU_KEY_FILE"
			break
		fi
	done
	test -n "$EKU_ISSUER_KEY" || fail "Cannot find certificate issuer key"

	openssl dgst -sha256 -sign "$EKU_ISSUER_KEY" -out "$EKU_SIGNATURE" \
		"$EKU_TBS" || fail "Cannot re-sign mutated certificate"

	perl - "$EKU_MUTATED_CERT" "$EKU_SIGNATURE" "$EKU_SIGNED_CERT" <<'PERL'
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
die "New signature has wrong length\n"
	if length($signature) != $sig_length - 1;
substr($cert, $offset + $sig_header + 1, $sig_length - 1, $signature);

open my $out, '>:raw', $output or die "Cannot open $output: $!\n";
print {$out} $cert;
close $out;
PERL
		test "$?" -eq 0 || fail "Cannot insert new certificate signature"

	openssl x509 -inform DER -in "$EKU_ISSUER_CERT" -pubkey -noout \
		> "$EKU_PUBLIC_KEY" || fail "Cannot extract issuer public key"
	openssl dgst -sha256 -verify "$EKU_PUBLIC_KEY" \
		-signature "$EKU_SIGNATURE" "$EKU_TBS" > /dev/null 2>&1 \
		|| fail "Mutated certificate signature does not verify"
}

eku_replace_binary_blob() {
	EKU_CONTAINER="$1"
	EKU_OLD_BLOB="$2"
	EKU_NEW_BLOB="$3"
	EKU_CONTAINER_OUTPUT="$4"

	perl - "$EKU_CONTAINER" "$EKU_OLD_BLOB" "$EKU_NEW_BLOB" \
		"$EKU_CONTAINER_OUTPUT" <<'PERL'
use strict;
use warnings;

my ($container_path, $old_path, $new_path, $output) = @ARGV;
sub read_all {
	my ($path) = @_;
	open my $fh, '<:raw', $path or die "Cannot open $path: $!\n";
	local $/;
	my $data = <$fh>;
	close $fh;
	return $data;
}

my $container = read_all($container_path);
my $old = read_all($old_path);
my $new = read_all($new_path);
die "Replacement blob changes DER length\n" if length($old) != length($new);
my $count = ($container =~ s/\Q$old\E/$new/g);
die "Expected one embedded certificate, found $count\n" if $count != 1;

open my $out, '>:raw', $output or die "Cannot open $output: $!\n";
print {$out} $container;
close $out;
PERL
		test "$?" -eq 0 || fail "Cannot replace embedded certificate"
}
