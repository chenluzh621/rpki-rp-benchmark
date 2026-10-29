#!/bin/sh

# Add AIA only to the self-signed TA; a conforming RP must reject the TA.
. tools/checks.sh
. rp/$RP.sh
# Add a valid but forbidden AIA extension to a self-signed trust anchor.
# BaRRy cannot finish an AIA extension when the certificate has no parent.

aia_add_to_self_signed_ta() {
	AIA_TA_RSYNC="sandbox/rsyncd/content/$TEST/ta.cer"
	AIA_TA_HTTP="sandbox/apache2/content/$TEST/ta.cer"
	AIA_WORK="$SANDBOX/certificate-update"
	AIA_URI="rsync://localhost:8873/rpki/$TEST/ta.cer"

	unset BARRY_GENERATE_KEYS
	run_barry
	mkdir -p "$AIA_WORK"

	perl - "$AIA_TA_RSYNC" "$AIA_URI" "$AIA_WORK/mutated-ta.cer" \
		"$AIA_WORK/tbs.der" <<'PERL'
use strict;
use warnings;
my ($input, $uri, $output, $tbs_output) = @ARGV;

sub read_all {
	my ($path) = @_;
	open my $fh, '<:raw', $path or die "Cannot open $path: $!\n";
	local $/;
	my $data = <$fh>;
	close $fh;
	return $data;
}
sub parse_tlv {
	my ($data, $offset) = @_;
	die "Truncated DER tag\n" if $offset + 2 > length($data);
	my $tag = ord(substr($data, $offset, 1));
	my $first = ord(substr($data, $offset + 1, 1));
	my ($header, $length);
	if ($first < 128) {
		($header, $length) = (2, $first);
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
	die "Truncated DER value\n"
		if $offset + $header + $length > length($data);
	return {
		tag => $tag, header => $header, length => $length,
		total => $header + $length, content => $offset + $header,
	};
}
sub content_of {
	my ($data) = @_;
	my $tlv = parse_tlv($data, 0);
	die "Trailing DER data\n" if $tlv->{total} != length($data);
	return substr($data, $tlv->{content}, $tlv->{length});
}
sub tag_of {
	return parse_tlv($_[0], 0)->{tag};
}
sub split_tlvs {
	my ($data) = @_;
	my (@items, $offset);
	$offset = 0;
	while ($offset < length($data)) {
		my $tlv = parse_tlv($data, $offset);
		push @items, substr($data, $offset, $tlv->{total});
		$offset += $tlv->{total};
	}
	die "DER child boundary mismatch\n" if $offset != length($data);
	return @items;
}
sub encode_length {
	my ($length) = @_;
	return chr($length) if $length < 128;
	my $encoded = '';
	while ($length) {
		$encoded = chr($length & 0xff) . $encoded;
		$length >>= 8;
	}
	return chr(0x80 | length($encoded)) . $encoded;
}
sub make_tlv {
	my ($tag, $body) = @_;
	return chr($tag) . encode_length(length($body)) . $body;
}

my $certificate = read_all($input);
die "Certificate is not a SEQUENCE\n" if tag_of($certificate) != 0x30;
my @certificate_fields = split_tlvs(content_of($certificate));
die "Unexpected Certificate field count\n" if @certificate_fields != 3;
my @tbs_fields = split_tlvs(content_of($certificate_fields[0]));

my $extensions_index = -1;
for my $i (0 .. $#tbs_fields) {
	next if tag_of($tbs_fields[$i]) != 0xa3;
	die "Multiple extension containers\n" if $extensions_index >= 0;
	$extensions_index = $i;
}
die "Extension container not found\n" if $extensions_index < 0;
my @wrapped = split_tlvs(content_of($tbs_fields[$extensions_index]));
die "Malformed Extensions wrapper\n"
	if @wrapped != 1 || tag_of($wrapped[0]) != 0x30;
my @extensions = split_tlvs(content_of($wrapped[0]));

my $aia_oid = pack('H*', '06082b06010505070101');
for my $extension (@extensions) {
	next if tag_of($extension) != 0x30;
	my @fields = split_tlvs(content_of($extension));
	die "TA already contains AIA\n" if @fields && $fields[0] eq $aia_oid;
}

my $ca_issuers_oid = pack('H*', '06082b06010505073002');
my $access_description = make_tlv(0x30,
    $ca_issuers_oid . make_tlv(0x86, $uri));
my $aia_value = make_tlv(0x30, $access_description);
push @extensions, make_tlv(0x30,
    $aia_oid . make_tlv(0x04, $aia_value));

my $new_extensions = make_tlv(0x30, join('', @extensions));
$tbs_fields[$extensions_index] = make_tlv(0xa3, $new_extensions);
my $new_tbs = make_tlv(0x30, join('', @tbs_fields));
my $new_certificate = make_tlv(0x30,
    $new_tbs . $certificate_fields[1] . $certificate_fields[2]);

open my $out, '>:raw', $output or die "Cannot open $output: $!\n";
print {$out} $new_certificate;
close $out;
open my $tbs, '>:raw', $tbs_output
	or die "Cannot open $tbs_output: $!\n";
print {$tbs} $new_tbs;
close $tbs;
PERL
	test "$?" -eq 0 || fail "Cannot add AIA to self-signed TA"

	AIA_KEY_HASH=$(openssl x509 -inform DER -in "$AIA_TA_RSYNC" \
		-pubkey -noout | openssl pkey -pubin -outform DER \
		2> /dev/null | sha256sum | cut -d' ' -f1)
	AIA_KEY_DIR="$BARRY_KEYS_PATH"
	test -n "$AIA_KEY_DIR" || AIA_KEY_DIR=custom/keys
	AIA_TA_KEY=""
	for AIA_KEY_FILE in "$AIA_KEY_DIR"/*.pem; do
		AIA_CANDIDATE_HASH=$(openssl pkey -in "$AIA_KEY_FILE" -pubout \
			-outform DER 2> /dev/null | sha256sum | cut -d' ' -f1)
		if test "$AIA_CANDIDATE_HASH" = "$AIA_KEY_HASH"; then
			AIA_TA_KEY="$AIA_KEY_FILE"
			break
		fi
	done
	test -n "$AIA_TA_KEY" || fail "Cannot find the TA private key"

	openssl dgst -sha256 -sign "$AIA_TA_KEY" \
		-out "$AIA_WORK/signature.bin" "$AIA_WORK/tbs.der" \
		|| fail "Cannot re-sign mutated TA"

	perl - "$AIA_WORK/mutated-ta.cer" "$AIA_WORK/signature.bin" \
		"$AIA_WORK/resigned-ta.cer" <<'PERL'
use strict;
use warnings;
my ($certificate_path, $signature_path, $output) = @ARGV;
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
		($header, $length) = (2, $first);
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
my $certificate = read_all($certificate_path);
my $signature = read_all($signature_path);
my ($outer_header, undef, undef) = tlv($certificate, 0);
my $offset = $outer_header;
for (1 .. 2) {
	my (undef, undef, $total) = tlv($certificate, $offset);
	$offset += $total;
}
die "Certificate signature is not a BIT STRING\n"
	if ord(substr($certificate, $offset, 1)) != 0x03;
my ($header, $length, undef) = tlv($certificate, $offset);
die "Unexpected unused-bits value\n"
	if ord(substr($certificate, $offset + $header, 1)) != 0;
die "New signature has wrong length\n" if length($signature) != $length - 1;
substr($certificate, $offset + $header + 1, $length - 1, $signature);
open my $out, '>:raw', $output or die "Cannot open $output: $!\n";
print {$out} $certificate;
close $out;
PERL
	test "$?" -eq 0 || fail "Cannot insert the TA's new signature"

	mv "$AIA_WORK/resigned-ta.cer" "$AIA_TA_RSYNC"
	cp "$AIA_TA_RSYNC" "$AIA_TA_HTTP"

	openssl x509 -inform DER -in "$AIA_TA_RSYNC" -noout \
		-ext authorityInfoAccess > "$AIA_WORK/aia.txt" 2>&1 \
		|| fail "Mutated TA is not valid DER"
	grep -Fq "$AIA_URI" "$AIA_WORK/aia.txt" \
		|| fail "Mutated TA does not contain the intended AIA"
	openssl x509 -inform DER -in "$AIA_TA_RSYNC" -pubkey -noout \
		> "$AIA_WORK/ta-public.pem"
	openssl dgst -sha256 -verify "$AIA_WORK/ta-public.pem" \
		-signature "$AIA_WORK/signature.bin" "$AIA_WORK/tbs.der" \
		> "$AIA_WORK/verify.log" 2>&1 \
		|| fail "The re-signed TA does not verify"
}

aia_add_to_self_signed_ta
run_rp

check_vrps

check_http_requests \
	"/$TEST/ta.cer 200"

check_rsync_requests
