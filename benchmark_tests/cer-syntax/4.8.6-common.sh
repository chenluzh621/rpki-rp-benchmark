# Shared helpers for constructing RFC 6487 section 4.8.6 CRLDP variants.
# BaRRy exposes the CRLDP extension itself, but not its extnValue structure.

crldp_mutate_ca() {
	CRLDP_VARIANT="$1"
	CRLDP_CA="sandbox/rsyncd/content/$TEST/ta/ca1.cer"
	CRLDP_TA="sandbox/rsyncd/content/$TEST/ta.cer"
	CRLDP_MANIFEST="sandbox/rsyncd/content/$TEST/ta/ta.mft"
	CRLDP_SNAPSHOT="sandbox/apache2/content/$TEST/snapshot.xml"
	CRLDP_NOTIFICATION="sandbox/apache2/content/$TEST/notification.xml"
	CRLDP_WORK="$SANDBOX/certificate-update"

	unset BARRY_GENERATE_KEYS
	run_barry
	mkdir -p "$CRLDP_WORK"

	CRLDP_OLD_HASH=$(sha256sum "$CRLDP_CA" | cut -d' ' -f1)
	perl - "$CRLDP_VARIANT" "$CRLDP_CA" "$CRLDP_WORK/mutated-ca.cer" \
		"$CRLDP_WORK/tbs.der" <<'PERL'
use strict;
use warnings;

my ($variant, $input, $output, $tbs_output) = @ARGV;

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
		$header = 2;
		$length = $first;
	} else {
		my $count = $first & 0x7f;
		die "Unsupported DER length\n" if $count < 1 || $count > 4;
		die "Truncated DER length\n" if $offset + 2 + $count > length($data);
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
		tag => $tag,
		offset => $offset,
		header => $header,
		length => $length,
		total => $header + $length,
		content_offset => $offset + $header,
	};
}

sub split_tlvs {
	my ($data) = @_;
	my @items;
	my $offset = 0;
	while ($offset < length($data)) {
		my $tlv = parse_tlv($data, $offset);
		push @items, substr($data, $offset, $tlv->{total});
		$offset += $tlv->{total};
	}
	die "DER child boundary mismatch\n" if $offset != length($data);
	return @items;
}

sub content_of {
	my ($tlv_data) = @_;
	my $tlv = parse_tlv($tlv_data, 0);
	die "Trailing data after DER value\n" if $tlv->{total} != length($tlv_data);
	return substr($tlv_data, $tlv->{content_offset}, $tlv->{length});
}

sub tag_of {
	my ($tlv_data) = @_;
	return parse_tlv($tlv_data, 0)->{tag};
}

sub encode_length {
	my ($length) = @_;
	return chr($length) if $length < 128;
	my $encoded = '';
	while ($length > 0) {
		$encoded = chr($length & 0xff) . $encoded;
		$length >>= 8;
	}
	return chr(0x80 | length($encoded)) . $encoded;
}

sub make_tlv {
	my ($tag, $content) = @_;
	return chr($tag) . encode_length(length($content)) . $content;
}

my $certificate = read_all($input);
die "Certificate is not a SEQUENCE\n" if tag_of($certificate) != 0x30;
my @certificate_fields = split_tlvs(content_of($certificate));
die "Unexpected Certificate field count\n" if @certificate_fields != 3;

my $tbs = $certificate_fields[0];
die "TBSCertificate is not a SEQUENCE\n" if tag_of($tbs) != 0x30;
my @tbs_fields = split_tlvs(content_of($tbs));

my $extensions_index = -1;
for my $i (0 .. $#tbs_fields) {
	if (tag_of($tbs_fields[$i]) == 0xa3) {
		die "Multiple certificate extension containers\n"
			if $extensions_index >= 0;
		$extensions_index = $i;
	}
}
die "Certificate extension container not found\n" if $extensions_index < 0;

my @explicit_extensions = split_tlvs(content_of($tbs_fields[$extensions_index]));
die "Malformed explicit Extensions wrapper\n"
	if @explicit_extensions != 1 || tag_of($explicit_extensions[0]) != 0x30;
my @extensions = split_tlvs(content_of($explicit_extensions[0]));

my $crldp_oid = pack('H*', '0603551d1f');
my $crldp_index = -1;
my $crldp_value;
for my $i (0 .. $#extensions) {
	next if tag_of($extensions[$i]) != 0x30;
	my @fields = split_tlvs(content_of($extensions[$i]));
	next if !@fields || $fields[0] ne $crldp_oid;
	die "Multiple CRLDP extensions\n" if $crldp_index >= 0;
	$crldp_index = $i;
	for my $field (@fields[1 .. $#fields]) {
		if (tag_of($field) == 0x04) {
			die "Multiple CRLDP extnValue fields\n" if defined $crldp_value;
			$crldp_value = content_of($field);
		}
	}
}
die "CRLDP extension not found\n" if $crldp_index < 0;
die "CRLDP extnValue not found\n" if !defined $crldp_value;

# The baseline value is:
# SEQUENCE { SEQUENCE { [0] { [0] { uniformResourceIdentifier } } } }
my @points = split_tlvs(content_of($crldp_value));
die "Baseline CRLDP must contain one DistributionPoint\n"
	if tag_of($crldp_value) != 0x30 || @points != 1
	    || tag_of($points[0]) != 0x30;
my @point_fields = split_tlvs(content_of($points[0]));
die "Baseline DistributionPoint has unexpected fields\n"
	if @point_fields != 1 || tag_of($point_fields[0]) != 0xa0;
my @dpn = split_tlvs(content_of($point_fields[0]));
die "Baseline DistributionPointName is not fullName\n"
	if @dpn != 1 || tag_of($dpn[0]) != 0xa0;
my @general_names = split_tlvs(content_of($dpn[0]));
die "Baseline fullName is not one URI\n"
	if @general_names != 1 || tag_of($general_names[0]) != 0x86;
my $uri = content_of($general_names[0]);

my $uri_name = make_tlv(0x86, $uri);
my $full_name = make_tlv(0xa0, $uri_name);
my $distribution_point_name = make_tlv(0xa0, $full_name);
my $valid_point = make_tlv(0x30, $distribution_point_name);
my $new_value;

if ($variant eq 'reasons') {
	# [1] IMPLICIT ReasonFlags: keyCompromise is TRUE.
	my $reasons = make_tlv(0x81, "\x06\x40");
	$new_value = make_tlv(0x30,
	    make_tlv(0x30, $distribution_point_name . $reasons));
} elsif ($variant eq 'crl-issuer') {
	# [2] IMPLICIT GeneralNames containing one URI GeneralName.
	my $crl_issuer = make_tlv(0xa2, $uri_name);
	$new_value = make_tlv(0x30,
	    make_tlv(0x30, $distribution_point_name . $crl_issuer));
} elsif ($variant eq 'name-relative') {
	# nameRelativeToCRLIssuer [1] contains RDN: CN=relative.
	my $common_name_oid = pack('H*', '0603550403');
	my $printable = make_tlv(0x13, 'relative');
	my $attribute = make_tlv(0x30, $common_name_oid . $printable);
	my $relative_name = make_tlv(0xa1, $attribute);
	my $relative_dpn = make_tlv(0xa0, $relative_name);
	$new_value = make_tlv(0x30, make_tlv(0x30, $relative_dpn));
} elsif ($variant eq 'non-uri-name') {
	# fullName contains a syntactically valid dNSName rather than a URI.
	my $dns_name = make_tlv(0x82, 'example.net');
	my $dns_full_name = make_tlv(0xa0, $dns_name);
	my $dns_dpn = make_tlv(0xa0, $dns_full_name);
	$new_value = make_tlv(0x30, make_tlv(0x30, $dns_dpn));
} elsif ($variant eq 'multiple-points') {
	$new_value = make_tlv(0x30, $valid_point . $valid_point);
} else {
	die "Unknown CRLDP variant: $variant\n";
}

my @crldp_fields = split_tlvs(content_of($extensions[$crldp_index]));
my $octet_count = 0;
for my $i (0 .. $#crldp_fields) {
	if (tag_of($crldp_fields[$i]) == 0x04) {
		$crldp_fields[$i] = make_tlv(0x04, $new_value);
		$octet_count++;
	}
}
die "Expected one CRLDP OCTET STRING\n" if $octet_count != 1;
$extensions[$crldp_index] = make_tlv(0x30, join('', @crldp_fields));

my $new_extensions = make_tlv(0x30, join('', @extensions));
$tbs_fields[$extensions_index] = make_tlv(0xa3, $new_extensions);
my $new_tbs = make_tlv(0x30, join('', @tbs_fields));
my $new_certificate = make_tlv(0x30,
    $new_tbs . $certificate_fields[1] . $certificate_fields[2]);

open my $out, '>:raw', $output or die "Cannot open $output: $!\n";
print {$out} $new_certificate;
close $out;
open my $tbs_out, '>:raw', $tbs_output
	or die "Cannot open $tbs_output: $!\n";
print {$tbs_out} $new_tbs;
close $tbs_out;
PERL
	test "$?" -eq 0 || fail "Cannot construct CRLDP variant $CRLDP_VARIANT"

	CRLDP_TA_KEY_HASH=$(openssl x509 -inform DER -in "$CRLDP_TA" \
		-pubkey -noout | openssl pkey -pubin -outform DER \
		2> /dev/null | sha256sum | cut -d' ' -f1)
	CRLDP_TA_KEY=""
	for CRLDP_KEY_FILE in "${BARRY_KEYS_PATH:-custom/keys}"/*.pem; do
		CRLDP_KEY_HASH=$(openssl pkey -in "$CRLDP_KEY_FILE" -pubout \
			-outform DER 2> /dev/null | sha256sum | cut -d' ' -f1)
		if test "$CRLDP_KEY_HASH" = "$CRLDP_TA_KEY_HASH"; then
			CRLDP_TA_KEY="$CRLDP_KEY_FILE"
			break
		fi
	done
	test -n "$CRLDP_TA_KEY" || fail "Cannot find the TA private key"

	openssl dgst -sha256 -sign "$CRLDP_TA_KEY" \
		-out "$CRLDP_WORK/signature.bin" "$CRLDP_WORK/tbs.der" \
		|| fail "Cannot re-sign mutated ca1.cer"

	perl - "$CRLDP_WORK/mutated-ca.cer" "$CRLDP_WORK/signature.bin" \
		"$CRLDP_WORK/resigned-ca.cer" <<'PERL'
use strict;
use warnings;

my ($cert_path, $signature_path, $output) = @ARGV;
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

my $certificate = read_all($cert_path);
my $signature = read_all($signature_path);
my ($outer_header, undef, undef) = parse_tlv($certificate, 0);
my $offset = $outer_header;
for (1 .. 2) {
	my (undef, undef, $total) = parse_tlv($certificate, $offset);
	$offset += $total;
}
die "Certificate signature is not a BIT STRING\n"
	if ord(substr($certificate, $offset, 1)) != 0x03;
my ($header, $length, undef) = parse_tlv($certificate, $offset);
die "Unexpected unused-bits value\n"
	if ord(substr($certificate, $offset + $header, 1)) != 0;
die "New signature has wrong length\n" if length($signature) != $length - 1;
substr($certificate, $offset + $header + 1, $length - 1, $signature);

open my $out, '>:raw', $output or die "Cannot open $output: $!\n";
print {$out} $certificate;
close $out;
PERL
	test "$?" -eq 0 || fail "Cannot insert ca1.cer's new signature"

	mv "$CRLDP_WORK/resigned-ca.cer" "$CRLDP_CA"
	CRLDP_NEW_HASH=$(sha256sum "$CRLDP_CA" | cut -d' ' -f1)

	openssl x509 -inform DER -in "$CRLDP_CA" -noout -text \
		> "$CRLDP_WORK/certificate.txt" 2>&1 \
		|| fail "Mutated ca1.cer is not valid DER"
	openssl x509 -inform DER -in "$CRLDP_TA" -pubkey -noout \
		> "$CRLDP_WORK/ta-public.pem"
	openssl dgst -sha256 -verify "$CRLDP_WORK/ta-public.pem" \
		-signature "$CRLDP_WORK/signature.bin" "$CRLDP_WORK/tbs.der" \
		> "$CRLDP_WORK/verify.log" 2>&1 \
		|| fail "The re-signed ca1.cer does not verify"

	rehash_and_resign_manifest \
		"$CRLDP_MANIFEST" "$CRLDP_OLD_HASH" "$CRLDP_NEW_HASH"
	replace_snapshot_object "$CRLDP_SNAPSHOT" \
		"rsync://localhost:8873/rpki/$TEST/ta/ca1.cer" "$CRLDP_CA"
	replace_snapshot_object "$CRLDP_SNAPSHOT" \
		"rsync://localhost:8873/rpki/$TEST/ta/ta.mft" "$CRLDP_MANIFEST"
	realign_snapshot_hash "$CRLDP_SNAPSHOT" "$CRLDP_NOTIFICATION"
}

crldp_check_rejected_branch() {
	run_rp

	check_vrps \
		"10.2.1.0/24-24 => AS64503" \
		"10.2.2.0/24-24 => AS64504"

	check_http_requests \
		"/$TEST/ta.cer 200" \
		"/$TEST/notification.xml 200" \
		"/$TEST/snapshot.xml 200"

	check_rsync_requests
}
