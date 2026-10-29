# Shared helper for mutating roa1-1.roa's ROAIPAddressFamily sequence.
# BaRRy's ipAddrBlocks shorthand canonicalizes entries into one IPv4 and one
# IPv6 family, so duplicate, unknown, and third AFIs must be inserted after
# repository generation.

mutate_roa_afi() {
	AFI_MUTATION="$1"
	ROA="sandbox/rsyncd/content/$TEST/ca1/roa1-1.roa"
	MANIFEST="sandbox/rsyncd/content/$TEST/ca1/ca1.mft"
	SNAPSHOT="sandbox/apache2/content/$TEST/snapshot.xml"
	NOTIFICATION="sandbox/apache2/content/$TEST/notification.xml"
	AFI_WORK="$SANDBOX/roa-afi-update"

	mkdir -p "$AFI_WORK"
	ORIGINAL_ROA_HASH=$(sha256sum "$ROA" | cut -d' ' -f1)

	openssl cms -verify -binary -inform DER \
		-in "$ROA" -noverify -nosigs \
		-out "$AFI_WORK/content.der" \
		-signer "$AFI_WORK/ee.pem" \
		> "$AFI_WORK/extract.log" 2>&1 \
		|| fail "Cannot extract $ROA"

	perl - "$AFI_WORK/content.der" "$AFI_WORK/content-updated.der" \
		"$AFI_MUTATION" <<'PERL'
use strict;
use warnings;

my ($input, $output, $mutation) = @ARGV;

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
		die "Truncated DER length\n"
			if $offset + 2 + $count > length($data);
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
		header => $header,
		length => $length,
		total => $header + $length,
		content => $offset + $header,
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
	my ($data) = @_;
	my $tlv = parse_tlv($data, 0);
	die "Trailing data after DER value\n" if $tlv->{total} != length($data);
	return substr($data, $tlv->{content}, $tlv->{length});
}

sub tag_of {
	return parse_tlv($_[0], 0)->{tag};
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
	my ($tag, $content) = @_;
	return chr($tag) . encode_length(length($content)) . $content;
}

sub replace_family_afi {
	my ($family, $afi) = @_;
	die "ROAIPAddressFamily is not a SEQUENCE\n" if tag_of($family) != 0x30;
	my @fields = split_tlvs(content_of($family));
	die "Malformed ROAIPAddressFamily\n"
		if @fields != 2 || tag_of($fields[0]) != 0x04
		|| tag_of($fields[1]) != 0x30;
	die "Expected baseline IPv4 AFI\n"
		if content_of($fields[0]) ne "\x00\x01";
	$fields[0] = make_tlv(0x04, pack('n', $afi));
	return make_tlv(0x30, join('', @fields));
}

sub ipv6_family {
	# 2001:db8:1::/48-48, covered by ca1.cer and the c-case ROA EE cert.
	my $address = make_tlv(0x03, "\x00\x20\x01\x0d\xb8\x00\x01");
	my $max_length = make_tlv(0x02, "\x30");
	my $roa_address = make_tlv(0x30, $address . $max_length);
	my $addresses = make_tlv(0x30, $roa_address);
	return make_tlv(0x30, make_tlv(0x04, "\x00\x02") . $addresses);
}

my $roa = read_all($input);
die "RouteOriginAttestation is not a SEQUENCE\n" if tag_of($roa) != 0x30;
my @roa_fields = split_tlvs(content_of($roa));
die "ROA has too few fields\n" if @roa_fields < 2;
my $blocks_index = $#roa_fields;
die "ipAddrBlocks is not the final SEQUENCE\n"
	if tag_of($roa_fields[$blocks_index]) != 0x30;

my @families = split_tlvs(content_of($roa_fields[$blocks_index]));
die "Expected exactly one baseline address family\n" if @families != 1;
# Validate the baseline AFI before applying any structural mutation.
replace_family_afi($families[0], 1);

if ($mutation eq 'bad') {
	@families = (replace_family_afi($families[0], 3));
} elsif ($mutation eq 'duplicated') {
	@families = ($families[0], $families[0]);
} elsif ($mutation eq 'too-many') {
	@families = ($families[0], ipv6_family(), $families[0]);
} else {
	die "Unknown AFI mutation: $mutation\n";
}

$roa_fields[$blocks_index] = make_tlv(0x30, join('', @families));
my $updated = make_tlv(0x30, join('', @roa_fields));
open my $out, '>:raw', $output or die "Cannot open $output: $!\n";
print {$out} $updated;
close $out;
PERL
	test "$?" -eq 0 || fail "Cannot apply $AFI_MUTATION AFI mutation"

	openssl asn1parse -inform DER -in "$AFI_WORK/content-updated.der" \
		> "$AFI_WORK/asn1.txt" 2>&1 \
		|| fail "Mutated ROA content is not valid DER"

	AFI_EE_KEY_HASH=$(openssl x509 -in "$AFI_WORK/ee.pem" -pubkey -noout \
		| openssl pkey -pubin -outform DER 2> /dev/null \
		| sha256sum | cut -d' ' -f1)
	AFI_EE_KEY=""
	for AFI_KEY_FILE in "${BARRY_KEYS_PATH:-custom/keys}"/*.pem; do
		AFI_KEY_HASH=$(openssl pkey -in "$AFI_KEY_FILE" -pubout \
			-outform DER 2> /dev/null | sha256sum | cut -d' ' -f1)
		if test "$AFI_KEY_HASH" = "$AFI_EE_KEY_HASH"; then
			AFI_EE_KEY="$AFI_KEY_FILE"
			break
		fi
	done
	test -n "$AFI_EE_KEY" || fail "Cannot find the ROA EE private key"

	openssl cms -sign -binary -nodetach -noindef -keyid -nosmimecap \
		-md sha256 -econtent_type 1.2.840.113549.1.9.16.1.24 \
		-in "$AFI_WORK/content-updated.der" \
		-signer "$AFI_WORK/ee.pem" -inkey "$AFI_EE_KEY" \
		-outform DER -out "$AFI_WORK/resigned.roa" \
		> "$AFI_WORK/sign.log" 2>&1 \
		|| fail "Cannot re-sign $ROA"

	openssl cms -verify -binary -inform DER \
		-in "$AFI_WORK/resigned.roa" -noverify \
		-out "$AFI_WORK/verified-content.der" \
		> "$AFI_WORK/verify.log" 2>&1 \
		|| fail "The re-signed $ROA does not verify"
	cmp -s "$AFI_WORK/content-updated.der" "$AFI_WORK/verified-content.der" \
		|| fail "The re-signed $ROA contains unexpected content"

	mv "$AFI_WORK/resigned.roa" "$ROA"
	MUTATED_ROA_HASH=$(sha256sum "$ROA" | cut -d' ' -f1)

	rehash_and_resign_manifest \
		"$MANIFEST" "$ORIGINAL_ROA_HASH" "$MUTATED_ROA_HASH"
	replace_snapshot_object "$SNAPSHOT" \
		"rsync://localhost:8873/rpki/$TEST/ca1/roa1-1.roa" "$ROA"
	replace_snapshot_object "$SNAPSHOT" \
		"rsync://localhost:8873/rpki/$TEST/ca1/ca1.mft" "$MANIFEST"
	realign_snapshot_hash "$SNAPSHOT" "$NOTIFICATION"
}
