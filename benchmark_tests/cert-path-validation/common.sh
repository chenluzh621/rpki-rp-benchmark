#!/bin/sh

# Shared setup and assertions for certificate-path validation tests.

generate_repository() {
	BARRY_GENERATE_KEYS=1
	run_barry
	unset BARRY_GENERATE_KEYS

	CPV_ROOT="sandbox/rsyncd/content/$TEST"
	CPV_TA="$CPV_ROOT/ta.cer"
	CPV_CA1="$CPV_ROOT/ta/ca1.cer"
	CPV_TA_CRL="$CPV_ROOT/ta/ta.crl"
	CPV_CA1_CRL="$CPV_ROOT/ca1/ca1.crl"
	CPV_ROA="$CPV_ROOT/ca1/roa1-1.roa"
	CPV_MFT="$CPV_ROOT/ca1/ca1.mft"
	CPV_WORK="$SANDBOX/cert-path-validation"
	mkdir -p "$CPV_WORK"
}

certificate_serial() {
	openssl x509 -inform DER -in "$1" -noout -serial \
		| sed 's/^serial=//'
}

cms_ee_serial() {
	openssl cms -verify -binary -inform DER -in "$1" \
		-noverify -nosigs -out /dev/null -signer "$CPV_WORK/ee.pem" \
		> "$CPV_WORK/cms-extract.log" 2>&1 \
		|| fail "Cannot extract the EE certificate from $1"
	openssl x509 -in "$CPV_WORK/ee.pem" -noout -serial \
		| sed 's/^serial=//'
}

assert_crl_revokes_serial() {
	CRL_PATH="$1"
	EXPECTED_SERIAL="$2"
	openssl crl -inform DER -in "$CRL_PATH" -text -noout \
		> "$CPV_WORK/crl.txt" 2>&1 \
		|| fail "$CRL_PATH is not a valid DER CRL"
	ACTUAL_SERIAL=$(awk '/Serial Number:/ { print $3; exit }' \
		"$CPV_WORK/crl.txt")
	test -n "$ACTUAL_SERIAL" \
		|| fail "$CRL_PATH has no revoked-certificate entry"
	test "$ACTUAL_SERIAL" = "$EXPECTED_SERIAL" \
		|| fail "$CRL_PATH revokes serial $ACTUAL_SERIAL, expected $EXPECTED_SERIAL"
}

check_ca1_branch_rejected() {
	check_vrps \
		"10.2.1.0/24-24 => AS64503" \
		"10.2.2.0/24-24 => AS64504"
	check_repository_requests
}

check_roa1_1_rejected() {
	check_vrps \
		"10.1.2.0/24-24 => AS64502" \
		"10.2.1.0/24-24 => AS64503" \
		"10.2.2.0/24-24 => AS64504"
	check_repository_requests
}

check_repository_requests() {
	check_http_requests \
		"/$TEST/ta.cer 200" \
		"/$TEST/notification.xml 200" \
		"/$TEST/snapshot.xml 200"
	check_rsync_requests
}
