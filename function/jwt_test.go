package main

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

func createKey() (jwk.Set, jwk.Key, error) {
	// base RSA key
	rsaKey, generateError := rsa.GenerateKey(rand.Reader, 2048)

	if generateError != nil {
		return nil, nil, generateError
	}

	// create private key
	privateKey := jwk.NewRSAPrivateKey()
	keyError := privateKey.FromRaw(rsaKey)

	if keyError != nil {
		return nil, nil, keyError
	}

	keyIdError := jwk.AssignKeyID(privateKey)

	if keyIdError != nil {
		return nil, nil, keyIdError
	}

	// create public key
	publicKey, publicKeyError := privateKey.PublicKey()

	if publicKeyError != nil {
		return nil, nil, keyIdError
	}

	publicSet := jwk.NewSet()
	publicSet.Add(publicKey)

	return publicSet, privateKey, nil
}

func createSignedJWT(issuer string, audience string, issuedAt time.Time, expiration time.Time) ([]byte, jwk.Set, error) {
	publicKeySet, privateKey, err := createKey()

	token, err := jwt.NewBuilder().
		IssuedAt(issuedAt).
		Expiration(expiration).
		Issuer(issuer).
		Audience([]string{audience}).
		Build()

	signed, err := jwt.Sign(token, "RS256", privateKey)

	if err != nil {
		return nil, nil, err
	}

	return signed, publicKeySet, nil
}

func expectError(expected string, actual error, t *testing.T) {
	if actual == nil {
		t.Errorf("test failed no error raised expected (%s)", expected)
	}

	if actual.Error() != expected {
		t.Errorf("test failed expected (%s) Error got (%s)", expected, actual)
	}

	if actual.Error() == expected {
		t.Logf("condition passed expected (%s) Error got (%s)", expected, actual)
	}
}

func TestValidJWTHasNoError(t *testing.T) {
	const issuer = "issuer"
	const audience = "audience"
	issuedAt := time.Now()
	expiration := time.Now().Add(time.Hour)

	signedJwt, publicKeySet, signError := createSignedJWT(issuer, audience, issuedAt, expiration)

	if signError != nil {
		t.Errorf("test failed due to signing error %v", err)
	}

	validatedToken, validateError := validateJWT(signedJwt, publicKeySet, issuer, audience)

	if validateError != nil {
		t.Errorf("test failed due to validation error %v", err)
	}

	log.Printf("ValidatedToken = %+v\n", validatedToken)
}

func TestInvalidIssuerJWTHasError(t *testing.T) {
	const issuer = "issuer"
	const audience = "audience"
	issuedAt := time.Now()
	expiration := time.Now().Add(time.Hour)

	signedJwt, publicKeySet, signError := createSignedJWT("invalid", audience, issuedAt, expiration)

	if signError != nil {
		t.Errorf("test failed due to signing error %v", err)
	}

	_, validateError := validateJWT(signedJwt, publicKeySet, issuer, audience)

	expectError("\"iss\" not satisfied: values do not match", validateError, t)
}

func TestInvalidAudienceJWTHasError(t *testing.T) {
	const issuer = "issuer"
	const audience = "audience"
	issuedAt := time.Now()
	expiration := time.Now().Add(time.Hour)

	signedJwt, publicKeySet, signError := createSignedJWT(issuer, "invalid", issuedAt, expiration)

	if signError != nil {
		t.Errorf("test failed due to signing error %v", err)
	}

	_, validateError := validateJWT(signedJwt, publicKeySet, issuer, audience)

	expectError("aud not satisfied", validateError, t)
}

func TestExpiredJWTHasError(t *testing.T) {
	const issuer = "issuer"
	const audience = "audience"
	issuedAt := time.Now().Add(-time.Hour)     // one hour ago
	expiration := time.Now().Add(-time.Second) // one second ago

	signedJwt, publicKeySet, signError := createSignedJWT(issuer, audience, issuedAt, expiration)

	if signError != nil {
		t.Errorf("test failed due to signing error %v", err)
	}

	_, validateError := validateJWT(signedJwt, publicKeySet, issuer, audience)

	expectError("exp not satisfied", validateError, t)
}

func TestFutureIssuedJWTHasError(t *testing.T) {
	const issuer = "issuer"
	const audience = "audience"
	issuedAt := time.Now().Add(time.Minute) // in one minute
	expiration := time.Now().Add(time.Hour) // in one hour

	signedJwt, publicKeySet, signError := createSignedJWT(issuer, audience, issuedAt, expiration)

	if signError != nil {
		t.Errorf("test failed due to signing error %v", err)
	}

	_, validateError := validateJWT(signedJwt, publicKeySet, issuer, audience)

	expectError("iat not satisfied", validateError, t)
}

func TestJunkJWTHasError(t *testing.T) {
	const issuer = "issuer"
	const audience = "audience"
	issuedAt := time.Now().Add(time.Minute) // in one minute
	expiration := time.Now().Add(time.Hour) // in one hour

	_, publicKeySet, signError := createSignedJWT(issuer, audience, issuedAt, expiration)

	if signError != nil {
		t.Errorf("test failed due to signing error %v", err)
	}

	_, validateError := validateJWT([]byte("Junk.jwt.isbad"), publicKeySet, issuer, audience)

	expectError("failed to parse token data as JWS message: failed to parse JOSE headers: invalid character '&' looking for beginning of value", validateError, t)
}
