package main

import (
	"context"
	"os"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

// example of using "github.com/lestrrat-go/jwx/jwk" to validate tokens
// implements best practice validations from AWS https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html#amazon-cognito-user-pools-using-tokens-step-1
func validateJWT(token []byte, keyset jwk.Set, issuer string, audience string) (jwt.Token, error) {

	parsedToken, err := jwt.Parse(
		[]byte(token),
		jwt.WithKeySet(keyset),
		jwt.WithValidate(true),
		jwt.InferAlgorithmFromKey(true),
		jwt.WithIssuer(issuer),
	)

	if err != nil {
		return nil, err
	}

	return parsedToken, nil
}

func fetchKey(region string, userPoolId string) (jwk.Set, error) {
	ctx := context.Background()

	// could be faster if cached this is just for example
	keyset, err := jwk.Fetch(ctx, "https://cognito-idp."+region+".amazonaws.com/"+userPoolId+"/.well-known/jwks.json")

	if err != nil {
		return nil, err
	}

	return keyset, nil
}

func loadKey(path string) (jwk.Key, error) {
	rawKey, err := os.ReadFile("./keys/data.json")

	if err != nil {
		return nil, err
	}

	key, err := jwk.New(rawKey)

	if err != nil {
		return nil, err
	}

	return key, nil
}
