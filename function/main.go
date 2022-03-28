package main

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/loader"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/sirupsen/logrus"
)

var (
	err      error
	compiler *ast.Compiler
	store    storage.Store
	ctx      = context.Background()
)

func init() {
	policyData, err := loader.All([]string{"data"})
	if err != nil {
		logrus.WithError(err).Fatal("Failed to load bundle from disk")
	}

	// Compile the module. The keys are used as identifiers in error messages.
	compiler, err = policyData.Compiler()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to compile policies in bundle")
	}

	store, err = policyData.Store()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create storage from bundle")
	}
}

func handler(request APIGatewayCustomAuthorizerRequestV2) (events.APIGatewayV2CustomAuthorizerSimpleResponse, error) {
	issuer := os.Getenv("ISSUER")
	audience := os.Getenv("AUDIENCE")
	logLevel := os.Getenv("LOG_LEVEL")

	// set logger defaults
	level, err := logrus.ParseLevel(logLevel)
	if err == nil {
		logrus.SetLevel(level)
	}

	// set json format
	logrus.SetFormatter(&logrus.JSONFormatter{})

	// startup info
	logrus.
		WithField("ISSUER", issuer).
		WithField("AUDIENCE", audience).
		WithField("LOG_LEVEL", logLevel).
		Info("starting")

	logrus.
		WithField("request", request).Info()

	path := request.RawPath
	method := request.RequestContext.HTTP.Method
	tokenHeader := request.Headers["authorization"]
	tokens := strings.Split(tokenHeader, " ")
	token := tokens[1]

	logrus.WithField("path", path).
		WithField("method", method).
		Info("Attempting to validate token")

	keySet, fetchKeyError := fetchKey("ap-southeast-2", "ap-southeast-2_bNwBiXJry")

	if fetchKeyError != nil {
		logrus.WithError(fetchKeyError).Fatal("JWKS fetch error")
		return events.APIGatewayV2CustomAuthorizerSimpleResponse{
			IsAuthorized: false,
		}, nil
	}

	parsedToken, validationError := validateJWT([]byte(token), keySet, issuer, audience)

	if validationError != nil {
		logrus.WithError(validationError).Fatal("JWT validation error")
		return events.APIGatewayV2CustomAuthorizerSimpleResponse{
			IsAuthorized: false,
		}, nil
	}

	logrus.WithField("id", parsedToken.JwtID()).
		WithField("sub", parsedToken.Subject()).
		WithField("exp", parsedToken.Expiration().GoString()).
		WithField("iss", parsedToken.IssuedAt()).
		WithField("aud", parsedToken.Audience()).
		Info("Parse token parameters")

	// Run evaluation.
	start := time.Now()
	// Create a new query that uses the compiled policy from above.
	rego := rego.New(
		rego.Query("data.testopa.allow"), // query the policy
		rego.Compiler(compiler),
		rego.Store(store),
		rego.Input(map[string]interface{}{
			"token":  token,
			"method": method,
			"path":   path,
		}),
	)

	elapsed := time.Since(start)
	logrus.WithField("elapsed_init", elapsed).Info("Rego query initiatized", elapsed)
	start_eval := time.Now()
	// Run evaluation.
	regoResult, err := rego.Eval(ctx)
	elapsed_eval := time.Since(start_eval)
	logrus.WithField("elapsed_eval", elapsed_eval).Info("Rego query evaluated", elapsed_eval)

	if err != nil {
		logrus.WithError(err).Fatal("OPA Evaluation Error")
		return events.APIGatewayV2CustomAuthorizerSimpleResponse{
			IsAuthorized: false,
		}, err
	}

	logrus.WithField("result", regoResult).Info("Rego query result")
	if regoResult[0].Expressions[0].Value == true {
		return events.APIGatewayV2CustomAuthorizerSimpleResponse{
			IsAuthorized: true,
		}, nil
	} else {
		logrus.Info("Unauthorized")
		return events.APIGatewayV2CustomAuthorizerSimpleResponse{
			IsAuthorized: false,
		}, nil
	}

}

func main() {
	lambda.Start(handler)
}
