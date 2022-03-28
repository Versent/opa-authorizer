package main

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/loader"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
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
		log.Fatalf("Failed to load bundle from disk: %v", err)
	}

	// Compile the module. The keys are used as identifiers in error messages.
	compiler, err = policyData.Compiler()
	if err != nil {
		log.Fatalf("Failed to compile policies in bundle: %v", err)
	}

	store, err = policyData.Store()
	if err != nil {
		log.Fatalf("Failed to create storage from bundle: %v", err)
	}
}

func handler(request APIGatewayCustomAuthorizerRequestV2) (events.APIGatewayV2CustomAuthorizerSimpleResponse, error) {
	log.Println("handler start ")

	log.Printf("Request = %+v\n", request)

	path := request.RawPath
	log.Println("path is = ", path)

	method := request.RequestContext.HTTP.Method
	log.Println("method is = ", method)

	tokenHeader := request.Headers["authorization"]
	log.Println("tokenHeader is = ", tokenHeader)

	tokens := strings.Split(tokenHeader, " ")
	token := tokens[1]
	log.Println("token is = ", token)

	log.Println("Attempting to validate token")
	issuer := os.Getenv("ISSUER")
	audience := os.Getenv("AUDIENCE")

	keySet := fetchKey("ap-southeast-2", "ap-southeast-2_bNwBiXJry")

	parsedToken, validationError := validateJWT([]byte(token), keySet, issuer, audience)

	if validationError != nil {
		log.Printf("JWT validation error %s\n", validationError)
		return events.APIGatewayV2CustomAuthorizerSimpleResponse{
			IsAuthorized: false,
		}, nil
	}

	log.Println("id", parsedToken.JwtID())
	log.Println("sub", parsedToken.Subject())
	log.Println("exp", parsedToken.Expiration().GoString())
	log.Println("iss", parsedToken.IssuedAt())

	log.Printf("ParsedToken = %+v\n", parsedToken)

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
	log.Println("Query initiation  took ", elapsed)
	start_eval := time.Now()
	// Run evaluation.
	regoResult, err := rego.Eval(ctx)
	elapsed_eval := time.Since(start_eval)
	log.Println("Evaluation  took ", elapsed_eval)

	if err != nil {
		log.Printf("OPA evaluation Error: %v", err)
		return events.APIGatewayV2CustomAuthorizerSimpleResponse{
			IsAuthorized: false,
		}, err
	}

	// print all vars
	log.Printf("RegoResult = %+v\n", regoResult)

	log.Println("Result of query evaluation is = ", regoResult[0].Expressions[0].Value)
	if regoResult[0].Expressions[0].Value == true {
		return events.APIGatewayV2CustomAuthorizerSimpleResponse{
			IsAuthorized: true,
		}, nil
	} else {
		log.Println("Unauthorized")
		return events.APIGatewayV2CustomAuthorizerSimpleResponse{
			IsAuthorized: false,
		}, nil
	}

}

func main() {
	lambda.Start(handler)
}
