package main

import (
	"context"
	"errors"
	"io/ioutil"
	"log"
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

func printDirs(path string) {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("dir %s", path)

	for _, file := range files {
		log.Println(file.Name(), file.IsDir())
	}
}

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

func handler(request events.APIGatewayCustomAuthorizerRequestTypeRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	log.Println("handler start ")

	path := request.Path
	log.Println("path is = ", path)

	method := request.HTTPMethod
	log.Println("method is = ", method)

	tokenHeader := request.Headers["Authorization"]
	log.Println("tokenHeader is = ", tokenHeader)

	tokens := strings.Split(tokenHeader, " ")
	token := tokens[1]
	log.Println("token is = ", token)

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
	rs, err := rego.Eval(ctx)
	elapsed_eval := time.Since(start_eval)
	log.Println("Evaluation  took ", elapsed_eval)

	if err != nil {
		// Handle error.
	}

	log.Println("Result of query evaluation is = ", rs[0].Expressions[0].Value)
	if rs[0].Expressions[0].Value == true {
		return generatePolicy("user", "Allow", request.MethodArn), nil
	} else {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized")
	}

}

func main() {
	lambda.Start(handler)
}

func generatePolicy(principalID, effect, resource string) events.APIGatewayCustomAuthorizerResponse {
	authResponse := events.APIGatewayCustomAuthorizerResponse{PrincipalID: principalID}

	if effect != "" && resource != "" {
		authResponse.PolicyDocument = events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   effect,
					Resource: []string{resource},
				},
			},
		}
	}

	return authResponse
}
