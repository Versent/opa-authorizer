# Open Policy Agent Spike

Open Policy Agent Authentication Lambda Authorizer

based on 
https://aws.amazon.com/blogs/opensource/creating-a-custom-lambda-authorizer-using-open-policy-agent/

## Structure
```
|-- .
    |-- bin # CDK entry
    |-- cdk.out
    |-- function # Go entry point
    |   |-- .gitignore
    |   |-- go.mod
    |   |-- go.sum
    |   |-- main.go # Go handler in here
    |   |-- data
    |       |-- data.json # dummy data for OPA
    |       |-- policies.rego # dummy rego policies
    |-- lib
    |   |-- opa-authorizer-stack.ts
    |-- test
        |-- opa-authorizer.test.ts
```
## Open Policy Agent Integration

Achieved via go library `github.com/open-policy-agent/opa`

### OPA Policies

Written in rego, and contained in `./function/data/policies.rego`.

Rego is a domain specific language for specifying polices

### OPA Data

Runtime data provided to OPA to allow dynamic decision making, typically this would be updated from an external datasource in this example its just a json file `data.json`

## Deployment 

Built using CDK v1 

```bash
npm run deploy  # Using currently active creds
npx cdk deploy --profile <profile> # specific profile
```


