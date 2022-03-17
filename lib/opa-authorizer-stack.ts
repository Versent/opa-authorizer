import * as cdk from "@aws-cdk/core";
import * as apigwv2 from "@aws-cdk/aws-apigatewayv2";
import * as authorizers from "@aws-cdk/aws-apigatewayv2-authorizers";
import * as integrations from "@aws-cdk/aws-apigatewayv2-integrations";
import * as lambda from "@aws-cdk/aws-lambda-go"
import { Runtime } from "@aws-cdk/aws-lambda"

import * as path from 'path'


export class OpaAuthorizerStack extends cdk.Stack {
  constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const authHandler = new lambda.GoFunction(this, 'OPAAuthorizerFunc', {
      functionName: 'OPAAuthorizerFunc',
      runtime: Runtime.GO_1_X, 
      entry: path.resolve('function'),
      retryAttempts: 0,
      bundling: {
        commandHooks: {
          beforeBundling: (inputDir, outputDir) => {
            console.log(`Before Bundling ${inputDir} -> ${outputDir}`)
            // adds data folder to bundle
            const dataPath = path.resolve(inputDir, 'data')
            console.log(`Adding data path ${dataPath}`)
            return [`cp -r ${dataPath} ${outputDir}`]
          },

          // required for some reason?
          afterBundling: (inputDir, outputDir) => {
            return []
          }
        }
      }
    })

    const authorizer = new authorizers.HttpLambdaAuthorizer(
      "OPAAuthorizer",
      authHandler,
      {
        responseTypes: [authorizers.HttpLambdaResponseType.SIMPLE], // Define if returns simple and/or iam response
        resultsCacheTtl: cdk.Duration.seconds(0)
      }
    );

    const api = new apigwv2.HttpApi(this, "HttpApi");

    api.addRoutes({
      methods: [apigwv2.HttpMethod.GET],
      integration: new integrations.HttpUrlIntegration(
        "GoogleProxy",
        "https://www.google.com"
      ),
      path: "/proxy",
      authorizer,
    });

    new cdk.CfnOutput(this, 'APIURL', {
      value: api.url!,
    })
  }
}
