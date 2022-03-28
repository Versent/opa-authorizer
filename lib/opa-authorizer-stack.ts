import * as cdk from "@aws-cdk/core";
import * as apigwv2 from "@aws-cdk/aws-apigatewayv2";
import * as authorizers from "@aws-cdk/aws-apigatewayv2-authorizers";
import * as integrations from "@aws-cdk/aws-apigatewayv2-integrations";
import * as lambda from "@aws-cdk/aws-lambda-go"
import * as cognito from "@aws-cdk/aws-cognito"
import { Runtime } from "@aws-cdk/aws-lambda"

import * as path from 'path'

export class OpaAuthorizerStack extends cdk.Stack {
  constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // creates user pool for test
    const userPool = new cognito.UserPool(this, 'OPATestUserPool', {
      userPoolName: 'opa-userpool',
      removalPolicy: cdk.RemovalPolicy.DESTROY // allows easy cleanup, dont recommend for production
    });
    const domain = userPool.addDomain('opa-userpool-test-domain', {cognitoDomain: {domainPrefix: 'versent-opa-test'}})
    new cdk.CfnOutput(this, 'UserPoolLoginEndPoint', {
      value: `https://${domain.domainName}.auth.${domain.stack.region}.amazoncognito.com/login`
    })
    new cdk.CfnOutput(this, 'UserPoolTokenEndPoint', {
      value: `https://${domain.domainName}.auth.${domain.stack.region}.amazoncognito.com/token`
    })

    const idpDomain = `https://cognito-idp.${props?.env?.region}.amazonaws.com/${userPool.userPoolId}`
    new cdk.CfnOutput(this, 'UserPoolPublicKey', {
      value: `${idpDomain}/.well-known/jwks.json`
    })

    // app client allowing postman to get JWT token
    const appClient = userPool.addClient('opa-app-client', {
      userPoolClientName: 'opa-app-client',
      accessTokenValidity: cdk.Duration.hours(24), // large value for testing dont recommend this for prod
      oAuth: {
        flows: {
          authorizationCodeGrant: true
        },
        scopes: [cognito.OAuthScope.OPENID],
        // postman + local
        callbackUrls: ["http://localhost", "https://oauth.pstmn.io/v1/callback"]
      }
    });
    const clientId = appClient.userPoolClientId;
    new cdk.CfnOutput(this, 'ClientIdOutput', {
      value: clientId
    })

    const authHandler = new lambda.GoFunction(this, 'OPAAuthorizerFunc', {
      functionName: 'OPAAuthorizerFunc',
      runtime: Runtime.GO_1_X, 
      entry: path.resolve('function'),
      retryAttempts: 0,
      environment: {
        ISSUER: idpDomain,
        AUDIENCE: appClient.userPoolClientId,
        LOG_LEVEL: 'INFO'
      },
      bundling: {
        commandHooks: {
          beforeBundling: (inputDir, outputDir) => {
            console.log(`Before Bundling ${inputDir} -> ${outputDir}`)
            // adds data folder to bundle
            const dataPath = path.resolve(inputDir, 'data')
            const keyPath = path.resolve(inputDir, 'keys')
            console.log(`Adding data path ${dataPath}`)
            return [`cp -r ${dataPath} ${outputDir}`, `cp -r ${keyPath} ${outputDir}`]
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
        resultsCacheTtl: cdk.Duration.seconds(0),
      }
    );

    // dummy api for testing
    const api = new apigwv2.HttpApi(this, "HttpApi");

    // two endpoints to play with
    api.addRoutes({
      methods: [apigwv2.HttpMethod.GET],
      integration: new integrations.HttpUrlIntegration(
        "GoogleProxy",
        "https://www.google.com"
      ),
      path: "/google",
      authorizer,
    });

    api.addRoutes({
      methods: [apigwv2.HttpMethod.GET],
      integration: new integrations.HttpUrlIntegration(
        "BingProxy",
        `https://www.bing.com`,
      ),
      path: '/bing',
      authorizer
    })

    new cdk.CfnOutput(this, 'APIURL', {
      value: api.url!,
    })
  }
}
