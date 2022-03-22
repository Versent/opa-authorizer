package main

// doesnt appear to be in aws package
// issue open https://github.com/aws/aws-lambda-go/pull/399
type APIGatewayCustomAuthorizerRequestV2 struct {
	Version               string            `json:"version"`
	Type                  string            `json:"type"`
	RouteArn              string            `json:"routeArn"`
	IdentitySource        []string          `json:"identitySource"`
	RouteKey              string            `json:"routeKey"`
	RawPath               string            `json:"rawPath"`
	RawQueryString        string            `json:"rawQueryString"`
	Cookies               []string          `json:"cookies"`
	Headers               map[string]string `json:"headers"`
	MethodArn             string            `json:"methodArn"`
	QueryStringParameters map[string]string `json:"queryStringParameters"`
	RequestContext        struct {
		AccountID      string `json:"accountId"`
		APIID          string `json:"apiId"`
		Authentication struct {
			ClientCert struct {
				ClientCertPem string `json:"clientCertPem"`
				SubjectDN     string `json:"subjectDN"`
				IssuerDN      string `json:"issuerDN"`
				SerialNumber  string `json:"serialNumber"`
				Validity      struct {
					NotBefore string `json:"notBefore"`
					NotAfter  string `json:"notAfter"`
				} `json:"validity"`
			} `json:"clientCert"`
		} `json:"authentication"`
		DomainName   string `json:"domainName"`
		DomainPrefix string `json:"domainPrefix"`
		HTTP         struct {
			Method    string `json:"method"`
			Path      string `json:"path"`
			Protocol  string `json:"protocol"`
			SourceIP  string `json:"sourceIp"`
			UserAgent string `json:"userAgent"`
		} `json:"http"`
		RequestID string `json:"requestId"`
		RouteKey  string `json:"routeKey"`
		Stage     string `json:"stage"`
		Time      string `json:"time"`
		TimeEpoch int64  `json:"timeEpoch"`
	} `json:"requestContext"`
	PathParameters map[string]string `json:"pathParameters"`
	StageVariables map[string]string `json:"stageVariables"`
}
