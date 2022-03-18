package testopa

default allow = false

allow {
    # this policy only lets me in ;)
    claims.username = "kroum"
    input.path = "/bing"
    input.method = "GET"
}

allow {
	# this one only lets tom in :`(
    claims.username == "tom"
    input.path = "/google"
    input.method = "GET"
}

claims := payload {
	# Verify the signature on the Bearer token. In this example the secret is
	# hardcoded into the policy however it could also be loaded via data or
	# an environment variable. Environment variables can be accessed using
	# the `opa.runtime()` built-in function.
	# io.jwt.verify_hs256(bearer_token, "B41BD5F462719C6D6118E673A2389")

	# This statement invokes the built-in function `io.jwt.decode` passing the
	# parsed bearer_token as a parameter. The `io.jwt.decode` function returns an
	# array:
	#
	#	[header, payload, signature]
	#
	# In Rego, you can pattern match values using the `=` and `:=` operators. This
	# example pattern matches on the result to obtain the JWT payload.
	[_, payload, _] := io.jwt.decode(input.token)
}