package testopa

default allow = false

allow {
    # this policy only lets me in ;)
    claims.username == "kroum"
    input.path == "/bing"
    input.method == "GET"
}

allow {
	# this one only lets tom in :`(
    claims.username == "tom"
    input.path == "/google"
    input.method == "GET"
}

claims := payload {


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