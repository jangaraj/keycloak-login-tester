# keycloak-login-tester
CLI utility to test Open ID Connect Grant Code flow login (with optional TOTP)

Quick run:
```
$ go get github.com/jangaraj/keycloak-login-tester
$ keycloak-login-tester --config config.yaml
```

Config option:
```
$ go run main.go help
NAME:
   keycloak-login-tester - CLI tool to inspect Keycloak grant code login flow

USAGE:
   keycloak-login-tester [options]

VERSION:
   alpha

AUTHOR:
   Monitoring Artist / Jan Garaj <info@monitoringartist.com>

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --config value                             path the a configuration file [$TESTER_CONFIG_FILE]
   --discovery-url value                      discovery url to retrieve the openid configuration [$TESTER_DISCOVERY_URL]
   --client-id value                          client id used to authenticate to the oauth service [$TESTER_CLIENT_ID]
   --client-secret value                      client secret used to authenticate to the oauth service [$TESTER_CLIENT_SECRET]
   --client-redirect-url value                redirect url, which is allowed in the client redirect URI configuration [$TESTER_CLIENT_REDIRECT_URL]
   --client-scope value                       client scope used to authenticate to the oauth service (default: "openid email profile") [$TESTER_CLIENT_SCOPE]
   --username value                           user login [$TESTER_USERNAME]
   --password value                           user password, if not defined it is requested from stdin [$TESTER_PASSWORD]
   --client-timeout value                     covers the entire exchange, from Dial (if a connection is not reused) to reading the body (default: 1m0s)
   --transport-response-header-timeout value  limits the time spent reading the headers of the response (default: 5s)
   --help, -h                                 show help
   --version, -v                              print the version
```

Example:
```
$ cat config.yaml
discovery-url: https://play.monitoringartist.com/auth/realms/ad/.well-known/openid-configuration
client-id: aaa
client-secret: 2579c5e1-b4bf-4ac4-9fd1-323812ee99ec
client-redirect-url: https://redirecturl.com/
username: jan
password: jan

$ go run main.go --config config.yaml
DEBUG: authUrl: https://play.monitoringartist.com/auth/realms/ad/protocol/openid-connect/auth?client_id=aaa&redirect_uri=https%3A%2F%2Fredirecturl.com%2F&response_type=code&scope=openid+email+profile&state=Lw%3D%3D
DEBUG: postUrl: https://play.monitoringartist.com/auth/realms/ad/login-actions/authenticate?session_code=n0Q2l2adyNNOmQBjn2QcJB0D9lvNnpQ17BPnS9_6fvE&execution=7828c028-8697-4426-9b9b-936ab6a24b71&client_id=aaa&tab_id=KjIpq7ZRsH8
DEBUG: codeUrl: https://redirecturl.com/?state=Lw%3D%3D&session_state=e21cb442-6c19-47a7-b262-d76c4fc0a34c&code=3ba24b59-208b-424c-a85a-d9e69455f86b.e21cb442-6c19-47a7-b262-d76c4fc0a34c.c019941f-51b3-4f4a-8150-29c365eeaaf4
DEBUG: code: 3ba24b59-208b-424c-a85a-d9e69455f86b.e21cb442-6c19-47a7-b262-d76c4fc0a34c.c019941f-51b3-4f4a-8150-29c365eeaaf4
DEBUG: code to token request duration: 142.678658ms
ID token:
{
  "acr": "1",
  "aud": "aaa",
  "auth_time": 1583691974,
  "azp": "aaa",
  "email": "jan.garaj@gmail.com",
  "email_verified": true,
  "exp": 1583692274,
  "family_name": "Garaj",
  "given_name": "Jan",
  "iat": 1583691974,
  "iss": "https://play.monitoringartist.com/auth/realms/ad",
  "jti": "828669ee-86b4-43d7-b571-683de08731ab",
  "name": "Jan Garaj",
  "nbf": 0,
  "preferred_username": "jan",
  "session_state": "e21cb442-6c19-47a7-b262-d76c4fc0a34c",
  "sub": "0906067d-7eb9-46c4-9e26-cf5677ba9772",
  "typ": "ID"
}
Access token:
{
  "acr": "1",
  "aud": "account",
  "auth_time": 1583691974,
  "azp": "aaa",
  "email": "jan.garaj@gmail.com",
  "email_verified": true,
  "exp": 1583692274,
  "family_name": "Garaj",
  "given_name": "Jan",
  "iat": 1583691974,
  "iss": "https://play.monitoringartist.com/auth/realms/ad",
  "jti": "7d8426f2-9413-4965-b0b6-b57002e2d141",
  "name": "Jan Garaj",
  "nbf": 0,
  "preferred_username": "jan",
  "realm_access": {
    "roles": [
      "offline_access",
      "uma_authorization"
    ]
  },
  "resource_access": {
    "account": {
      "roles": [
        "manage-account",
        "manage-account-links",
        "view-profile"
      ]
    }
  },
  "scope": "openid profile email",
  "session_state": "e21cb442-6c19-47a7-b262-d76c4fc0a34c",
  "sub": "0906067d-7eb9-46c4-9e26-cf5677ba9772",
  "typ": "Bearer"
}
```
