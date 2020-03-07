package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/antchfx/htmlquery"
	"github.com/fatih/color"
	"github.com/urfave/cli"
	_ "go.uber.org/zap"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/square/go-jose.v2/jwt"
	yaml "gopkg.in/yaml.v2"
)

type Config struct {
	ConfigFile                     string        `json:"config" yaml:"config" usage:"path the a configuration file" env:"CONFIG_FILE"`
	DiscoveryURL                   string        `json:"discovery-url" yaml:"discovery-url" usage:"discovery url to retrieve the openid configuration" env:"DISCOVERY_URL"`
	ClientID                       string        `json:"client-id" yaml:"client-id" usage:"client id used to authenticate to the oauth service" env:"CLIENT_ID"`
	ClientSecret                   string        `json:"client-secret" yaml:"client-secret" usage:"client secret used to authenticate to the oauth service" env:"CLIENT_SECRET"`
	ClientRedirectURL              string        `json:"client-redirect-url" yaml:"client-redirect-url" usage:"redirect url, which is allowed in the client redirect URI configuration" env:"CLIENT_REDIRECT_URL"`
	ClientScope                    string        `json:"client-scope" yaml:"client-scope" usage:"client scope used to authenticate to the oauth service" env:"CLIENT_SCOPE"`
	Username                       string        `json:"username" yaml:"username" usage:"user login" env:"USERNAME"`
	Password                       string        `json:"password" yaml:"password" usage:"user password, if not defined it is requested from stdin" env:"PASSWORD"`
	ClientTimeout                  time.Duration `json:"client-timeout" yaml:"client-timeout" usage:"covers the entire exchange, from Dial (if a connection is not reused) to reading the body" env:"CLIENT_TIMEOUT"`
	TransportResponseHeaderTimeout time.Duration `json:"transport-response-header-timeout" yaml:"transport-response-header-timeout" usage:"limits the time spent reading the headers of the response" env:"TRANSPORT_RESPONSE_HEADER_TIMEOUT"`
}

const (
	prog         = "keycloak-login-tester"
	author       = "Monitoring Artist / Jan Garaj"
	email        = "info@monitoringartist.com"
	description  = "CLI tool to inspect Keycloak grant code login flow"
	durationType = "time.Duration"
	envPrefix    = "TESTER_"
)

func main() {
	//logger, _ := zap.NewProduction()
	//defer logger.Sync()
	//logger.Info("Starting ...")

	config := newDefaultConfig()
	app := cli.NewApp()
	app.Name = prog
	app.Usage = description
	app.Version = "alpha"
	app.Author = author
	app.Email = email
	app.Flags = getCommandLineOptions()
	app.UsageText = "keycloak-login-tester [options]"

	// step: the standard usage message isn't that helpful
	app.OnUsageError = func(context *cli.Context, err error, isSubcommand bool) error {
		fmt.Fprintf(os.Stderr, "[error] invalid options, %s\n", err)
		return err
	}

	// step: set the default action
	app.Action = func(cx *cli.Context) error {
		configFile := cx.String("config")
		// step: do we have a configuration file?
		if configFile != "" {
			if err := readConfigFile(configFile, config); err != nil {
				return printError("unable to read the configuration file: %s, error: %s", configFile, err.Error())
			}
		}

		// step: parse the command line options
		if err := parseCLIOptions(cx, config); err != nil {
			return printError(err.Error())
		}

		// step: validate the configuration
		if err := config.isValid(); err != nil {
			return printError(err.Error())
		}

		//fmt.Printf("%+v\n", config)

		cookieJar, _ := cookiejar.New(nil)
		httpClient := http.Client{
			Timeout: config.ClientTimeout,
			Jar:     cookieJar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		// discovery
		req, err := http.NewRequest(http.MethodGet, config.DiscoveryURL, nil)
		if err != nil {
			color.Red("ERROR: " + err.Error())
			//logger.Fatal("Can't process discovery-url", zap.String("discovery-url", config.DiscoveryURL), zap.Error(err))
			os.Exit(1)
		}
		req.Header.Set("User-Agent", prog)
		res, err := httpClient.Do(req)
		if err != nil {
			//logger.Fatal("Can't process discovery-url", zap.String("discovery-url", config.DiscoveryURL), zap.Error(err))
			color.Red("ERROR: " + err.Error())
			os.Exit(1)
		}
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			color.Red("ERROR: " + err.Error())
			os.Exit(1)
		}
		var result map[string]interface{}
		err = json.Unmarshal(body, &result)
		if err != nil {
			color.Red("ERROR: " + err.Error())
			os.Exit(1)
		}

		// auth
		authUrl := result["authorization_endpoint"].(string) + "?client_id=" + url.QueryEscape(config.ClientID) + "&redirect_uri=" + url.QueryEscape(config.ClientRedirectURL) + "&response_type=code&scope=" + url.QueryEscape(config.ClientScope) + "&state=Lw%3D%3D"
		color.Yellow("DEBUG: authUrl: " + authUrl)
		req, err = http.NewRequest(http.MethodGet, authUrl, nil)
		if err != nil {
			color.Red("ERROR: " + err.Error())
			os.Exit(1)
		}
		req.Header.Set("User-Agent", prog)
		res, err = httpClient.Do(req)
		if err != nil {
			color.Red("ERROR: " + err.Error())
			os.Exit(1)
		}
		body, err = ioutil.ReadAll(res.Body)
		if err != nil {
			color.Red("ERROR: " + err.Error())
			os.Exit(1)
		}
		if res.StatusCode != 200 {
			doc, err := htmlquery.Parse(strings.NewReader(string(body)))
			nodes, err := htmlquery.QueryAll(doc, "//*[@id=\"kc-error-message\"]")
			if err != nil {
				color.Red("ERROR: not a valid XPath for kc-error-message expression")
				os.Exit(1)
			}
			keycloakError := ""
			for _, n := range nodes {
				p := htmlquery.FindOne(n, "//p")
				keycloakError = keycloakError + htmlquery.InnerText(p)
			}
			if keycloakError != "" {
				color.Red("ERROR: Keycloak responds with error for auth URL request: " + keycloakError)
				os.Exit(1)
			}
			color.Red("ERROR: Keycloak responds with error for auth URL request: " + string(body))
			os.Exit(1)
		}

		doc, err := htmlquery.Parse(strings.NewReader(string(body)))
		nodes, err := htmlquery.QueryAll(doc, "//*[@id=\"kc-form-login\"]")
		if err != nil {
			color.Red("ERROR: not a valid XPath for kc-form-login expression")
			os.Exit(1)
		}
		postUrl := ""
		for _, n := range nodes {
			f := htmlquery.FindOne(n, "//form")
			postUrl = postUrl + htmlquery.SelectAttr(f, "action")
		}
		if postUrl == "" {
			color.Red("ERROR: Can't find POST url in auth form")
			os.Exit(1)
		}
		color.Yellow("DEBUG: postUrl: " + postUrl)

		// authentication
		if config.Password == "" {
			fmt.Printf("Please type the user '" + config.Username + "' password: ")
			password, _ := terminal.ReadPassword(0)
			fmt.Println("")
			config.Password = string(password)
		}

		data := url.Values{}
		data.Set("username", config.Username)
		data.Set("password", config.Password)
		req, err = http.NewRequest(http.MethodPost, postUrl, strings.NewReader(data.Encode()))
		if err != nil {
			color.Red("ERROR: " + err.Error())
			os.Exit(1)
		}
		req.Header.Set("User-Agent", prog)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
		res, err = httpClient.Do(req)
		if err != nil {
			color.Red("ERROR: " + err.Error())
			os.Exit(1)
		}
		codeUrl := ""
		for k, v := range res.Header {
			if k == "Location" {
				codeUrl = v[0]
			}
		}
		if codeUrl == "" {
			// maybe TOTP
			//*[@id="username"]
			body, err = ioutil.ReadAll(res.Body)
			if err != nil {
				color.Red("ERROR: " + err.Error())
				os.Exit(1)
			}
			doc, err := htmlquery.Parse(strings.NewReader(string(body)))
			// TOTP test
			nodes, err := htmlquery.QueryAll(doc, "//*[@id=\"username\"]")
			if len(nodes) > 0 {
				input := htmlquery.FindOne(nodes[0], "//input")
				if htmlquery.SelectAttr(input, "name") == "totp" {
					//*[@id="kc-totp-login-form"]
					nodes, err = htmlquery.QueryAll(doc, "//*[@id=\"kc-totp-login-form\"]")
					totpUrl := ""
					if len(nodes) > 0 {
						form := htmlquery.FindOne(nodes[0], "//form")
						totpUrl = htmlquery.SelectAttr(form, "action")
					}
					if totpUrl == "" {
						color.Red("ERROR: TOTP request detected, but can't find totpUrl")
						os.Exit(1)
					}
					// current totp input from stdin
					reader := bufio.NewReader(os.Stdin)
					fmt.Print("Enter current user TOTP code: ")
					totp, _ := reader.ReadString('\n')
					data = url.Values{}
					data.Set("totp", totp)
					req, err = http.NewRequest(http.MethodPost, totpUrl, strings.NewReader(data.Encode()))
					if err != nil {
						color.Red("ERROR: " + err.Error())
						os.Exit(1)
					}
					req.Header.Set("User-Agent", prog)
					req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
					req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
					res, err = httpClient.Do(req)
					if err != nil {
						color.Red("ERROR: " + err.Error())
						os.Exit(1)
					}
					codeUrl = ""
					for k, v := range res.Header {
						if k == "Location" {
							codeUrl = v[0]
						}
					}
					if codeUrl == "" {
						color.Red("ERROR: can't find codeUrl and Keycloak responds with error for post URL request: " + string(body))
						os.Exit(1)
					}
				}
			}

			// ERROR test
			nodes, err = htmlquery.QueryAll(doc, "//*[@id=\"alert\"]")
			if err != nil {
				color.Red("ERROR: can't find codeUrl and not a valid XPath for alertx expression")
				os.Exit(1)
			}
			keycloakError := ""
			for _, n := range nodes {
				span := htmlquery.FindOne(n, "//span")
				keycloakError = keycloakError + htmlquery.InnerText(span)
			}
			keycloakError = strings.Replace(keycloakError, "\n", "", -1)
			space := regexp.MustCompile(`\s+`)
			keycloakError = space.ReplaceAllString(keycloakError, " ")
			if keycloakError != "" {
				color.Red("ERROR: can't find codeUrl and Keycloak responds with error for post URL request: " + keycloakError)
				os.Exit(1)
			}
			color.Red("ERROR: can't find codeUrl and Keycloak responds with error for post URL request: " + string(body))
			os.Exit(1)
		}
		color.Yellow("DEBUG: codeUrl: " + codeUrl)

		//code to token exchange
		u, err := url.Parse(codeUrl)
		if err != nil {
			color.Red("ERROR: " + err.Error())
			os.Exit(1)
		}
		m, _ := url.ParseQuery(u.RawQuery)
		if _, ok := m["code"]; !ok {
			color.Red("ERROR: Can't find code in codeUrl: " + codeUrl)
			os.Exit(1)
		}
		code := m["code"][0]
		color.Yellow("DEBUG: code: " + code)
		data = url.Values{}
		data.Set("client_id", config.ClientID)
		data.Set("client_secret", config.ClientSecret)
		data.Set("code", code)
		data.Set("grant_type", "authorization_code")
		data.Set("redirect_uri", config.ClientRedirectURL)
		req, err = http.NewRequest(http.MethodPost, result["token_endpoint"].(string), strings.NewReader(data.Encode()))
		if err != nil {
			color.Red("ERROR: " + err.Error())
			os.Exit(1)
		}
		req.Header.Set("User-Agent", prog)
		req.Header.Set("Accept", "application/json")
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
		start := time.Now()
		res, err = httpClient.Do(req)
		if err != nil {
			color.Red("ERROR: " + err.Error())
			os.Exit(1)
		}
		color.Yellow("DEBUG: code to token request duration: " + time.Since(start).String())
		body, err = ioutil.ReadAll(res.Body)
		if err != nil {
			color.Red("ERROR: " + err.Error())
			os.Exit(1)
		}
		var tokenResult map[string]interface{}
		err = json.Unmarshal(body, &tokenResult)
		if err != nil {
			color.Red("ERROR: " + err.Error())
			os.Exit(1)
		}
		if val, ok := tokenResult["error"]; ok {
			color.Red("ERROR: Error from token endpoint: " + val.(string) + " (error description: " + tokenResult["error_description"].(string) + ")")
			os.Exit(1)
		}

		// id token
		var claims map[string]interface{}
		token, _ := jwt.ParseSigned(tokenResult["id_token"].(string))
		_ = token.UnsafeClaimsWithoutVerification(&claims)
		color.Cyan("ID token payload:")
		ftoken, _ := json.MarshalIndent(claims, "", "  ")
		fmt.Println(string(ftoken))

		// access token
		token, _ = jwt.ParseSigned(tokenResult["access_token"].(string))
		_ = token.UnsafeClaimsWithoutVerification(&claims)
		color.Cyan("Access token payload:")
		ftoken, _ = json.MarshalIndent(claims, "", "  ")
		fmt.Println(string(ftoken))

		return nil
	}

	app.Run(os.Args)

}

func mergeMaps(dest, source map[string]string) map[string]string {
	for k, v := range source {
		dest[k] = v
	}

	return dest
}

func printError(message string, args ...interface{}) *cli.ExitError {
	return cli.NewExitError(fmt.Sprintf("[error] "+message, args...), 1)
}

func containedIn(value string, list []string) bool {
	for _, x := range list {
		if x == value {
			return true
		}
	}

	return false
}

func decodeKeyPairs(list []string) (map[string]string, error) {
	kp := make(map[string]string)

	for _, x := range list {
		items := strings.Split(x, "=")
		if len(items) != 2 {
			return kp, fmt.Errorf("invalid tag '%s' should be key=pair", x)
		}
		kp[items[0]] = items[1]
	}

	return kp, nil
}

func parseCLIOptions(cx *cli.Context, config *Config) (err error) {
	// step: we can ignore these options in the Config struct
	ignoredOptions := []string{"tag-data", "match-claims", "resources", "headers"}
	// step: iterate the Config and grab command line options via reflection
	count := reflect.TypeOf(config).Elem().NumField()
	for i := 0; i < count; i++ {
		field := reflect.TypeOf(config).Elem().Field(i)
		name := field.Tag.Get("yaml")
		if containedIn(name, ignoredOptions) {
			continue
		}

		if cx.IsSet(name) {
			switch field.Type.Kind() {
			case reflect.Bool:
				reflect.ValueOf(config).Elem().FieldByName(field.Name).SetBool(cx.Bool(name))
			case reflect.String:
				reflect.ValueOf(config).Elem().FieldByName(field.Name).SetString(cx.String(name))
			case reflect.Slice:
				reflect.ValueOf(config).Elem().FieldByName(field.Name).Set(reflect.ValueOf(cx.StringSlice(name)))
			case reflect.Int:
				reflect.ValueOf(config).Elem().FieldByName(field.Name).Set(reflect.ValueOf(cx.Int(name)))
			case reflect.Int64:
				switch field.Type.String() {
				case durationType:
					reflect.ValueOf(config).Elem().FieldByName(field.Name).SetInt(int64(cx.Duration(name)))
				default:
					reflect.ValueOf(config).Elem().FieldByName(field.Name).SetInt(cx.Int64(name))
				}
			}
		}
	}
	return nil
}

func (r *Config) isValid() error {
	if r.DiscoveryURL == "" {
		return errors.New("you have not specified the discovery-url")
	}
	if r.ClientID == "" {
		return errors.New("you have not specified the client-id")
	}
	if r.ClientSecret == "" {
		return errors.New("you have not specified the client-secret")
	}
	if r.ClientRedirectURL == "" {
		return errors.New("you have not specified the client-redirect-url")
	}
	if r.Username == "" {
		return errors.New("you have not specified the username")
	}
	return nil
}

func readConfigFile(filename string, config *Config) error {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	// step: attempt to un-marshal the data
	switch ext := filepath.Ext(filename); ext {
	case "json":
		err = json.Unmarshal(content, config)
	default:
		err = yaml.Unmarshal(content, config)
	}

	return err
}

func newDefaultConfig() *Config {
	var hostnames []string
	if name, err := os.Hostname(); err == nil {
		hostnames = append(hostnames, name)
	}
	hostnames = append(hostnames, []string{"localhost", "127.0.0.1"}...)

	return &Config{
		ClientTimeout:                  60 * time.Second,
		ClientScope:                    "openid email profile",
		TransportResponseHeaderTimeout: 5 * time.Second,
	}
}

func getCommandLineOptions() []cli.Flag {
	defaults := newDefaultConfig()
	var flags []cli.Flag
	count := reflect.TypeOf(Config{}).NumField()
	for i := 0; i < count; i++ {
		field := reflect.TypeOf(Config{}).Field(i)
		usage, found := field.Tag.Lookup("usage")
		if !found {
			continue
		}
		envName := field.Tag.Get("env")
		if envName != "" {
			envName = envPrefix + envName
		}
		optName := field.Tag.Get("yaml")

		switch t := field.Type; t.Kind() {
		case reflect.Bool:
			dv := reflect.ValueOf(defaults).Elem().FieldByName(field.Name).Bool()
			msg := fmt.Sprintf("%s (default: %t)", usage, dv)
			flags = append(flags, cli.BoolTFlag{
				Name:   optName,
				Usage:  msg,
				EnvVar: envName,
			})
		case reflect.String:
			defaultValue := reflect.ValueOf(defaults).Elem().FieldByName(field.Name).String()
			flags = append(flags, cli.StringFlag{
				Name:   optName,
				Usage:  usage,
				EnvVar: envName,
				Value:  defaultValue,
			})
		case reflect.Slice:
			fallthrough
		case reflect.Map:
			flags = append(flags, cli.StringSliceFlag{
				Name:  optName,
				Usage: usage,
			})
		case reflect.Int:
			flags = append(flags, cli.IntFlag{
				Name:   optName,
				Usage:  usage,
				EnvVar: envName,
			})
		case reflect.Int64:
			switch t.String() {
			case durationType:
				dv := reflect.ValueOf(defaults).Elem().FieldByName(field.Name).Int()
				flags = append(flags, cli.DurationFlag{
					Name:  optName,
					Usage: usage,
					Value: time.Duration(dv),
				})
			default:
				panic("unknown uint64 type in the Config struct")
			}
		default:
			errMsg := fmt.Sprintf("field: %s, type: %s, kind: %s is not being handled", field.Name, t.String(), t.Kind())
			panic(errMsg)
		}
	}

	return flags
}
