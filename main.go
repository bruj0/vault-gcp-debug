package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/vault/sdk/helper/useragent"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

const (
	serviceAccountMaxLen             = 30
	serviceAccountDisplayNameHashLen = 8
	serviceAccountDisplayNameMaxLen  = 100
	serviceAccountDisplayNameTmpl    = "Service account for Vault secrets backend role set %s"
)

type StringSet map[string]struct{}

type ResourceBindings map[string]StringSet

type TokenGenerator struct {
	KeyName    string
	B64KeyJSON string

	Scopes []string
}

type RoleSet struct {
	Name       string
	SecretType string

	RawBindings string
	Bindings    ResourceBindings

	AccountId *gcputil.ServiceAccountId
	TokenGen  *TokenGenerator
}

func roleSetServiceAccountName(rsName string) (name string) {
	// Sanitize role name
	reg := regexp.MustCompile("[^a-zA-Z0-9-]+")
	rsName = reg.ReplaceAllString(rsName, "-")

	intSuffix := fmt.Sprintf("%d", time.Now().Unix())
	fullName := fmt.Sprintf("vault%s-%s", rsName, intSuffix)
	name = fullName
	if len(fullName) > serviceAccountMaxLen {
		toTrunc := len(fullName) - serviceAccountMaxLen
		name = fmt.Sprintf("vault%s-%s", rsName[:len(rsName)-toTrunc], intSuffix)
	}
	return name
}
func HTTPClient() (*http.Client, error) {
	creds, err := credentials()
	if err != nil {
		return nil, fmt.Errorf("Error from credentials(): {{%s}}", err)
	}

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, cleanhttp.DefaultClient())

	client := oauth2.NewClient(ctx, creds.TokenSource)

	return client, nil
}
func credentials() (*google.Credentials, error) {
	//b.Logger().Debug("loading credentials")

	ctx := context.Background()

	dat, err := ioutil.ReadFile("sa.json")
	if err != nil {
		panic(err)
	}

	var obj map[string]interface{}
	json.Unmarshal([]byte(dat), &obj)
	obj["private_key"] = "<REMOVED>"
	fmt.Printf("raw SA=%s", spew.Sdump(obj))

	//fmt.Printf("raw SA=%s", dat)

	// Get creds from the config
	credBytes := []byte(dat)

	// If credentials were provided, use those. Otherwise fall back to the
	// default application credentials.
	var creds *google.Credentials
	if len(credBytes) > 0 {
		creds, err = google.CredentialsFromJSON(ctx, credBytes, iam.CloudPlatformScope)
		fmt.Printf("* Got credentials from file\n")
		if err != nil {
			return nil, errwrap.Wrapf("failed to parse credentials: {{err}}", err)
		}
	} else {
		creds, err = google.FindDefaultCredentials(ctx, iam.CloudPlatformScope)
		fmt.Printf("* Got credentials from default source\n")
		if err != nil {
			return nil, errwrap.Wrapf("failed to get default credentials: {{err}}", err)
		}
	}

	return creds, err

	// if err != nil {
	// 	return nil, err
	// }
	// return creds.(*google.Credentials), nil
}

// IAMAdminClient returns a new IAM client. The client is cached.
func IAMAdminClient() (*iam.Service, error) {
	httpClient, err := HTTPClient()
	if err != nil {
		return nil, errwrap.Wrapf("failed to create IAM HTTP client: {{err}}", err)
	}

	client, err := iam.NewService(context.Background(), option.WithHTTPClient(httpClient))
	if err != nil {
		return nil, errwrap.Wrapf("failed to create IAM client: {{err}}", err)
	}
	client.UserAgent = useragent.String()

	return client, nil
}
func roleSetServiceAccountDisplayName(name string) string {
	fullDisplayName := fmt.Sprintf(serviceAccountDisplayNameTmpl, name)
	displayName := fullDisplayName
	if len(fullDisplayName) > serviceAccountDisplayNameMaxLen {
		truncIndex := serviceAccountDisplayNameMaxLen - serviceAccountDisplayNameHashLen
		h := fmt.Sprintf("%x", sha256.Sum256([]byte(fullDisplayName[truncIndex:])))
		displayName = fullDisplayName[:truncIndex] + h[:serviceAccountDisplayNameHashLen]
	}
	return displayName
}

func main() {

	configPath := flag.String("sa-key", "", "Path to the json file for the service account")
	project := flag.String("project", "rodrigo-support", "Project name in GCP")
	rsName := flag.String("role", "march11test", "Roleset name")
	flag.Parse()

	if *configPath == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	fmt.Printf("Starting------------\n")
	spew.Config = spew.ConfigState{Indent: "\t"}

	//rsName := "march11test"
	displayName := roleSetServiceAccountDisplayName(*rsName)

	fmt.Printf("IAMAdminClient called------------\n")
	iamAdmin, err := IAMAdminClient()
	if err != nil {
		panic(err)
	}
	//project := "rodrigo-support"
	projectName := fmt.Sprintf("projects/%s", *project)
	saEmailPrefix := roleSetServiceAccountName(*rsName)

	fmt.Printf("* Data gathered:\n")
	fmt.Printf("* Project:%s\n", *project)
	fmt.Printf("* ProjectName:%s\n", projectName)
	fmt.Printf("* saEmailPrefix:%s\n", saEmailPrefix)
	fmt.Printf("* displayName:%s\n", displayName)

	fmt.Printf("---------------------------\n\n")
	call := iamAdmin.Projects.ServiceAccounts.Create(
		projectName, &iam.CreateServiceAccountRequest{
			AccountId:      saEmailPrefix,
			ServiceAccount: &iam.ServiceAccount{DisplayName: displayName},
		})
	fmt.Printf("call=%s\n", spew.Sdump(call))
	fmt.Printf("---------------------------\n\n")

	sa, err := call.Do()
	fmt.Printf("sa=%s\n", spew.Sdump(sa))
	fmt.Printf("---------------------------\n\n")

	if err != nil {
		fmt.Printf("ERROR=%s\n", err)
	}
	fmt.Printf("---------------------------\n\n")
}
