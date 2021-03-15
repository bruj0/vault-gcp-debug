# vault-gcp-debug
This utility will print debugging information and try to create a service account key in GCP.

It uses the same logic as HashiCorp Vault's secret engine for GCP and its meant to be used to debug it.

https://github.com/hashicorp/vault-plugin-secrets-gcp


## Usage
```
$ ./vault-gcp-debug
  -project string
     Project name in GCP (default "rodrigo-support")
  -role string
     Roleset name (default "march11test")
  -sa-key string
     Path to the json file for the service account
```