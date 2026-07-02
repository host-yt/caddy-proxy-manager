// terraform-provider-hpg is the Terraform provider for Hostyt Proxy Gateway.
// It is a thin client over the panel's REST API v1 (see ../docs/TERRAFORM.md).
//
// It lives here as a nested module (its own go.mod) so it builds independently
// of the panel; publishing to the Terraform Registry means splitting this
// directory into a repo named `terraform-provider-hpg` and tagging releases.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/host-yt/terraform-provider-hpg/internal/provider"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/host-yt/hpg",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err.Error())
	}
}
