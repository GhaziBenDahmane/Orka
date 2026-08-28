package main

import (
	"context"
	"log"

	"github.com/bendahma/dokploy-go/internal/tfprovider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

var version = "dev"

func main() {
	err := providerserver.Serve(context.Background(), tfprovider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/dockyard/dockyard",
	})
	if err != nil {
		log.Fatal(err)
	}
}
