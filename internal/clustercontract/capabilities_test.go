package clustercontract

import "testing"

func TestValidateEdgeProxyCapability(t *testing.T) {
	capabilities := Baseline()
	capabilities.EdgeProxy = &EdgeProxyCapability{
		Provider: "traefik", ManagementMode: "external", ServiceName: "edge_traefik",
		PublicNetwork: "dockyard-public", DynamicConfigurationMode: "file",
		DynamicConfigurationPath: "/etc/traefik/dynamic", Ready: true, Status: "ready", SupportsCustomCertificates: true,
	}
	if err := Validate(capabilities); err != nil {
		t.Fatal(err)
	}
	capabilities.EdgeProxy.SupportsCustomCertificates = false
	if err := Validate(capabilities); err == nil {
		t.Fatal("expected inconsistent certificate support to be rejected")
	}
}

func TestValidateAllowsNoEdgeProxy(t *testing.T) {
	if err := Validate(Baseline()); err != nil {
		t.Fatal(err)
	}
}
