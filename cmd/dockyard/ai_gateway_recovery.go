package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/GhaziBenDahmane/Orka/internal/aigatewayrecovery"
)

func verifyAIGatewayRecoveryManifest(arguments []string) error {
	flags := flag.NewFlagSet("verify-ai-gateway-recovery-manifest", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	manifestPath := flags.String("manifest", "", "signed recovery manifest")
	signaturePath := flags.String("signature", "", "raw Ed25519 signature")
	publicKeyPath := flags.String("public-key-file", "", "Ed25519 verification key")
	encryptionKeyPath := flags.String("encryption-key-file", "", "backup encryption key")
	expected := aigatewayrecovery.Expected{}
	flags.StringVar(&expected.Stack, "stack", "", "expected Swarm stack")
	flags.StringVar(&expected.Service, "service", "", "expected 9Router service")
	flags.StringVar(&expected.Volume, "volume", "", "expected 9Router volume")
	flags.StringVar(&expected.StorageNodeID, "storage-node", "", "expected storage node")
	flags.StringVar(&expected.RouterImage, "router-image", "", "expected 9Router image")
	flags.StringVar(&expected.HelperImage, "helper-image", "", "expected Dockyard helper image")
	flags.StringVar(&expected.ObjectRef, "object-ref", "", "expected durable object reference")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *manifestPath == "" || *signaturePath == "" || *publicKeyPath == "" || *encryptionKeyPath == "" {
		return errors.New("usage: dockyard verify-ai-gateway-recovery-manifest --manifest PATH --signature PATH --public-key-file PATH --encryption-key-file PATH --stack NAME --service NAME --volume NAME --storage-node ID --router-image IMAGE --helper-image IMAGE --object-ref REF")
	}
	manifestData, err := aigatewayrecovery.ReadRegularFile(*manifestPath, aigatewayrecovery.MaxManifestBytes)
	if err != nil {
		return err
	}
	signature, err := aigatewayrecovery.ReadRegularFile(*signaturePath, aigatewayrecovery.MaxSignatureBytes)
	if err != nil {
		return err
	}
	publicKey, err := aigatewayrecovery.ReadRegularFile(*publicKeyPath, aigatewayrecovery.MaxKeyBytes)
	if err != nil {
		return err
	}
	encryptionKey, err := aigatewayrecovery.ReadRegularFile(*encryptionKeyPath, aigatewayrecovery.MaxKeyBytes)
	if err != nil {
		return err
	}
	defer clear(encryptionKey)
	manifest, err := aigatewayrecovery.Verify(manifestData, signature, publicKey, encryptionKey, expected, time.Now())
	if err != nil {
		return fmt.Errorf("verify AI gateway recovery manifest: %w", err)
	}
	return json.NewEncoder(os.Stdout).Encode(manifest)
}
