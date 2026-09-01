package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/GhaziBenDahmane/Orka/internal/controlplanerecovery"
)

func verifyControlPlaneRecoveryManifest(arguments []string) error {
	flags := flag.NewFlagSet("verify-control-plane-recovery-manifest", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	manifestPath := flags.String("manifest", "", "signed recovery manifest")
	signaturePath := flags.String("signature", "", "raw Ed25519 signature")
	publicKeyPath := flags.String("public-key-file", "", "Ed25519 verification key")
	masterKeyPath := flags.String("master-key-file", "", "decoded 32-byte master key")
	agentCACertificatePath := flags.String("agent-ca-certificate-file", "", "optional agent CA certificate")
	agentCAKeyPath := flags.String("agent-ca-key-file", "", "optional matching agent CA private key")
	expected := controlplanerecovery.Expected{}
	flags.StringVar(&expected.Stack, "stack", "", "expected Swarm stack")
	flags.StringVar(&expected.Database, "database", "", "expected PostgreSQL database")
	flags.StringVar(&expected.ControllerImage, "controller-image", "", "expected controller image")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *manifestPath == "" || *signaturePath == "" || *publicKeyPath == "" || *masterKeyPath == "" {
		return errors.New("usage: dockyard verify-control-plane-recovery-manifest --manifest PATH --signature PATH --public-key-file PATH --master-key-file PATH [--agent-ca-certificate-file PATH --agent-ca-key-file PATH] --stack NAME --database NAME --controller-image IMAGE")
	}
	if (*agentCACertificatePath == "") != (*agentCAKeyPath == "") {
		return errors.New("agent CA certificate and private key files must be configured together")
	}
	manifestData, err := controlplanerecovery.ReadRegularFile(*manifestPath, controlplanerecovery.MaxManifestBytes)
	if err != nil {
		return err
	}
	signature, err := controlplanerecovery.ReadRegularFile(*signaturePath, controlplanerecovery.MaxSignatureBytes)
	if err != nil {
		return err
	}
	publicKey, err := controlplanerecovery.ReadRegularFile(*publicKeyPath, controlplanerecovery.MaxKeyBytes)
	if err != nil {
		return err
	}
	masterKey, err := controlplanerecovery.ReadRegularFile(*masterKeyPath, controlplanerecovery.MasterKeyBytes)
	if err != nil {
		return err
	}
	defer clear(masterKey)
	var agentCACertificate, agentCAKey []byte
	if *agentCACertificatePath != "" {
		agentCACertificate, err = controlplanerecovery.ReadRegularFile(*agentCACertificatePath, controlplanerecovery.MaxKeyBytes)
		if err != nil {
			return err
		}
		agentCAKey, err = controlplanerecovery.ReadRegularFile(*agentCAKeyPath, controlplanerecovery.MaxKeyBytes)
		if err != nil {
			return err
		}
		defer clear(agentCAKey)
	}
	manifest, err := controlplanerecovery.Verify(manifestData, signature, publicKey, masterKey, agentCACertificate, agentCAKey, expected, time.Now())
	if err != nil {
		return fmt.Errorf("verify control-plane recovery manifest: %w", err)
	}
	return json.NewEncoder(os.Stdout).Encode(manifest)
}
