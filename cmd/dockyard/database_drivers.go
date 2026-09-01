package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"

	"github.com/GhaziBenDahmane/Orka/internal/database"
	"github.com/GhaziBenDahmane/Orka/pkg/databaseplugin"
)

type externalDriverInventory struct {
	ProtocolVersion int                   `json:"protocolVersion"`
	Digest          string                `json:"digest"`
	Drivers         []database.EngineInfo `json:"drivers"`
}

func inspectDatabaseDrivers(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("inspect-database-drivers", flag.ContinueOnError)
	directory := flags.String("directory", "", "absolute directory containing trusted driver executables")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *directory == "" {
		return errors.New("usage: dockyard inspect-database-drivers --directory PATH")
	}
	registry := database.NewRegistry()
	if err := registry.LoadExternal(*directory); err != nil {
		return err
	}
	drivers := make([]database.EngineInfo, 0)
	for _, engine := range registry.Engines() {
		if engine.Source == "external" {
			drivers = append(drivers, engine)
		}
	}
	if len(drivers) == 0 {
		return errors.New("database driver directory contains no trusted executable drivers")
	}
	canonical, err := json.Marshal(drivers)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canonical)
	return json.NewEncoder(output).Encode(externalDriverInventory{
		ProtocolVersion: databaseplugin.ProtocolVersion,
		Digest:          "sha256:" + hex.EncodeToString(digest[:]),
		Drivers:         drivers,
	})
}
