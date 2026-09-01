package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var routePattern = regexp.MustCompile(`"(GET|POST|PUT|PATCH|DELETE) (/[^" ]+)"`)
var parameterPattern = regexp.MustCompile(`\{([^}]+)\}`)

type operation struct{ method, path string }

func main() {
	root, err := repositoryRoot()
	if err != nil {
		panic(err)
	}
	files := []string{"server.go", "clusters.go"}
	byPath := map[string][]operation{}
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(root, "internal", "httpapi", name))
		if err != nil {
			panic(err)
		}
		for _, match := range routePattern.FindAllSubmatch(data, -1) {
			op := operation{method: strings.ToLower(string(match[1])), path: string(match[2])}
			if !isAPIPath(op.path) {
				continue
			}
			byPath[op.path] = append(byPath[op.path], op)
		}
	}
	paths := make([]string, 0, len(byPath))
	for path := range byPath {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var output bytes.Buffer
	output.WriteString(`openapi: 3.1.0
info:
  title: Dockyard API
  version: 0.1.0
  description: Generated route contract for the Dockyard Compose-on-Swarm control plane.
servers:
  - url: http://localhost:8080
security:
  - bearerAuth: []
paths:
`)
	for _, path := range paths {
		fmt.Fprintf(&output, "  %s:\n", path)
		operations := byPath[path]
		sort.Slice(operations, func(i, j int) bool { return operations[i].method < operations[j].method })
		for _, op := range operations {
			fmt.Fprintf(&output, "    %s:\n      operationId: %s\n      tags: [%s]\n", op.method, operationID(op), tag(op.path))
			if isPublic(op.path) {
				output.WriteString("      security: []\n")
			} else if op.path == "/metrics" {
				output.WriteString("      security:\n        - metricsBearer: []\n")
			} else if strings.HasPrefix(op.path, "/v1/agent/") {
				output.WriteString("      security:\n        - mutualTLS: []\n")
			} else if strings.HasPrefix(op.path, "/scim/") {
				output.WriteString("      security:\n        - scimBearer: []\n")
			}
			parameters := parameterPattern.FindAllStringSubmatch(op.path, -1)
			isSCIMList := op.method == "get" && (op.path == "/scim/v2/Users" || op.path == "/scim/v2/Groups")
			isMigrationList := op.method == "get" && op.path == "/v1/migration-resources"
			isNotificationDeliveryList := op.method == "get" && op.path == "/v1/notification-deliveries"
			if len(parameters) > 0 || (op.method == "get" && op.path == "/v1/templates") || isSCIMList || isMigrationList || isNotificationDeliveryList {
				output.WriteString("      parameters:\n")
				for _, parameter := range parameters {
					format := ""
					if isUUIDPathParameter(parameter[1]) {
						format = "\n            format: uuid"
					}
					fmt.Fprintf(&output, "        - name: %s\n          in: path\n          required: true\n          schema:\n            type: string%s\n", parameter[1], format)
				}
				if op.method == "get" && op.path == "/v1/templates" {
					output.WriteString("        - name: limit\n          in: query\n          schema: {type: integer, minimum: 1, maximum: 200, default: 100}\n        - name: cursor\n          in: query\n          schema: {type: string}\n")
				}
				if isSCIMList {
					output.WriteString("        - name: filter\n          in: query\n          schema: {type: string}\n        - name: startIndex\n          in: query\n          schema: {type: integer, minimum: 1, default: 1}\n        - name: count\n          in: query\n          schema: {type: integer, minimum: 0, maximum: 100, default: 100}\n")
				}
				if isMigrationList {
					output.WriteString("        - name: sourceOrganizationId\n          in: query\n          schema: {type: string, maxLength: 255}\n        - name: limit\n          in: query\n          schema: {type: integer, minimum: 1, maximum: 500, default: 250}\n        - name: cursor\n          in: query\n          description: Opaque cursor returned by the previous page. It is bound to the source organization filter.\n          schema: {type: string, maxLength: 8192}\n")
				}
				if isNotificationDeliveryList {
					output.WriteString("        - name: status\n          in: query\n          schema: {type: string, enum: [pending, running, succeeded, failed]}\n        - name: event\n          in: query\n          schema: {type: string}\n        - name: limit\n          in: query\n          schema: {type: integer, minimum: 1, maximum: 200, default: 100}\n")
				}
			}
			if op.method == "post" || op.method == "put" || op.method == "patch" || (op.method == "delete" && op.path == "/v1/auth/mfa") {
				if strings.HasSuffix(op.path, "/artifact-source") {
					output.WriteString("      requestBody:\n        required: true\n        content:\n          multipart/form-data:\n            schema:\n              type: object\n              required: [file]\n              properties:\n                file:\n                  type: string\n                  format: binary\n")
				} else if op.method == "post" && op.path == "/v1/services/{serviceID}/databases" {
					output.WriteString("      requestBody:\n        required: true\n        content:\n          application/json:\n            schema:\n              $ref: '#/components/schemas/LinkedDatabaseCreateInput'\n")
				} else if op.method == "put" && op.path == "/v1/databases/{databaseID}/credentials" {
					output.WriteString("      requestBody:\n        required: true\n        content:\n          application/json:\n            schema:\n              $ref: '#/components/schemas/LinkedDatabaseCredentialsInput'\n")
				} else if op.method == "put" && op.path == "/v1/services/{serviceID}/volume-backup-policies/{volumeName}" {
					output.WriteString("      requestBody:\n        required: true\n        content:\n          application/json:\n            schema:\n              $ref: '#/components/schemas/VolumeBackupPolicyInput'\n")
				} else if op.method == "post" && op.path == "/v1/volume-backups/{backupID}/restore" {
					output.WriteString("      requestBody:\n        required: true\n        content:\n          application/json:\n            schema:\n              $ref: '#/components/schemas/VolumeRestoreRequest'\n")
				} else if op.path == "/v1/migration-resources/verify" {
					output.WriteString("      requestBody:\n        required: true\n        content:\n          application/json:\n            schema:\n              type: object\n              required: [sourceOrganizationId]\n              properties:\n                sourceOrganizationId: {type: string, minLength: 1, maxLength: 255}\n                requireOperational: {type: boolean, default: true}\n                acknowledgements:\n                  type: array\n                  maxItems: 1000\n                  items: {type: string, maxLength: 1024, pattern: '^[^:]+:.+$'}\n")
				} else {
					mediaType := "application/json"
					if strings.HasPrefix(op.path, "/scim/") {
						mediaType = "application/scim+json"
					}
					fmt.Fprintf(&output, "      requestBody:\n        required: false\n        content:\n          %s:\n            schema:\n              type: object\n              additionalProperties: true\n", mediaType)
				}
			}
			output.WriteString("      responses:\n        '2XX':\n")
			if op.method == "post" && op.path == "/v1/migration-resources/verify" {
				output.WriteString("          description: Fail-closed verification report. A successful response may still have ready=false.\n")
			} else {
				output.WriteString("          description: Successful response\n")
			}
			if (op.method == "post" && op.path == "/v1/services/{serviceID}/databases") || (op.method == "put" && op.path == "/v1/databases/{databaseID}/credentials") {
				output.WriteString("          content:\n            application/json:\n              schema:\n                $ref: '#/components/schemas/DatabaseInstance'\n")
			} else if op.method == "get" && op.path == "/v1/database-engines" {
				output.WriteString("          content:\n            application/json:\n              schema:\n                $ref: '#/components/schemas/DatabaseEngineList'\n")
			} else if op.method == "get" && op.path == "/v1/database-backups/{backupID}" {
				output.WriteString("          content:\n            application/json:\n              schema:\n                $ref: '#/components/schemas/DatabaseBackup'\n")
			} else if op.method == "get" && op.path == "/v1/database-restores/{restoreID}" {
				output.WriteString("          content:\n            application/json:\n              schema:\n                $ref: '#/components/schemas/DatabaseRestore'\n")
			} else if op.method == "get" && op.path == "/v1/database-migrations/{migrationID}" {
				output.WriteString("          content:\n            application/json:\n              schema:\n                $ref: '#/components/schemas/DatabaseMigration'\n")
			} else if op.method == "get" && op.path == "/v1/databases/{databaseID}/backups" {
				output.WriteString("          content:\n            application/json:\n              schema:\n                $ref: '#/components/schemas/DatabaseBackupList'\n")
			} else if op.method == "get" && op.path == "/v1/databases/{databaseID}/restores" {
				output.WriteString("          content:\n            application/json:\n              schema:\n                $ref: '#/components/schemas/DatabaseRestoreList'\n")
			} else if op.method == "get" && op.path == "/v1/databases/{databaseID}/migrations" {
				output.WriteString("          content:\n            application/json:\n              schema:\n                $ref: '#/components/schemas/DatabaseMigrationList'\n")
			} else if op.method == "get" && op.path == "/v1/services/{serviceID}/volumes" {
				output.WriteString("          content:\n            application/json:\n              schema:\n                $ref: '#/components/schemas/ServiceVolumeList'\n")
			} else if op.method == "get" && op.path == "/v1/services/{serviceID}/volume-backup-policies" {
				output.WriteString("          content:\n            application/json:\n              schema:\n                $ref: '#/components/schemas/VolumeBackupPolicyList'\n")
			} else if op.method == "put" && op.path == "/v1/services/{serviceID}/volume-backup-policies/{volumeName}" {
				output.WriteString("          content:\n            application/json:\n              schema:\n                $ref: '#/components/schemas/VolumeBackupPolicy'\n")
			} else if op.method == "get" && op.path == "/v1/services/{serviceID}/volume-backups" {
				output.WriteString("          content:\n            application/json:\n              schema:\n                $ref: '#/components/schemas/VolumeBackupList'\n")
			} else if op.method == "post" && op.path == "/v1/services/{serviceID}/volume-backups/{volumeName}" || op.method == "get" && op.path == "/v1/volume-backups/{backupID}" {
				output.WriteString("          content:\n            application/json:\n              schema:\n                $ref: '#/components/schemas/VolumeBackup'\n")
			} else if op.method == "get" && op.path == "/v1/services/{serviceID}/volume-restores" {
				output.WriteString("          content:\n            application/json:\n              schema:\n                $ref: '#/components/schemas/VolumeRestoreList'\n")
			} else if op.method == "post" && op.path == "/v1/volume-backups/{backupID}/restore" || op.method == "get" && op.path == "/v1/volume-restores/{restoreID}" {
				output.WriteString("          content:\n            application/json:\n              schema:\n                $ref: '#/components/schemas/VolumeRestore'\n")
			} else if isMigrationList {
				output.WriteString("          content:\n            application/json:\n              schema:\n                $ref: '#/components/schemas/MigrationResourcePage'\n")
			} else if op.method == "post" && op.path == "/v1/migration-resources/verify" {
				output.WriteString("          content:\n            application/json:\n              schema:\n                $ref: '#/components/schemas/DokployVerification'\n")
			} else if op.method == "get" && op.path == "/v1/templates" {
				output.WriteString("          content:\n            application/json:\n              schema:\n                $ref: '#/components/schemas/TemplateCatalogPage'\n")
			} else if isSCIMList {
				output.WriteString("          content:\n            application/scim+json:\n              schema:\n                $ref: '#/components/schemas/SCIMListResponse'\n")
			} else if strings.HasPrefix(op.path, "/scim/") {
				output.WriteString("          content:\n            application/scim+json:\n              schema:\n                $ref: '#/components/schemas/SCIMResource'\n")
			}
			errorMediaType := "application/json"
			if strings.HasPrefix(op.path, "/scim/") {
				errorMediaType = "application/scim+json"
			}
			errorSchema := "ErrorEnvelope"
			if strings.HasPrefix(op.path, "/scim/") {
				errorSchema = "SCIMError"
			}
			fmt.Fprintf(&output, "        default:\n          description: Structured API error\n          content:\n            %s:\n              schema:\n                $ref: '#/components/schemas/%s'\n", errorMediaType, errorSchema)
		}
	}
	output.WriteString(`components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
    metricsBearer:
      type: http
      scheme: bearer
      description: Dedicated operator token configured with DOCKYARD_METRICS_TOKEN.
    scimBearer:
      type: http
      scheme: bearer
      description: Organization-scoped SCIM provisioning token.
    mutualTLS:
      type: mutualTLS
  schemas:
    LinkedDatabaseCreateInput:
      type: object
      additionalProperties: false
      required: [name, engine, connectionServiceName, password]
      properties:
        name: {type: string, minLength: 1, maxLength: 120}
        engine: {type: string, minLength: 1, maxLength: 64}
        version: {type: string, maxLength: 128}
        connectionServiceName: {type: string, pattern: '^[a-z0-9][a-z0-9_-]{0,62}$'}
        database: {type: string, maxLength: 8192, description: Required by engines with named databases.}
        username: {type: string, maxLength: 8192, description: Required by engines with user identities.}
        password: {type: string, minLength: 1, maxLength: 8192, writeOnly: true}
        port: {type: integer, minimum: 0, maximum: 65535}
    LinkedDatabaseCredentialsInput:
      type: object
      additionalProperties: false
      required: [connectionServiceName, password]
      properties:
        version: {type: string, maxLength: 128}
        connectionServiceName: {type: string, pattern: '^[a-z0-9][a-z0-9_-]{0,62}$'}
        database: {type: string, maxLength: 8192, description: Required by engines with named databases.}
        username: {type: string, maxLength: 8192, description: Required by engines with user identities.}
        password: {type: string, minLength: 1, maxLength: 8192, writeOnly: true}
        port: {type: integer, minimum: 0, maximum: 65535}
    DatabaseInstance:
      type: object
      required: [id, environmentId, composeServiceId, name, slug, engine, version, driverSource, managementKind, config, status, createdAt]
      properties:
        id: {type: string, format: uuid}
        environmentId: {type: string, format: uuid}
        composeServiceId: {type: string, format: uuid}
        name: {type: string}
        slug: {type: string}
        engine: {type: string}
        version: {type: string}
        driverSource: {type: string, enum: [built-in, external, unbound]}
        driverArtifactDigest: {type: string}
        managementKind: {type: string, enum: [managed, compose]}
        connectionServiceName: {type: string}
        storageNodeId: {type: string}
        config: {type: object, additionalProperties: true, description: Non-secret driver metadata.}
        status: {type: string}
        createdAt: {type: string, format: date-time}
    DatabaseBackup:
      type: object
      required: [id, databaseInstanceId, status, artifactValid, format, encrypted, createdAt]
      properties:
        id: {type: string, format: uuid}
        databaseInstanceId: {type: string, format: uuid}
        status: {type: string, enum: [queued, running, succeeded, failed, cancelled]}
        artifactValid: {type: boolean, description: True only when a successful backup has complete metadata required for restore.}
        format: {type: string}
        sizeBytes: {type: integer, format: int64, minimum: 0}
        sha256: {type: string, pattern: '^[a-f0-9]{64}$'}
        encrypted: {type: boolean}
        plaintextSha256: {type: string, pattern: '^[a-f0-9]{64}$'}
        destinationId: {type: string, format: uuid}
        objectKey: {type: string}
        utilityImage: {type: string, pattern: '^.+@sha256:[a-f0-9]{64}$'}
        error: {type: string}
        createdAt: {type: string, format: date-time}
        startedAt: {type: string, format: date-time}
        finishedAt: {type: string, format: date-time}
    DatabaseBackupList:
      type: object
      required: [items]
      properties:
        items:
          type: array
          items: {$ref: '#/components/schemas/DatabaseBackup'}
    DatabaseRestore:
      type: object
      required: [id, databaseBackupId, status, kind, createdAt]
      properties:
        id: {type: string, format: uuid}
        databaseBackupId: {type: string, format: uuid}
        status: {type: string, enum: [queued, running, succeeded, failed, cancelled]}
        kind: {type: string, enum: [manual, drill]}
        utilityImage: {type: string, pattern: '^.+@sha256:[a-f0-9]{64}$'}
        readinessImage: {type: string, pattern: '^.+@sha256:[a-f0-9]{64}$'}
        error: {type: string}
        createdAt: {type: string, format: date-time}
        startedAt: {type: string, format: date-time}
        finishedAt: {type: string, format: date-time}
    DatabaseRestoreList:
      type: object
      required: [items]
      properties:
        items:
          type: array
          items: {$ref: '#/components/schemas/DatabaseRestore'}
    ServiceVolume:
      type: object
      required: [name, dockerName, storageNodeId]
      properties:
        name: {type: string}
        dockerName: {type: string}
        storageNodeId: {type: string}
    ServiceVolumeList:
      type: object
      required: [items]
      properties:
        items:
          type: array
          items: {$ref: '#/components/schemas/ServiceVolume'}
    VolumeBackupPolicyInput:
      type: object
      additionalProperties: false
      required: [destinationId, intervalSeconds, retentionCount, quiesce, enabled]
      properties:
        destinationId: {type: string, format: uuid}
        intervalSeconds: {type: integer, minimum: 900, maximum: 2678400}
        retentionCount: {type: integer, minimum: 1, maximum: 100}
        quiesce: {type: boolean}
        enabled: {type: boolean}
    VolumeBackupPolicy:
      type: object
      required: [id, composeServiceId, volumeName, destinationId, intervalSeconds, retentionCount, quiesce, enabled, nextRunAt, createdAt, updatedAt]
      properties:
        id: {type: string, format: uuid}
        composeServiceId: {type: string, format: uuid}
        volumeName: {type: string}
        destinationId: {type: string, format: uuid}
        intervalSeconds: {type: integer, minimum: 900, maximum: 2678400}
        retentionCount: {type: integer, minimum: 1, maximum: 100}
        quiesce: {type: boolean}
        enabled: {type: boolean}
        nextRunAt: {type: string, format: date-time}
        lastRunAt: {type: string, format: date-time}
        createdAt: {type: string, format: date-time}
        updatedAt: {type: string, format: date-time}
    VolumeBackupPolicyList:
      type: object
      required: [items]
      properties:
        items:
          type: array
          items: {$ref: '#/components/schemas/VolumeBackupPolicy'}
    VolumeBackup:
      type: object
      required: [id, composeServiceId, volumeName, storageNodeId, destinationId, quiesce, status, artifactValid, createdAt]
      properties:
        id: {type: string, format: uuid}
        volumeBackupPolicyId: {type: string, format: uuid}
        composeServiceId: {type: string, format: uuid}
        volumeName: {type: string}
        storageNodeId: {type: string}
        destinationId: {type: string, format: uuid}
        quiesce: {type: boolean}
        status: {type: string, enum: [queued, running, succeeded, failed, cancelled]}
        artifactValid: {type: boolean, description: True only when a successful encrypted backup has complete metadata required for restore.}
        objectKey: {type: string}
        sizeBytes: {type: integer, format: int64, minimum: 0}
        sha256: {type: string, pattern: '^[a-f0-9]{64}$'}
        plaintextSha256: {type: string, pattern: '^[a-f0-9]{64}$'}
        error: {type: string}
        createdAt: {type: string, format: date-time}
        startedAt: {type: string, format: date-time}
        finishedAt: {type: string, format: date-time}
    VolumeBackupList:
      type: object
      required: [items]
      properties:
        items:
          type: array
          items: {$ref: '#/components/schemas/VolumeBackup'}
    VolumeRestoreRequest:
      type: object
      additionalProperties: false
      required: [confirm]
      properties:
        confirm: {type: string, minLength: 1}
        offline: {type: boolean, default: false}
    VolumeRestore:
      type: object
      required: [id, volumeBackupId, offline, status, createdAt]
      properties:
        id: {type: string, format: uuid}
        volumeBackupId: {type: string, format: uuid}
        targetStorageNodeId: {type: string}
        offline: {type: boolean}
        status: {type: string, enum: [queued, running, succeeded, failed, cancelled]}
        error: {type: string}
        createdAt: {type: string, format: date-time}
        startedAt: {type: string, format: date-time}
        finishedAt: {type: string, format: date-time}
    VolumeRestoreList:
      type: object
      required: [items]
      properties:
        items:
          type: array
          items: {$ref: '#/components/schemas/VolumeRestore'}
    DatabaseMigration:
      type: object
      required: [id, databaseInstanceId, sourceKind, sourceId, sourceEngine, sourceVersion, sourceHost, status, createdAt]
      properties:
        id: {type: string, format: uuid}
        databaseInstanceId: {type: string, format: uuid}
        sourceKind: {type: string}
        sourceId: {type: string}
        sourceEngine: {type: string}
        sourceVersion: {type: string}
        sourceHost: {type: string}
        status: {type: string, enum: [queued, running, succeeded, failed, cancelled]}
        sizeBytes: {type: integer, format: int64, minimum: 0}
        sha256: {type: string, pattern: '^[a-f0-9]{64}$'}
        output: {type: string}
        sourceUtilityImage: {type: string, pattern: '^.+@sha256:[a-f0-9]{64}$'}
        targetUtilityImage: {type: string, pattern: '^.+@sha256:[a-f0-9]{64}$'}
        readinessImage: {type: string, pattern: '^.+@sha256:[a-f0-9]{64}$'}
        error: {type: string}
        createdAt: {type: string, format: date-time}
        startedAt: {type: string, format: date-time}
        finishedAt: {type: string, format: date-time}
    DatabaseMigrationList:
      type: object
      required: [items]
      properties:
        items:
          type: array
          items: {$ref: '#/components/schemas/DatabaseMigration'}
    DatabaseEngine:
      type: object
      required: [name, defaultVersion, source, backupCapable, backupExtension]
      properties:
        name: {type: string}
        defaultVersion: {type: string}
        source: {type: string, enum: [built-in, external]}
        artifactDigest: {type: string, pattern: '^sha256:[a-f0-9]{64}$'}
        backupCapable: {type: boolean}
        backupExtension: {type: string}
        persistentConfigKeys:
          type: array
          maxItems: 128
          uniqueItems: true
          items: {type: string, pattern: '^[A-Za-z][A-Za-z0-9_.-]{0,127}$'}
    DatabaseEngineList:
      type: object
      required: [items, backupCapable, engines]
      properties:
        items:
          type: array
          items: {type: string}
        backupCapable:
          type: array
          items: {type: string}
        engines:
          type: array
          items:
            $ref: '#/components/schemas/DatabaseEngine'
    TemplateCatalogPage:
      type: object
      required: [items, nextCursor]
      properties:
        items:
          type: array
          items: {type: object, additionalProperties: true}
        nextCursor: {type: string}
    MigrationResourcePage:
      type: object
      required: [items, nextCursor]
      properties:
        items:
          type: array
          items:
            type: object
            required: [targetOrganizationId, sourceOrganizationId, sourceKind, sourceId, status, metadata, updatedAt]
            properties:
              targetOrganizationId: {type: string, format: uuid}
              sourceOrganizationId: {type: string}
              sourceKind: {type: string}
              sourceId: {type: string}
              targetId: {type: string, format: uuid}
              status: {type: string, enum: [imported, skipped]}
              reason: {type: string}
              metadata: {type: object, additionalProperties: true}
              updatedAt: {type: string, format: date-time}
        nextCursor: {type: string}
    DokployVerification:
      type: object
      required: [ready, targetOrganizationId, sourceOrganizationId, checkedAt, verified, acknowledged, blocked, checks]
      properties:
        ready: {type: boolean}
        targetOrganizationId: {type: string, format: uuid}
        sourceOrganizationId: {type: string}
        checkedAt: {type: string, format: date-time}
        verified: {type: integer, minimum: 0}
        acknowledged: {type: integer, minimum: 0}
        blocked: {type: integer, minimum: 0}
        checks:
          type: array
          items:
            type: object
            required: [sourceKind, sourceId, status]
            properties:
              sourceKind: {type: string}
              sourceId: {type: string}
              targetId: {type: string, format: uuid}
              status: {type: string, enum: [verified, acknowledged, blocked]}
              reason: {type: string}
    SCIMResource:
      type: object
      additionalProperties: true
    SCIMListResponse:
      type: object
      required: [schemas, totalResults, startIndex, itemsPerPage, Resources]
      properties:
        schemas:
          type: array
          items: {type: string}
        totalResults: {type: integer, minimum: 0}
        startIndex: {type: integer, minimum: 1}
        itemsPerPage: {type: integer, minimum: 0, maximum: 100}
        Resources:
          type: array
          items:
            $ref: '#/components/schemas/SCIMResource'
    SCIMError:
      type: object
      required: [schemas, status, detail]
      properties:
        schemas:
          type: array
          items: {type: string}
        status: {type: string}
        detail: {type: string}
    ErrorEnvelope:
      type: object
      required: [error]
      properties:
        error:
          type: object
          required: [code, message]
          properties:
            code: {type: string}
            message: {type: string}
`)
	directory := filepath.Join(root, "api")
	if err := os.MkdirAll(directory, 0755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "openapi.yaml"), output.Bytes(), 0644); err != nil {
		panic(err)
	}
}

func isAPIPath(path string) bool {
	return path == "/healthz" || path == "/readyz" || path == "/metrics" || strings.HasPrefix(path, "/v1/") || strings.HasPrefix(path, "/scim/")
}

func repositoryRoot() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", fmt.Errorf("go.mod not found")
		}
		directory = parent
	}
}

func operationID(op operation) string {
	value := op.method + "_" + strings.Trim(op.path, "/")
	value = strings.NewReplacer("/", "_", "{", "", "}", "", "-", "_").Replace(value)
	return value
}

func tag(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) > 1 && parts[0] == "v1" {
		return parts[1]
	}
	return parts[0]
}

func isPublic(path string) bool {
	if path == "/healthz" || path == "/readyz" || path == "/v1/auth/bootstrap" || path == "/v1/auth/login" || path == "/v1/invitations/accept" || path == "/v1/agent/enroll" || isPublicSCIMDiscovery(path) {
		return true
	}
	return strings.HasPrefix(path, "/v1/auth/sso/") || strings.HasPrefix(path, "/v1/auth/saml/") || strings.HasPrefix(path, "/v1/hooks/")
}

func isPublicSCIMDiscovery(path string) bool {
	return path == "/scim/v2/ServiceProviderConfig" || path == "/scim/v2/Schemas" || strings.HasPrefix(path, "/scim/v2/Schemas/") || path == "/scim/v2/ResourceTypes" || strings.HasPrefix(path, "/scim/v2/ResourceTypes/")
}

func isUUIDPathParameter(name string) bool {
	if name == "schemaID" || name == "resourceTypeID" {
		return false
	}
	return strings.HasSuffix(name, "ID") || strings.HasSuffix(name, "Id")
}
