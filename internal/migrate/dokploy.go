package migrate

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/database"
	"github.com/bendahma/dokploy-go/internal/deploy"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DokployOptions struct {
	SourceURL             string
	SourceOrganizationID  string
	TargetOrganizationID  uuid.UUID
	RegistryPrefix        string
	ServerClusterMappings map[string]uuid.UUID
	DryRun                bool
	EncryptionKeys        [][]byte
}

type DokployReport struct {
	DryRun                bool                    `json:"dryRun"`
	Projects              int                     `json:"projects"`
	Environments          int                     `json:"environments"`
	Services              int                     `json:"services"`
	Applications          int                     `json:"applications"`
	Databases             int                     `json:"databases"`
	Routes                int                     `json:"routes"`
	BackupDestinations    int                     `json:"backupDestinations"`
	BackupPolicies        int                     `json:"backupPolicies"`
	SourceCredentials     int                     `json:"sourceCredentials"`
	NotificationEndpoints int                     `json:"notificationEndpoints"`
	Tags                  int                     `json:"tags"`
	ProjectTags           int                     `json:"projectTags"`
	Networks              int                     `json:"networks"`
	ServiceNetworks       int                     `json:"serviceNetworks"`
	Skipped               int                     `json:"skipped"`
	Warnings              []string                `json:"warnings"`
	Resources             []DokployResourceReport `json:"resources"`
}

type DokployResourceReport struct {
	SourceKind string         `json:"sourceKind"`
	SourceID   string         `json:"sourceId"`
	TargetID   *uuid.UUID     `json:"targetId,omitempty"`
	Status     string         `json:"status"`
	Reason     string         `json:"reason,omitempty"`
	Metadata   map[string]any `json:"metadata"`
}

type sourceProject struct{ id, name, description string }
type sourceEnvironment struct{ id, projectID, name string }
type sourceCompose struct {
	id, environmentID, name, appName, compose, env, serverID string
	networks                                                 map[string][]string
}
type sourceTag struct{ id, name, color string }
type sourceProjectTag struct{ id, projectID, tagID string }
type sourceNetwork struct {
	id, name, driver, serverID                   string
	internal, attachable, enableIPv4, enableIPv6 bool
	mtu                                          *int
	ipam                                         []store.NetworkIPAMConfig
}
type sourceDatabase struct {
	id, environmentID, name, appName, sourceEngine, engine     string
	databaseName, databaseUser, databasePassword, rootPassword string
	dockerImage, env, serverID                                 string
	networkIDs                                                 []string
}

func (d sourceDatabase) identityEngine() string {
	if d.sourceEngine != "" {
		return d.sourceEngine
	}
	return d.engine
}

func (d sourceDatabase) identity() string { return d.identityEngine() + ":" + d.id }

func mappedDokployDatabaseID(options DokployOptions, prefix string, item sourceDatabase) uuid.UUID {
	return mappedID(options, prefix+":"+item.identityEngine(), item.id)
}

type targetNetworkAssignment struct {
	sourceID, sourceKind string
	serviceID, networkID uuid.UUID
	serviceNames         []string
}
type sourceRoute struct {
	id, composeID, host, path, internalPath, serviceName, resolver string
	port                                                           int
	tls, enabled, stripPath                                        bool
}

type preparedBackupDestination struct {
	sourceID, key, name, endpoint, region, bucket, prefix string
	id, reportID                                          uuid.UUID
	useTLS                                                bool
	encryptedCredentials                                  string
}

type preparedBackupPolicy struct {
	source                        sourceBackupPolicy
	id, databaseID, destinationID uuid.UUID
	intervalSeconds               int
}

type preparedVolumeBackupPolicy struct {
	source                       sourceVolumeBackupPolicy
	id, serviceID, destinationID uuid.UUID
	volumeName                   string
	intervalSeconds              int
}

func ImportDokploy(ctx context.Context, destination *store.Store, box *cryptox.Box, compiler deploy.Compiler, options DokployOptions) (DokployReport, error) {
	report := DokployReport{DryRun: options.DryRun, Warnings: []string{}}
	if options.SourceURL == "" || options.SourceOrganizationID == "" || options.TargetOrganizationID == uuid.Nil {
		return report, errors.New("source URL, source organization, and target organization are required")
	}
	source, err := pgxpool.New(ctx, options.SourceURL)
	if err != nil {
		return report, fmt.Errorf("open Dokploy database: %w", err)
	}
	defer source.Close()
	if err = source.Ping(ctx); err != nil {
		return report, fmt.Errorf("connect to Dokploy database: %w", err)
	}
	var targetExists bool
	if err = destination.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1)`, options.TargetOrganizationID).Scan(&targetExists); err != nil || !targetExists {
		if err == nil {
			err = store.ErrNotFound
		}
		return report, fmt.Errorf("target organization: %w", err)
	}

	projects, err := readProjects(ctx, source, options.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	environments, err := readEnvironments(ctx, source, options.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	tags, err := readTags(ctx, source, options.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	projectTags, err := readProjectTags(ctx, source, options.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	networks, err := readNetworks(ctx, source, options.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	services, err := readCompose(ctx, source, options.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	routes, err := readRoutes(ctx, source, options.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	applications, err := readApplications(ctx, source, options.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	applicationRoutes, err := readApplicationRoutes(ctx, source, options.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	databases, err := readDatabases(ctx, source, options.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	environmentClusters, err := resolveDokployEnvironmentClusters(ctx, destination, options, environments, services, applications, databases)
	if err != nil {
		return report, err
	}
	report.Projects, report.Environments, report.Services, report.Tags, report.ProjectTags, report.Networks = len(projects), len(environments), len(services), len(tags), len(projectTags), len(networks)
	for _, item := range projects {
		targetID := mappedID(options, "project", item.id)
		report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "project", SourceID: item.id, TargetID: &targetID, Status: "imported", Metadata: map[string]any{"name": item.name}})
	}
	for _, item := range environments {
		targetID := mappedID(options, "environment", item.id)
		metadata := map[string]any{"name": item.name, "projectId": item.projectID}
		if clusterID := environmentClusters[item.id]; clusterID != nil {
			metadata["clusterId"] = clusterID.String()
		}
		report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "environment", SourceID: item.id, TargetID: &targetID, Status: "imported", Metadata: metadata})
	}
	tagIDs := map[string]uuid.UUID{}
	existingTagIDs := map[string]uuid.UUID{}
	rows, queryErr := destination.Pool.Query(ctx, `SELECT lower(name),id FROM tags WHERE organization_id=$1`, options.TargetOrganizationID)
	if queryErr != nil {
		return report, queryErr
	}
	for rows.Next() {
		var name string
		var id uuid.UUID
		if queryErr = rows.Scan(&name, &id); queryErr != nil {
			rows.Close()
			return report, queryErr
		}
		existingTagIDs[name] = id
	}
	if queryErr = rows.Err(); queryErr != nil {
		rows.Close()
		return report, queryErr
	}
	rows.Close()
	seenTagNames := map[string]bool{}
	for _, item := range tags {
		name := strings.TrimSpace(item.name)
		color := normalizeTagColor(item.color)
		metadata := map[string]any{"name": name, "color": color}
		key := strings.ToLower(name)
		if name == "" || len([]rune(name)) > 64 || strings.ContainsAny(name, "\x00\r\n\t") || seenTagNames[key] {
			reason := "tag has an invalid or duplicate case-insensitive name"
			report.Skipped++
			report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "tag", SourceID: item.id, Status: "skipped", Reason: reason, Metadata: metadata})
			continue
		}
		seenTagNames[key] = true
		targetID, exists := existingTagIDs[key]
		if !exists {
			targetID = mappedID(options, "tag", item.id)
		}
		tagIDs[item.id] = targetID
		report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "tag", SourceID: item.id, TargetID: &targetID, Status: "imported", Metadata: metadata})
	}
	for _, item := range projectTags {
		tagID, valid := tagIDs[item.tagID]
		projectID := mappedID(options, "project", item.projectID)
		metadata := map[string]any{"projectId": projectID.String(), "tagId": tagID.String()}
		if !valid {
			report.Skipped++
			report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "project_tag", SourceID: item.id, Status: "skipped", Reason: "tag was not imported", Metadata: metadata})
			continue
		}
		report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "project_tag", SourceID: item.id, TargetID: &tagID, Status: "imported", Metadata: metadata})
	}
	networkIDs := map[string]uuid.UUID{}
	networkDrivers := map[string]string{}
	networkClusters := map[string]*uuid.UUID{}
	existingNetworks, err := destination.ListManagedNetworks(ctx, options.TargetOrganizationID)
	if err != nil {
		return report, err
	}
	existingNetworksByName := map[string]store.ManagedNetwork{}
	existingNetworksByID := map[uuid.UUID]store.ManagedNetwork{}
	for _, item := range existingNetworks {
		existingNetworksByName[managedNetworkScopeKey(item.ClusterID, item.Name)] = item
		existingNetworksByID[item.ID] = item
	}
	for _, item := range networks {
		metadata := map[string]any{"name": item.name, "driver": item.driver, "internal": item.internal, "attachable": item.attachable, "enableIpv4": item.enableIPv4, "enableIpv6": item.enableIPv6, "serverId": item.serverID}
		clusterID, mapped := mappedDokployServer(options, item.serverID)
		if !mapped {
			report.Skipped++
			report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "network", SourceID: item.id, Status: "skipped", Reason: "remote Dokploy server requires an explicit target cluster mapping", Metadata: metadata})
			continue
		}
		if clusterID != nil {
			metadata["clusterId"] = clusterID.String()
		}
		spec := deploy.ManagedNetworkSpec{ID: item.id, Name: item.name, Driver: item.driver, Internal: item.internal, Attachable: item.attachable, EnableIPv4: item.enableIPv4, EnableIPv6: item.enableIPv6, MTU: item.mtu}
		for _, config := range item.ipam {
			spec.IPAM = append(spec.IPAM, deploy.NetworkIPAMConfig{Subnet: config.Subnet, Gateway: config.Gateway, IPRange: config.IPRange})
		}
		if validateErr := deploy.ValidateManagedNetworkSpec(spec); validateErr != nil || item.name == compiler.PublicNetwork {
			reason := "network configuration is invalid"
			if validateErr != nil {
				reason = validateErr.Error()
			}
			report.Skipped++
			report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "network", SourceID: item.id, Status: "skipped", Reason: reason, Metadata: metadata})
			continue
		}
		targetID := mappedID(options, "network", item.id)
		if existing, exists := existingNetworksByID[targetID]; exists && (!sameOptionalUUID(existing.ClusterID, clusterID) || existing.Name != item.name) {
			report.Skipped++
			report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "network", SourceID: item.id, Status: "skipped", Reason: "previous import maps this network to a different target cluster or name", Metadata: metadata})
			continue
		}
		if existing, exists := existingNetworksByName[managedNetworkScopeKey(clusterID, item.name)]; exists {
			if !compatibleImportedNetwork(existing, item) {
				report.Skipped++
				report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "network", SourceID: item.id, Status: "skipped", Reason: "target network with the same name has different settings", Metadata: metadata})
				continue
			}
			targetID = existing.ID
		}
		networkIDs[item.id], networkDrivers[item.id] = targetID, item.driver
		networkClusters[item.id] = clusterID
		report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "network", SourceID: item.id, TargetID: &targetID, Status: "imported", Metadata: metadata})
	}
	networkAssignments := []targetNetworkAssignment{}
	addNetworkAssignment := func(sourceKind, parentSourceID, environmentID string, serviceID uuid.UUID, sourceNetworkID string, serviceNames []string) {
		if serviceNames == nil {
			serviceNames = []string{}
		}
		report.ServiceNetworks++
		sourceID := parentSourceID + ":" + sourceNetworkID
		networkID, valid := networkIDs[sourceNetworkID]
		metadata := map[string]any{"serviceId": serviceID.String(), "networkId": networkID.String(), "serviceNames": serviceNames}
		if !valid || networkDrivers[sourceNetworkID] != "overlay" {
			report.Skipped++
			report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "service_network", SourceID: sourceKind + ":" + sourceID, Status: "skipped", Reason: "network was not imported as an attachable Swarm overlay", Metadata: metadata})
			return
		}
		if !sameOptionalUUID(networkClusters[sourceNetworkID], environmentClusters[environmentID]) {
			report.Skipped++
			report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "service_network", SourceID: sourceKind + ":" + sourceID, Status: "skipped", Reason: "network and workload resolve to different target clusters", Metadata: metadata})
			return
		}
		networkAssignments = append(networkAssignments, targetNetworkAssignment{sourceID: sourceKind + ":" + sourceID, sourceKind: sourceKind, serviceID: serviceID, networkID: networkID, serviceNames: serviceNames})
		report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "service_network", SourceID: sourceKind + ":" + sourceID, TargetID: &networkID, Status: "imported", Metadata: metadata})
	}

	validServices := map[string]bool{}
	for _, service := range services {
		targetID := mappedID(options, "compose", service.id)
		metadata := map[string]any{"name": service.name, "environmentId": service.environmentID, "serverId": service.serverID}
		if strings.TrimSpace(service.compose) == "" {
			report.Skipped++
			report.Warnings = append(report.Warnings, fmt.Sprintf("compose %s has no inline composeFile and was skipped", service.id))
			report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "compose", SourceID: service.id, Status: "skipped", Reason: "no inline composeFile", Metadata: metadata})
			continue
		}
		if _, compileErr := compiler.Compile(service.compose, nil); compileErr != nil {
			report.Skipped++
			report.Warnings = append(report.Warnings, fmt.Sprintf("compose %s is incompatible: %v", service.id, compileErr))
			report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "compose", SourceID: service.id, Status: "skipped", Reason: compileErr.Error(), Metadata: metadata})
			continue
		}
		validServices[service.id] = true
		report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "compose", SourceID: service.id, TargetID: &targetID, Status: "imported", Metadata: metadata})
		for _, networkID := range sortedNetworkIDs(service.networks) {
			serviceNames := service.networks[networkID]
			addNetworkAssignment("compose", service.id, service.environmentID, targetID, networkID, serviceNames)
		}
		if strings.HasPrefix(service.env, "enc:v1:") && len(options.EncryptionKeys) == 0 {
			report.Warnings = append(report.Warnings, fmt.Sprintf("compose %s has encrypted environment values; supply --encryption-key-file before import", service.id))
		}
	}
	filteredRoutes := make([]sourceRoute, 0, len(routes))
	seenRoute := map[string]bool{}
	for _, route := range routes {
		metadata := map[string]any{"host": route.host, "path": route.path, "composeId": route.composeID}
		if !validServices[route.composeID] || route.serviceName == "" || route.port < 1 || route.port > 65535 {
			report.Skipped++
			report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "compose_route", SourceID: route.id, Status: "skipped", Reason: "invalid or parent service was not imported", Metadata: metadata})
			continue
		}
		key := strings.ToLower(route.host) + "\x00" + route.path
		if seenRoute[key] {
			report.Skipped++
			report.Warnings = append(report.Warnings, "duplicate route "+route.host+route.path+" was skipped")
			report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "compose_route", SourceID: route.id, Status: "skipped", Reason: "duplicate host and path", Metadata: metadata})
			continue
		}
		seenRoute[key] = true
		filteredRoutes = append(filteredRoutes, route)
		targetID := mappedID(options, "route", route.id)
		report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "compose_route", SourceID: route.id, TargetID: &targetID, Status: "imported", Metadata: metadata})
	}
	validApplications := map[string]bool{}
	for _, item := range applications {
		prepared, warnings, prepareErr := prepareApplication(item, options)
		report.Warnings = append(report.Warnings, warnings...)
		if prepareErr == nil {
			_, prepareErr = compiler.Compile(prepared.composeYAML, nil)
		}
		if prepareErr != nil {
			report.Skipped++
			report.Warnings = append(report.Warnings, fmt.Sprintf("application %s is incompatible: %v", item.ID, prepareErr))
			report.Resources = append(report.Resources, dokployApplicationReport(item, nil, "skipped", prepareErr.Error()))
			continue
		}
		validApplications[item.ID] = true
		targetID := prepared.serviceID
		report.Resources = append(report.Resources, dokployApplicationReport(item, &targetID, "imported", ""))
		for _, networkID := range item.NetworkIDs {
			addNetworkAssignment("application", item.ID, item.EnvironmentID, targetID, networkID, nil)
		}
		if strings.HasPrefix(item.Env, "enc:v1:") && len(options.EncryptionKeys) == 0 {
			report.Warnings = append(report.Warnings, fmt.Sprintf("application %s has encrypted environment values; supply --encryption-key-file before import", item.ID))
		}
	}
	filteredApplicationRoutes := make([]sourceApplicationRoute, 0, len(applicationRoutes))
	for _, route := range applicationRoutes {
		metadata := map[string]any{"host": route.host, "path": route.path, "applicationId": route.applicationID}
		if !validApplications[route.applicationID] || route.port < 1 || route.port > 65535 {
			report.Skipped++
			report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "application_route", SourceID: route.id, Status: "skipped", Reason: "invalid or parent application was not imported", Metadata: metadata})
			continue
		}
		key := strings.ToLower(route.host) + "\x00" + route.path
		if seenRoute[key] {
			report.Skipped++
			report.Warnings = append(report.Warnings, "duplicate route "+route.host+route.path+" was skipped")
			report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "application_route", SourceID: route.id, Status: "skipped", Reason: "duplicate host and path", Metadata: metadata})
			continue
		}
		seenRoute[key] = true
		filteredApplicationRoutes = append(filteredApplicationRoutes, route)
		targetID := mappedID(options, "application-route", route.id)
		report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "application_route", SourceID: route.id, TargetID: &targetID, Status: "imported", Metadata: metadata})
	}
	report.Routes = len(filteredRoutes) + len(filteredApplicationRoutes)
	report.Applications = len(applications)
	report.Databases = len(databases)
	backupDestinations, err := readBackupDestinations(ctx, source, options.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	backupPolicies, err := readBackupPolicies(ctx, source, options.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	volumeBackupPolicies, err := readVolumeBackupPolicies(ctx, source, options.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	report.BackupDestinations, report.BackupPolicies = len(backupDestinations), len(backupPolicies)+len(volumeBackupPolicies)
	sourceCredentials, err := readSourceCredentials(ctx, source, options.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	report.SourceCredentials = len(sourceCredentials)
	notifications, err := readNotifications(ctx, source, options.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	report.NotificationEndpoints = len(notifications)
	registry := database.NewRegistry()
	validDatabases := map[string]bool{}
	for _, item := range databases {
		targetID := mappedDokployDatabaseID(options, "database", item)
		metadata := map[string]any{"name": item.name, "engine": item.engine, "environmentId": item.environmentID, "serverId": item.serverID}
		if item.sourceEngine != item.engine {
			metadata["sourceEngine"] = item.sourceEngine
		}
		_, renderErr := registry.Render(item.engine, database.Request{Name: migratedSlug(item.appName, targetID), Version: imageVersion(item.dockerImage, "latest"), Config: databaseConfig(item)})
		if renderErr != nil {
			report.Skipped++
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s database %s is incompatible: %v", item.engine, item.id, renderErr))
			report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "database", SourceID: item.identity(), Status: "skipped", Reason: renderErr.Error(), Metadata: metadata})
			continue
		}
		validDatabases[item.identity()] = true
		report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "database", SourceID: item.identity(), TargetID: &targetID, Status: "imported", Metadata: metadata})
		for _, networkID := range item.networkIDs {
			addNetworkAssignment("database", item.identity(), item.environmentID, mappedDokployDatabaseID(options, "database-service", item), networkID, nil)
		}
		if strings.HasPrefix(item.env, "enc:v1:") && len(options.EncryptionKeys) == 0 {
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s database %s has encrypted environment values; supply --encryption-key-file before import", item.engine, item.id))
		}
	}
	preparedDestinations := map[string]preparedBackupDestination{}
	destinationSources := map[string]sourceBackupDestination{}
	for _, item := range backupDestinations {
		destinationSources[item.id] = item
		if len(item.additionalFlags) > 0 {
			report.Warnings = append(report.Warnings, fmt.Sprintf("backup destination %s has additional flags that require manual review", item.id))
		}
		prepared, prepareErr := prepareDokployBackupDestination(box, options, item, "")
		if prepareErr != nil {
			report.Skipped++
			report.Warnings = append(report.Warnings, fmt.Sprintf("backup destination %s is incompatible: %v", item.id, prepareErr))
			report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "backup_destination", SourceID: item.id, Status: "skipped", Reason: prepareErr.Error(), Metadata: backupDestinationMetadata(item, "")})
			continue
		}
		preparedDestinations[prepared.key] = prepared
		report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "backup_destination", SourceID: item.id, TargetID: &prepared.reportID, Status: "imported", Metadata: backupDestinationMetadata(item, "")})
	}
	preparedPolicies := []preparedBackupPolicy{}
	preparedVolumePolicies := []preparedVolumeBackupPolicy{}
	for _, item := range volumeBackupPolicies {
		policyID := mappedID(options, "volume-backup-policy", item.id)
		metadata := map[string]any{
			"name": item.name, "volumeName": item.volumeName, "prefix": item.prefix, "serviceType": item.serviceType,
			"appName": item.appName, "serviceName": item.serviceName, "turnOff": item.turnOff, "schedule": item.cronExpression,
			"retentionCount": item.retentionCount, "enabled": item.enabled, "destinationId": item.destinationID,
		}
		serviceID, composeYAML, found := dokployVolumeService(options, item, services, applications, validServices, validApplications)
		volumeName, volumeFound := dokployLogicalVolume(composeYAML, item.volumeName)
		interval, supportedSchedule := cronInterval(item.cronExpression)
		reason := ""
		if !found {
			reason = "the referenced Compose service or application was not imported"
		} else if !volumeFound {
			reason = "the referenced named volume is not declared by the imported Compose service"
		} else if !supportedSchedule || interval < 900 || interval > 2_678_400 {
			reason = "cron schedule cannot be represented as a fixed 15-minute to 31-day interval"
		} else if item.retentionCount < 1 || item.retentionCount > 100 {
			reason = "retention count is outside Dockyard's 1..100 range"
		}
		destinationSource, destinationFound := destinationSources[item.destinationID]
		if reason == "" && !destinationFound {
			reason = "the referenced backup destination was not found"
		}
		var preparedDestination preparedBackupDestination
		if reason == "" {
			preparedDestination, err = prepareDokployBackupDestination(box, options, destinationSource, item.prefix)
			if err != nil {
				reason = err.Error()
			}
		}
		if reason == "" {
			for _, existing := range preparedVolumePolicies {
				if existing.serviceID == serviceID && existing.volumeName == volumeName {
					reason = "Dockyard supports one backup policy per service volume"
					break
				}
			}
		}
		if reason == "" {
			var existingID uuid.UUID
			existingErr := destination.Pool.QueryRow(ctx, `SELECT policy.id FROM volume_backup_policies policy JOIN compose_services service ON service.id=policy.compose_service_id JOIN environments environment ON environment.id=service.environment_id JOIN projects project ON project.id=environment.project_id WHERE policy.compose_service_id=$1 AND policy.volume_name=$2 AND project.organization_id=$3`, serviceID, volumeName, options.TargetOrganizationID).Scan(&existingID)
			if existingErr == nil {
				policyID = existingID
			} else if !errors.Is(existingErr, pgx.ErrNoRows) {
				return report, existingErr
			}
		}
		if reason != "" {
			report.Skipped++
			report.Warnings = append(report.Warnings, fmt.Sprintf("volume backup policy %s was skipped: %s", item.id, reason))
			report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "volume_backup", SourceID: item.id, Status: "skipped", Reason: reason, Metadata: metadata})
			continue
		}
		preparedDestinations[preparedDestination.key] = preparedDestination
		preparedVolumePolicies = append(preparedVolumePolicies, preparedVolumeBackupPolicy{source: item, id: policyID, serviceID: serviceID, destinationID: preparedDestination.id, volumeName: volumeName, intervalSeconds: interval})
		report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "volume_backup", SourceID: item.id, TargetID: &policyID, Status: "imported", Metadata: metadata})
	}
	seenDatabasePolicy := map[uuid.UUID]bool{}
	for _, item := range backupPolicies {
		policyID := mappedID(options, "backup-policy", item.id)
		metadata := map[string]any{"schedule": item.schedule, "databaseType": item.databaseType, "backupType": item.backupType, "prefix": item.prefix, "enabled": item.enabled, "retentionCount": item.retentionCount}
		reason := ""
		interval, supportedSchedule := cronInterval(item.schedule)
		databaseID := mappedID(options, "database:"+item.databaseType, item.databaseID)
		if item.backupType != "database" {
			reason = "Compose backup policies are not supported"
		} else if !validDatabases[item.databaseType+":"+item.databaseID] || item.databaseID == "" || !dokployTransferCapableEngine(item.databaseType) {
			reason = "the referenced database was not imported or is not backup-capable"
		} else if !supportedSchedule || interval < 900 || interval > 2_678_400 {
			reason = "cron schedule cannot be represented as a fixed 15-minute to 31-day interval"
		} else if item.retentionCount < 1 || item.retentionCount > 100 {
			reason = "retention count is outside Dockyard's 1..100 range"
		} else if seenDatabasePolicy[databaseID] {
			reason = "Dockyard supports one backup policy per database"
		}
		destinationSource, destinationFound := destinationSources[item.destinationID]
		if reason == "" && !destinationFound {
			reason = "the referenced backup destination was not found"
		}
		var preparedDestination preparedBackupDestination
		if reason == "" {
			preparedDestination, err = prepareDokployBackupDestination(box, options, destinationSource, item.prefix)
			if err != nil {
				reason = err.Error()
			}
		}
		if reason != "" {
			report.Skipped++
			report.Warnings = append(report.Warnings, fmt.Sprintf("backup policy %s was skipped: %s", item.id, reason))
			report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "backup_policy", SourceID: item.id, Status: "skipped", Reason: reason, Metadata: metadata})
			continue
		}
		seenDatabasePolicy[databaseID] = true
		preparedDestinations[preparedDestination.key] = preparedDestination
		preparedPolicies = append(preparedPolicies, preparedBackupPolicy{source: item, id: policyID, databaseID: databaseID, destinationID: preparedDestination.id, intervalSeconds: interval})
		report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "backup_policy", SourceID: item.id, TargetID: &policyID, Status: "imported", Metadata: metadata})
	}
	preparedCredentials := map[string]preparedSourceCredential{}
	for _, item := range sourceCredentials {
		prepared, prepareErr := prepareSourceCredential(box, options, item)
		metadata := map[string]any{"name": item.name, "provider": item.sourceKind, "server": item.server, "kind": item.kind}
		if prepareErr != nil {
			report.Skipped++
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s credential %s was skipped: %v", item.sourceKind, item.sourceID, prepareErr))
			report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "source_credential", SourceID: item.sourceKind + ":" + item.sourceID, Status: "skipped", Reason: prepareErr.Error(), Metadata: metadata})
			continue
		}
		preparedCredentials[credentialKey(item.sourceKind, item.sourceID)] = prepared
		report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "source_credential", SourceID: item.sourceKind + ":" + item.sourceID, TargetID: &prepared.id, Status: "imported", Metadata: metadata})
	}
	preparedNotifications := []preparedNotification{}
	for _, item := range notifications {
		prepared, warnings, prepareErr := prepareNotification(box, options, item)
		report.Warnings = append(report.Warnings, warnings...)
		metadata := notificationMetadata(item, prepared.events)
		if prepareErr != nil {
			report.Skipped++
			report.Warnings = append(report.Warnings, fmt.Sprintf("notification %s was skipped: %v", item.id, prepareErr))
			report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "notification", SourceID: item.id, Status: "skipped", Reason: prepareErr.Error(), Metadata: metadata})
			continue
		}
		preparedNotifications = append(preparedNotifications, prepared)
		report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "notification", SourceID: item.id, TargetID: &prepared.id, Status: "imported", Metadata: metadata})
	}
	for _, item := range applications {
		if !validApplications[item.ID] {
			continue
		}
		providerID := applicationProviderID(item)
		if providerID != "" {
			if _, ok := preparedCredentials[credentialKey(item.SourceType, providerID)]; !ok {
				report.Warnings = append(report.Warnings, fmt.Sprintf("application %s has no convertible %s credential", item.ID, item.SourceType))
			}
		}
		registryID := item.BuildRegistryID
		if registryID == "" {
			registryID = item.RegistryID
		}
		if registryID != "" {
			credential, ok := preparedCredentials[credentialKey("registry", registryID)]
			if !ok || credential.server != deploy.RegistryHost(options.RegistryPrefix) {
				report.Warnings = append(report.Warnings, fmt.Sprintf("application %s build registry credential could not be attached to %s", item.ID, options.RegistryPrefix))
			}
		}
	}
	sort.Strings(report.Warnings)
	if options.DryRun {
		return report, nil
	}

	tx, err := destination.Pool.Begin(ctx)
	if err != nil {
		return report, err
	}
	defer tx.Rollback(ctx)
	for _, item := range projects {
		id := mappedID(options, "project", item.id)
		_, err = tx.Exec(ctx, `INSERT INTO projects(id,organization_id,name,slug,description) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO UPDATE SET name=excluded.name,description=excluded.description`, id, options.TargetOrganizationID, item.name, migratedSlug(item.name, id), item.description)
		if err != nil {
			return report, fmt.Errorf("import project %s: %w", item.id, err)
		}
	}
	for _, item := range tags {
		id, valid := tagIDs[item.id]
		if !valid {
			continue
		}
		_, err = tx.Exec(ctx, `INSERT INTO tags(id,organization_id,name,color) VALUES($1,$2,$3,$4)
			ON CONFLICT(id) DO UPDATE SET name=excluded.name,color=excluded.color,updated_at=now()`, id, options.TargetOrganizationID, strings.TrimSpace(item.name), normalizeTagColor(item.color))
		if err != nil {
			return report, fmt.Errorf("import tag %s: %w", item.id, err)
		}
	}
	for _, item := range projectTags {
		tagID, valid := tagIDs[item.tagID]
		if !valid {
			continue
		}
		projectID := mappedID(options, "project", item.projectID)
		_, err = tx.Exec(ctx, `INSERT INTO project_tags(project_id,tag_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, projectID, tagID)
		if err != nil {
			return report, fmt.Errorf("import project tag %s: %w", item.id, err)
		}
	}
	for _, item := range networks {
		id, valid := networkIDs[item.id]
		if !valid {
			continue
		}
		clusterID, _ := mappedDokployServer(options, item.serverID)
		if existing, exists := existingNetworksByName[managedNetworkScopeKey(clusterID, item.name)]; exists && existing.ID == id {
			continue
		}
		ipam, marshalErr := json.Marshal(item.ipam)
		if marshalErr != nil {
			return report, marshalErr
		}
		_, err = tx.Exec(ctx, `INSERT INTO managed_networks(id,organization_id,cluster_id,name,driver,internal,attachable,enable_ipv4,enable_ipv6,mtu,ipam,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'provisioning')
			ON CONFLICT(id) DO UPDATE SET name=excluded.name,driver=excluded.driver,internal=excluded.internal,attachable=excluded.attachable,enable_ipv4=excluded.enable_ipv4,enable_ipv6=excluded.enable_ipv6,mtu=excluded.mtu,ipam=excluded.ipam,updated_at=now()`, id, options.TargetOrganizationID, clusterID, item.name, item.driver, item.internal, item.attachable, item.enableIPv4, item.enableIPv6, item.mtu, ipam)
		if err != nil {
			return report, fmt.Errorf("import network %s: %w", item.id, err)
		}
		payload, _ := json.Marshal(map[string]string{"networkId": id.String()})
		if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key,max_attempts) SELECT $1,'network.create',$2,$3,10 WHERE EXISTS(SELECT 1 FROM managed_networks WHERE id=$4 AND status<>'ready' AND deletion_requested_at IS NULL) AND NOT EXISTS(SELECT 1 FROM jobs WHERE kind='network.create' AND payload->>'networkId'=$5 AND status IN ('pending','running'))`, uuid.New(), payload, "network:"+id.String(), id, id.String()); err != nil {
			return report, fmt.Errorf("queue network %s provisioning: %w", item.id, err)
		}
	}
	for _, item := range environments {
		id, projectID := mappedID(options, "environment", item.id), mappedID(options, "project", item.projectID)
		_, err = tx.Exec(ctx, `INSERT INTO environments(id,project_id,cluster_id,name,slug) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO UPDATE SET name=excluded.name,cluster_id=excluded.cluster_id`, id, projectID, environmentClusters[item.id], item.name, migratedSlug(item.name, id))
		if err != nil {
			return report, fmt.Errorf("import environment %s: %w", item.id, err)
		}
	}
	for _, item := range preparedCredentials {
		_, err = tx.Exec(ctx, `INSERT INTO source_credentials(id,organization_id,kind,name,server,username,encrypted_secret) VALUES($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT(id) DO UPDATE SET name=excluded.name,server=excluded.server,username=excluded.username,encrypted_secret=excluded.encrypted_secret,updated_at=now()`, item.id, options.TargetOrganizationID, item.source.kind, item.name, item.server, item.username, item.secret)
		if err != nil {
			return report, fmt.Errorf("import %s credential %s: %w", item.source.sourceKind, item.source.sourceID, err)
		}
	}
	for _, item := range services {
		if !validServices[item.id] {
			continue
		}
		id := mappedID(options, "compose", item.id)
		encryptedEnv := ""
		if item.env != "" {
			plain, decryptErr := decryptDokploy(item.env, options.EncryptionKeys)
			if decryptErr != nil {
				return report, fmt.Errorf("decrypt compose %s environment: %w", item.id, decryptErr)
			}
			environment := parseEnv(plain)
			data, _ := json.Marshal(environment)
			encryptedEnv, err = box.Encrypt(data, cryptox.ResourceContext("compose-env", id.String()))
			if err != nil {
				return report, err
			}
		}
		name := item.name
		if name == "" {
			name = item.appName
		}
		_, err = tx.Exec(ctx, `INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,encrypted_env) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(id) DO UPDATE SET name=excluded.name,compose_yaml=excluded.compose_yaml,encrypted_env=excluded.encrypted_env,revision=compose_services.revision+1,updated_at=now()`, id, mappedID(options, "environment", item.environmentID), name, migratedSlug(item.appName, id), migratedSlug(item.appName, id), item.compose, encryptedEnv)
		if err != nil {
			return report, fmt.Errorf("import compose %s: %w", item.id, err)
		}
	}
	for _, item := range applications {
		if !validApplications[item.ID] {
			continue
		}
		if item.Env != "" {
			plain, decryptErr := decryptDokploy(item.Env, options.EncryptionKeys)
			if decryptErr != nil {
				return report, fmt.Errorf("decrypt application %s environment: %w", item.ID, decryptErr)
			}
			item.Env = plain
		}
		prepared, _, prepareErr := prepareApplication(item, options)
		if prepareErr != nil {
			return report, fmt.Errorf("prepare application %s: %w", item.ID, prepareErr)
		}
		environmentJSON, _ := json.Marshal(prepared.environment)
		encryptedEnvironment, encryptErr := box.Encrypt(environmentJSON, cryptox.ResourceContext("compose-env", prepared.serviceID.String()))
		if encryptErr != nil {
			return report, encryptErr
		}
		_, err = tx.Exec(ctx, `INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,encrypted_env) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(id) DO UPDATE SET name=excluded.name,compose_yaml=excluded.compose_yaml,encrypted_env=excluded.encrypted_env,revision=compose_services.revision+1,updated_at=now()`, prepared.serviceID, mappedID(options, "environment", item.EnvironmentID), item.Name, "app-"+prepared.slug, prepared.slug, prepared.composeYAML, encryptedEnvironment)
		if err != nil {
			return report, fmt.Errorf("import application %s: %w", item.ID, err)
		}
		if prepared.source != nil {
			var gitCredentialID, registryCredentialID *uuid.UUID
			if providerID := applicationProviderID(item); providerID != "" {
				if credential, ok := preparedCredentials[credentialKey(item.SourceType, providerID)]; ok && credential.server == repositoryHost(prepared.source.RepositoryURL) {
					id := credential.id
					gitCredentialID = &id
				}
			}
			registryID := item.BuildRegistryID
			if registryID == "" {
				registryID = item.RegistryID
			}
			if credential, ok := preparedCredentials[credentialKey("registry", registryID)]; ok && credential.server == deploy.RegistryHost(prepared.source.RegistryImage) {
				id := credential.id
				registryCredentialID = &id
			}
			encryptedBuildConfig := ""
			if len(prepared.source.BuildArguments) > 0 || len(prepared.source.BuildSecrets) > 0 {
				data, marshalErr := json.Marshal(store.ApplicationBuildConfig{Arguments: prepared.source.BuildArguments, Secrets: prepared.source.BuildSecrets})
				if marshalErr != nil {
					return report, marshalErr
				}
				encryptedBuildConfig, err = box.Encrypt(data, "application-build-config:"+prepared.source.ComposeServiceID.String())
				if err != nil {
					return report, err
				}
			}
			_, err = tx.Exec(ctx, `INSERT INTO application_sources(compose_service_id,source_type,repository_url,git_ref,context_directory,dockerfile,build_type,builder_image,output_directory,build_target,enable_submodules,encrypted_build_config,target_service,registry_image,git_credential_id,registry_credential_id) VALUES($1,'git',$2,$3,$4,$5,$6,'',$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(compose_service_id) DO UPDATE SET source_type=excluded.source_type,repository_url=excluded.repository_url,git_ref=excluded.git_ref,context_directory=excluded.context_directory,dockerfile=excluded.dockerfile,build_type=excluded.build_type,builder_image=excluded.builder_image,output_directory=excluded.output_directory,build_target=excluded.build_target,enable_submodules=excluded.enable_submodules,encrypted_build_config=excluded.encrypted_build_config,target_service=excluded.target_service,registry_image=excluded.registry_image,git_credential_id=excluded.git_credential_id,registry_credential_id=excluded.registry_credential_id,updated_at=now()`, prepared.source.ComposeServiceID, prepared.source.RepositoryURL, prepared.source.GitRef, prepared.source.ContextDirectory, prepared.source.Dockerfile, prepared.source.BuildType, prepared.source.OutputDirectory, prepared.source.BuildTarget, prepared.source.EnableSubmodules, encryptedBuildConfig, prepared.source.TargetService, prepared.source.RegistryImage, gitCredentialID, registryCredentialID)
			if err != nil {
				return report, fmt.Errorf("import application source %s: %w", item.ID, err)
			}
		} else if _, err = tx.Exec(ctx, `DELETE FROM application_sources WHERE compose_service_id=$1`, prepared.serviceID); err != nil {
			return report, fmt.Errorf("remove stale application source %s: %w", item.ID, err)
		}
	}
	for _, item := range databases {
		if !validDatabases[item.identity()] {
			continue
		}
		databaseID := mappedDokployDatabaseID(options, "database", item)
		serviceID := mappedDokployDatabaseID(options, "database-service", item)
		slug := migratedSlug(item.appName, databaseID)
		config := databaseConfig(item)
		version := imageVersion(item.dockerImage, "latest")
		rendered, renderErr := registry.Render(item.engine, database.Request{Name: slug, Version: version, Config: config})
		if renderErr != nil {
			return report, fmt.Errorf("render %s database %s: %w", item.engine, item.id, renderErr)
		}
		driver, exists := registry.Engine(item.engine)
		if !exists {
			return report, fmt.Errorf("database driver %s disappeared during import", item.engine)
		}
		environment := map[string]string{}
		if item.env != "" {
			plain, decryptErr := decryptDokploy(item.env, options.EncryptionKeys)
			if decryptErr != nil {
				return report, fmt.Errorf("decrypt %s database %s environment: %w", item.engine, item.id, decryptErr)
			}
			environment = parseEnv(plain)
		}
		for key, value := range rendered.Environment {
			environment[key] = value
		}
		environmentJSON, _ := json.Marshal(environment)
		encryptedEnvironment, encryptErr := box.Encrypt(environmentJSON, cryptox.ResourceContext("compose-env", serviceID.String()))
		if encryptErr != nil {
			return report, encryptErr
		}
		credentialsJSON, _ := json.Marshal(rendered.Credentials)
		encryptedCredentials, encryptErr := box.Encrypt(credentialsJSON, cryptox.ResourceContext("database-credentials", databaseID.String()))
		if encryptErr != nil {
			return report, encryptErr
		}
		configJSON, _ := json.Marshal(database.StoredConfig(config))
		_, err = tx.Exec(ctx, `INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,encrypted_env) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(id) DO UPDATE SET name=excluded.name,compose_yaml=excluded.compose_yaml,encrypted_env=excluded.encrypted_env,revision=compose_services.revision+1,updated_at=now()`, serviceID, mappedID(options, "environment", item.environmentID), item.name, "db-"+slug, slug, rendered.ComposeYAML, encryptedEnvironment)
		if err != nil {
			return report, fmt.Errorf("import %s service %s: %w", item.engine, item.id, err)
		}
		_, err = tx.Exec(ctx, `INSERT INTO database_instances(id,environment_id,name,slug,engine,version,driver_source,driver_artifact_digest,compose_service_id,encrypted_credentials,config,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'pending') ON CONFLICT(id) DO UPDATE SET name=excluded.name,engine=excluded.engine,version=excluded.version,driver_source=excluded.driver_source,driver_artifact_digest=excluded.driver_artifact_digest,compose_service_id=excluded.compose_service_id,encrypted_credentials=excluded.encrypted_credentials,config=excluded.config,status='pending',updated_at=now()`, databaseID, mappedID(options, "environment", item.environmentID), item.name, slug, item.engine, rendered.Version, driver.Source, driver.ArtifactDigest, serviceID, encryptedCredentials, configJSON)
		if err != nil {
			return report, fmt.Errorf("import %s database %s: %w", item.engine, item.id, err)
		}
	}
	for _, assignment := range networkAssignments {
		_, err = tx.Exec(ctx, `INSERT INTO compose_service_networks(compose_service_id,network_id,service_names) VALUES($1,$2,$3) ON CONFLICT(compose_service_id,network_id) DO UPDATE SET service_names=excluded.service_names`, assignment.serviceID, assignment.networkID, assignment.serviceNames)
		if err != nil {
			return report, fmt.Errorf("import service network %s: %w", assignment.sourceID, err)
		}
	}
	for _, item := range preparedDestinations {
		_, err = tx.Exec(ctx, `INSERT INTO backup_destinations(id,organization_id,name,endpoint,region,bucket,prefix,use_tls,encrypted_credentials) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT(id) DO UPDATE SET name=excluded.name,endpoint=excluded.endpoint,region=excluded.region,bucket=excluded.bucket,prefix=excluded.prefix,use_tls=excluded.use_tls,encrypted_credentials=excluded.encrypted_credentials,updated_at=now()`, item.id, options.TargetOrganizationID, item.name, item.endpoint, item.region, item.bucket, item.prefix, item.useTLS, item.encryptedCredentials)
		if err != nil {
			return report, fmt.Errorf("import backup destination %s: %w", item.sourceID, err)
		}
	}
	for _, item := range preparedPolicies {
		_, err = tx.Exec(ctx, `INSERT INTO backup_policies(id,database_instance_id,interval_seconds,retention_count,enabled,next_run_at,destination_id,verify_restore) VALUES($1,$2,$3,$4,$5,now()+($3::int * interval '1 second'),$6,false)
			ON CONFLICT(database_instance_id) DO UPDATE SET interval_seconds=excluded.interval_seconds,retention_count=excluded.retention_count,enabled=excluded.enabled,destination_id=excluded.destination_id,next_run_at=CASE WHEN backup_policies.enabled=false AND excluded.enabled=true THEN excluded.next_run_at ELSE backup_policies.next_run_at END,updated_at=now()`, item.id, item.databaseID, item.intervalSeconds, item.source.retentionCount, item.source.enabled, item.destinationID)
		if err != nil {
			return report, fmt.Errorf("import backup policy %s: %w", item.source.id, err)
		}
	}
	for _, item := range preparedVolumePolicies {
		_, err = tx.Exec(ctx, `INSERT INTO volume_backup_policies(id,compose_service_id,volume_name,destination_id,interval_seconds,retention_count,quiesce,enabled,next_run_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,now()+($5::int * interval '1 second'))
			ON CONFLICT(compose_service_id,volume_name) DO UPDATE SET destination_id=excluded.destination_id,interval_seconds=excluded.interval_seconds,retention_count=excluded.retention_count,quiesce=excluded.quiesce,enabled=excluded.enabled,next_run_at=CASE WHEN volume_backup_policies.enabled=false AND excluded.enabled=true THEN excluded.next_run_at ELSE volume_backup_policies.next_run_at END,updated_at=now()`, item.id, item.serviceID, item.volumeName, item.destinationID, item.intervalSeconds, item.source.retentionCount, item.source.turnOff, item.source.enabled)
		if err != nil {
			return report, fmt.Errorf("import volume backup policy %s: %w", item.source.id, err)
		}
	}
	for _, item := range preparedNotifications {
		_, err = tx.Exec(ctx, `INSERT INTO notification_endpoints(id,organization_id,name,kind,encrypted_url,encrypted_secret,events,enabled) VALUES($1,$2,$3,$4,$5,$6,$7,true)
			ON CONFLICT(id) DO UPDATE SET name=excluded.name,kind=excluded.kind,encrypted_url=excluded.encrypted_url,encrypted_secret=excluded.encrypted_secret,events=excluded.events,enabled=true,updated_at=now()`, item.id, options.TargetOrganizationID, item.name, item.kind, item.encryptedURL, item.encryptedSecret, item.events)
		if err != nil {
			return report, fmt.Errorf("import notification %s: %w", item.source.id, err)
		}
	}
	for _, item := range filteredRoutes {
		id := mappedID(options, "route", item.id)
		path := item.path
		if path == "" {
			path = "/"
		}
		resolver := item.resolver
		if resolver == "" {
			resolver = "letsencrypt"
		}
		internalPath := item.internalPath
		if internalPath == "" {
			internalPath = "/"
		}
		_, err = tx.Exec(ctx, `INSERT INTO routes(id,compose_service_id,service_name,host,path_prefix,internal_path,strip_path,enabled,target_port,tls,certificate_resolver) VALUES($1,$2,$3,lower($4),$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(id) DO UPDATE SET service_name=excluded.service_name,host=excluded.host,path_prefix=excluded.path_prefix,internal_path=excluded.internal_path,strip_path=excluded.strip_path,enabled=excluded.enabled,target_port=excluded.target_port,tls=excluded.tls,certificate_resolver=excluded.certificate_resolver,updated_at=now()`, id, mappedID(options, "compose", item.composeID), item.serviceName, item.host, path, internalPath, item.stripPath, item.enabled, item.port, item.tls, resolver)
		if err != nil {
			return report, fmt.Errorf("import route %s: %w", item.id, err)
		}
	}
	for _, item := range filteredApplicationRoutes {
		path := item.path
		if path == "" {
			path = "/"
		}
		resolver := item.resolver
		if resolver == "" {
			resolver = "letsencrypt"
		}
		internalPath := item.internalPath
		if internalPath == "" {
			internalPath = "/"
		}
		_, err = tx.Exec(ctx, `INSERT INTO routes(id,compose_service_id,service_name,host,path_prefix,internal_path,strip_path,enabled,target_port,tls,certificate_resolver) VALUES($1,$2,'app',lower($3),$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(id) DO UPDATE SET service_name='app',host=excluded.host,path_prefix=excluded.path_prefix,internal_path=excluded.internal_path,strip_path=excluded.strip_path,enabled=excluded.enabled,target_port=excluded.target_port,tls=excluded.tls,certificate_resolver=excluded.certificate_resolver,updated_at=now()`, mappedID(options, "application-route", item.id), mappedID(options, "application-service", item.applicationID), item.host, path, internalPath, item.stripPath, item.enabled, item.port, item.tls, resolver)
		if err != nil {
			return report, fmt.Errorf("import application route %s: %w", item.id, err)
		}
	}
	if _, err = tx.Exec(ctx, `DELETE FROM dokploy_migration_resources WHERE target_organization_id=$1 AND source_organization_id=$2`, options.TargetOrganizationID, options.SourceOrganizationID); err != nil {
		return report, fmt.Errorf("replace Dokploy migration parity manifest: %w", err)
	}
	for _, resource := range report.Resources {
		metadata, marshalErr := json.Marshal(resource.Metadata)
		if marshalErr != nil {
			return report, marshalErr
		}
		_, err = tx.Exec(ctx, `INSERT INTO dokploy_migration_resources(target_organization_id,source_organization_id,source_kind,source_id,target_id,status,reason,metadata) VALUES($1,$2,$3,$4,$5,$6,$7,$8)
			ON CONFLICT(target_organization_id,source_organization_id,source_kind,source_id) DO UPDATE SET target_id=excluded.target_id,status=excluded.status,reason=excluded.reason,metadata=excluded.metadata,updated_at=now()`, options.TargetOrganizationID, options.SourceOrganizationID, resource.SourceKind, resource.SourceID, resource.TargetID, resource.Status, resource.Reason, metadata)
		if err != nil {
			return report, fmt.Errorf("record migration metadata for %s %s: %w", resource.SourceKind, resource.SourceID, err)
		}
	}
	return report, tx.Commit(ctx)
}

func dokployTransferCapableEngine(engine string) bool {
	switch engine {
	case "postgres", "timescaledb", "mysql", "mariadb", "mongo", "redis", "valkey", "libsql":
		return true
	default:
		return false
	}
}

func databaseConfig(item sourceDatabase) map[string]any {
	return map[string]any{"username": item.databaseUser, "password": item.databasePassword, "database": item.databaseName, "rootPassword": item.rootPassword, "image": item.dockerImage, "source": "dokploy", "sourceId": item.id}
}

func mappedDokployServer(options DokployOptions, sourceServerID string) (*uuid.UUID, bool) {
	sourceServerID = strings.TrimSpace(sourceServerID)
	if sourceServerID == "" {
		return nil, true
	}
	clusterID, ok := options.ServerClusterMappings[sourceServerID]
	if !ok || clusterID == uuid.Nil {
		return nil, false
	}
	return &clusterID, true
}

func managedNetworkScopeKey(clusterID *uuid.UUID, name string) string {
	if clusterID == nil {
		return "local\x00" + name
	}
	return clusterID.String() + "\x00" + name
}

func sameOptionalUUID(left, right *uuid.UUID) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func resolveDokployEnvironmentClusters(ctx context.Context, destination *store.Store, options DokployOptions, environments []sourceEnvironment, services []sourceCompose, applications []sourceApplication, databases []sourceDatabase) (map[string]*uuid.UUID, error) {
	knownClusters := map[uuid.UUID]bool{}
	clusters, err := destination.ListClusters(ctx, options.TargetOrganizationID)
	if err != nil {
		return nil, fmt.Errorf("list target clusters: %w", err)
	}
	for _, cluster := range clusters {
		knownClusters[cluster.ID] = true
	}
	for sourceServerID, clusterID := range options.ServerClusterMappings {
		if strings.TrimSpace(sourceServerID) == "" || clusterID == uuid.Nil {
			return nil, errors.New("Dokploy server mappings require a non-empty source server ID and target cluster UUID")
		}
		if !knownClusters[clusterID] {
			return nil, fmt.Errorf("Dokploy server %q maps to target cluster %s outside the target organization", sourceServerID, clusterID)
		}
	}
	return resolveDokployEnvironmentPlacements(options, environments, services, applications, databases)
}

func resolveDokployEnvironmentPlacements(options DokployOptions, environments []sourceEnvironment, services []sourceCompose, applications []sourceApplication, databases []sourceDatabase) (map[string]*uuid.UUID, error) {
	placements := make(map[string]*uuid.UUID, len(environments))
	seen := make(map[string]bool, len(environments))
	for _, environment := range environments {
		seen[environment.id] = true
	}
	assign := func(environmentID, sourceServerID, sourceKind, sourceID string) error {
		clusterID, mapped := mappedDokployServer(options, sourceServerID)
		if !mapped {
			return fmt.Errorf("%s %s uses unmapped remote Dokploy server %q; pass --server-cluster %s=TARGET_CLUSTER_UUID", sourceKind, sourceID, sourceServerID, sourceServerID)
		}
		if current, exists := placements[environmentID]; exists {
			if !sameOptionalUUID(current, clusterID) {
				return fmt.Errorf("Dokploy environment %s spans local and remote servers or multiple target clusters; split it before import", environmentID)
			}
			return nil
		}
		placements[environmentID] = clusterID
		return nil
	}
	for _, service := range services {
		if assignErr := assign(service.environmentID, service.serverID, "Compose service", service.id); assignErr != nil {
			return nil, assignErr
		}
	}
	for _, application := range applications {
		if assignErr := assign(application.EnvironmentID, application.ServerID, "application", application.ID); assignErr != nil {
			return nil, assignErr
		}
	}
	for _, database := range databases {
		if assignErr := assign(database.environmentID, database.serverID, database.engine+" database", database.id); assignErr != nil {
			return nil, assignErr
		}
	}
	for environmentID := range seen {
		if _, exists := placements[environmentID]; !exists {
			placements[environmentID] = nil
		}
	}
	return placements, nil
}

func readDatabases(ctx context.Context, db *pgxpool.Pool, org string) ([]sourceDatabase, error) {
	items := []sourceDatabase{}
	for _, engine := range []string{"postgres", "mysql", "mariadb", "mongo", "redis", "libsql"} {
		idColumn := pgx.Identifier{engine + "Id"}.Sanitize()
		table := pgx.Identifier{engine}.Sanitize()
		var query string
		switch engine {
		case "postgres":
			query = fmt.Sprintf(`SELECT d.%s,d."environmentId",d.name,d."appName",d."databaseName",d."databaseUser",d."databasePassword",'',d."dockerImage",COALESCE(d.env,''),COALESCE(to_jsonb(d)->'networkIds','[]'::jsonb),COALESCE(to_jsonb(d)->>'serverId','') FROM %s d JOIN environment e ON e."environmentId"=d."environmentId" JOIN project p ON p."projectId"=e."projectId" WHERE p."organizationId"=$1 ORDER BY d.%s`, idColumn, table, idColumn)
		case "mysql", "mariadb":
			query = fmt.Sprintf(`SELECT d.%s,d."environmentId",d.name,d."appName",d."databaseName",d."databaseUser",d."databasePassword",d."rootPassword",d."dockerImage",COALESCE(d.env,''),COALESCE(to_jsonb(d)->'networkIds','[]'::jsonb),COALESCE(to_jsonb(d)->>'serverId','') FROM %s d JOIN environment e ON e."environmentId"=d."environmentId" JOIN project p ON p."projectId"=e."projectId" WHERE p."organizationId"=$1 ORDER BY d.%s`, idColumn, table, idColumn)
		case "mongo":
			query = fmt.Sprintf(`SELECT d.%s,d."environmentId",d.name,d."appName",'admin',d."databaseUser",d."databasePassword",'',d."dockerImage",COALESCE(d.env,''),COALESCE(to_jsonb(d)->'networkIds','[]'::jsonb),COALESCE(to_jsonb(d)->>'serverId','') FROM %s d JOIN environment e ON e."environmentId"=d."environmentId" JOIN project p ON p."projectId"=e."projectId" WHERE p."organizationId"=$1 ORDER BY d.%s`, idColumn, table, idColumn)
		case "redis":
			query = fmt.Sprintf(`SELECT d.%s,d."environmentId",d.name,d."appName",'0','',d.password,'',d."dockerImage",COALESCE(d.env,''),COALESCE(to_jsonb(d)->'networkIds','[]'::jsonb),COALESCE(to_jsonb(d)->>'serverId','') FROM %s d JOIN environment e ON e."environmentId"=d."environmentId" JOIN project p ON p."projectId"=e."projectId" WHERE p."organizationId"=$1 ORDER BY d.%s`, idColumn, table, idColumn)
		case "libsql":
			query = fmt.Sprintf(`SELECT d.%s,d."environmentId",d.name,d."appName",'app',d."databaseUser",d."databasePassword",'',d."dockerImage",COALESCE(d.env,''),COALESCE(to_jsonb(d)->'networkIds','[]'::jsonb),COALESCE(to_jsonb(d)->>'serverId','') FROM %s d JOIN environment e ON e."environmentId"=d."environmentId" JOIN project p ON p."projectId"=e."projectId" WHERE p."organizationId"=$1 ORDER BY d.%s`, idColumn, table, idColumn)
		}
		rows, err := db.Query(ctx, query, org)
		if err != nil {
			return nil, fmt.Errorf("read Dokploy %s databases: %w", engine, err)
		}
		for rows.Next() {
			item := sourceDatabase{sourceEngine: engine, engine: engine}
			var networkIDs []byte
			if err = rows.Scan(&item.id, &item.environmentID, &item.name, &item.appName, &item.databaseName, &item.databaseUser, &item.databasePassword, &item.rootPassword, &item.dockerImage, &item.env, &networkIDs, &item.serverID); err != nil {
				rows.Close()
				return nil, err
			}
			if err = json.Unmarshal(networkIDs, &item.networkIDs); err != nil {
				rows.Close()
				return nil, fmt.Errorf("decode Dokploy %s network ids: %w", engine, err)
			}
			item.engine = classifyDokployDatabaseEngine(item.sourceEngine, item.dockerImage)
			items = append(items, item)
		}
		if err = rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	return items, nil
}

func classifyDokployDatabaseEngine(sourceEngine, image string) string {
	repository := strings.ToLower(strings.TrimSpace(image))
	if index := strings.IndexByte(repository, '@'); index >= 0 {
		repository = repository[:index]
	}
	if colon, slash := strings.LastIndex(repository, ":"), strings.LastIndex(repository, "/"); colon > slash {
		repository = repository[:colon]
	}
	for _, prefix := range []string{"docker.io/", "index.docker.io/", "registry-1.docker.io/"} {
		repository = strings.TrimPrefix(repository, prefix)
	}
	switch {
	case sourceEngine == "postgres" && repository == "timescale/timescaledb":
		return "timescaledb"
	case sourceEngine == "redis" && repository == "valkey/valkey":
		return "valkey"
	default:
		return sourceEngine
	}
}

func imageVersion(image, fallback string) string {
	withoutDigest := strings.SplitN(image, "@", 2)[0]
	colon := strings.LastIndex(withoutDigest, ":")
	if colon > strings.LastIndex(withoutDigest, "/") && colon+1 < len(withoutDigest) {
		return withoutDigest[colon+1:]
	}
	return fallback
}

func readProjects(ctx context.Context, db *pgxpool.Pool, org string) ([]sourceProject, error) {
	rows, err := db.Query(ctx, `SELECT "projectId",name,COALESCE(description,'') FROM project WHERE "organizationId"=$1 ORDER BY "projectId"`, org)
	if err != nil {
		return nil, fmt.Errorf("read Dokploy projects: %w", err)
	}
	defer rows.Close()
	items := []sourceProject{}
	for rows.Next() {
		var v sourceProject
		if err = rows.Scan(&v.id, &v.name, &v.description); err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return items, rows.Err()
}
func readEnvironments(ctx context.Context, db *pgxpool.Pool, org string) ([]sourceEnvironment, error) {
	rows, err := db.Query(ctx, `SELECT e."environmentId",e."projectId",e.name FROM environment e JOIN project p ON p."projectId"=e."projectId" WHERE p."organizationId"=$1 ORDER BY e."environmentId"`, org)
	if err != nil {
		return nil, fmt.Errorf("read Dokploy environments: %w", err)
	}
	defer rows.Close()
	items := []sourceEnvironment{}
	for rows.Next() {
		var v sourceEnvironment
		if err = rows.Scan(&v.id, &v.projectID, &v.name); err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return items, rows.Err()
}
func readCompose(ctx context.Context, db *pgxpool.Pool, org string) ([]sourceCompose, error) {
	rows, err := db.Query(ctx, `SELECT c."composeId",c."environmentId",c.name,c."appName",c."composeFile",COALESCE(c.env,''),COALESCE(to_jsonb(c)->'serviceNetworks','[]'::jsonb),COALESCE(to_jsonb(c)->>'serverId','') FROM compose c JOIN environment e ON e."environmentId"=c."environmentId" JOIN project p ON p."projectId"=e."projectId" WHERE p."organizationId"=$1 ORDER BY c."composeId"`, org)
	if err != nil {
		return nil, fmt.Errorf("read Dokploy compose services: %w", err)
	}
	defer rows.Close()
	items := []sourceCompose{}
	for rows.Next() {
		var v sourceCompose
		var raw []byte
		if err = rows.Scan(&v.id, &v.environmentID, &v.name, &v.appName, &v.compose, &v.env, &raw, &v.serverID); err != nil {
			return nil, err
		}
		var attachments []struct {
			ServiceName string   `json:"serviceName"`
			NetworkIDs  []string `json:"networkIds"`
		}
		if err = json.Unmarshal(raw, &attachments); err != nil {
			return nil, fmt.Errorf("decode Dokploy compose service networks: %w", err)
		}
		v.networks = map[string][]string{}
		for _, attachment := range attachments {
			for _, networkID := range attachment.NetworkIDs {
				if networkID == "" || attachment.ServiceName == "" {
					continue
				}
				v.networks[networkID] = appendUniqueString(v.networks[networkID], attachment.ServiceName)
			}
		}
		for networkID := range v.networks {
			sort.Strings(v.networks[networkID])
		}
		items = append(items, v)
	}
	return items, rows.Err()
}

func readNetworks(ctx context.Context, db *pgxpool.Pool, org string) ([]sourceNetwork, error) {
	var exists bool
	if err := db.QueryRow(ctx, `SELECT to_regclass('network') IS NOT NULL`).Scan(&exists); err != nil {
		return nil, fmt.Errorf("inspect Dokploy network schema: %w", err)
	}
	if !exists {
		return []sourceNetwork{}, nil
	}
	rows, err := db.Query(ctx, `SELECT "networkId",name,COALESCE(driver::text,'overlay'),COALESCE(internal,false),COALESCE(attachable,false),COALESCE((to_jsonb(network)->>'enableIPv4')::boolean,true),COALESCE((to_jsonb(network)->>'enableIPv6')::boolean,false),CASE WHEN to_jsonb(network)->>'mtu'='' THEN NULL ELSE (to_jsonb(network)->>'mtu')::integer END,COALESCE(to_jsonb(network)->'ipam','{}'::jsonb),COALESCE(to_jsonb(network)->>'serverId','') FROM network WHERE "organizationId"=$1 ORDER BY "networkId"`, org)
	if err != nil {
		return nil, fmt.Errorf("read Dokploy networks: %w", err)
	}
	defer rows.Close()
	items := []sourceNetwork{}
	for rows.Next() {
		var item sourceNetwork
		var raw []byte
		if err = rows.Scan(&item.id, &item.name, &item.driver, &item.internal, &item.attachable, &item.enableIPv4, &item.enableIPv6, &item.mtu, &raw, &item.serverID); err != nil {
			return nil, err
		}
		var ipam struct {
			Config []store.NetworkIPAMConfig `json:"config"`
		}
		if err = json.Unmarshal(raw, &ipam); err != nil {
			return nil, fmt.Errorf("decode Dokploy network IPAM: %w", err)
		}
		item.ipam = ipam.Config
		items = append(items, item)
	}
	return items, rows.Err()
}

func readTags(ctx context.Context, db *pgxpool.Pool, org string) ([]sourceTag, error) {
	var exists bool
	if err := db.QueryRow(ctx, `SELECT to_regclass('tag') IS NOT NULL`).Scan(&exists); err != nil {
		return nil, fmt.Errorf("inspect Dokploy tag schema: %w", err)
	}
	if !exists {
		return []sourceTag{}, nil
	}
	rows, err := db.Query(ctx, `SELECT "tagId",name,COALESCE(color,'') FROM tag WHERE "organizationId"=$1 ORDER BY "tagId"`, org)
	if err != nil {
		return nil, fmt.Errorf("read Dokploy tags: %w", err)
	}
	defer rows.Close()
	items := []sourceTag{}
	for rows.Next() {
		var item sourceTag
		if err = rows.Scan(&item.id, &item.name, &item.color); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func readProjectTags(ctx context.Context, db *pgxpool.Pool, org string) ([]sourceProjectTag, error) {
	var exists bool
	if err := db.QueryRow(ctx, `SELECT to_regclass('project_tag') IS NOT NULL AND to_regclass('tag') IS NOT NULL`).Scan(&exists); err != nil {
		return nil, fmt.Errorf("inspect Dokploy project-tag schema: %w", err)
	}
	if !exists {
		return []sourceProjectTag{}, nil
	}
	rows, err := db.Query(ctx, `SELECT pt.id,pt."projectId",pt."tagId" FROM project_tag pt JOIN project p ON p."projectId"=pt."projectId" JOIN tag t ON t."tagId"=pt."tagId" WHERE p."organizationId"=$1 AND t."organizationId"=$1 ORDER BY pt.id`, org)
	if err != nil {
		return nil, fmt.Errorf("read Dokploy project tags: %w", err)
	}
	defer rows.Close()
	items := []sourceProjectTag{}
	for rows.Next() {
		var item sourceProjectTag
		if err = rows.Scan(&item.id, &item.projectID, &item.tagID); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func normalizeTagColor(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if !tagColorPattern.MatchString(value) {
		return "#64748B"
	}
	return value
}

func sortedNetworkIDs(items map[string][]string) []string {
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func appendUniqueString(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}

func compatibleImportedNetwork(existing store.ManagedNetwork, source sourceNetwork) bool {
	if existing.Driver != source.driver || existing.Internal != source.internal || existing.Attachable != source.attachable || existing.EnableIPv4 != source.enableIPv4 || existing.EnableIPv6 != source.enableIPv6 {
		return false
	}
	if (existing.MTU == nil) != (source.mtu == nil) || existing.MTU != nil && *existing.MTU != *source.mtu {
		return false
	}
	existingIPAM, _ := json.Marshal(existing.IPAM)
	sourceIPAM, _ := json.Marshal(source.ipam)
	return string(existingIPAM) == string(sourceIPAM)
}
func readRoutes(ctx context.Context, db *pgxpool.Pool, org string) ([]sourceRoute, error) {
	rows, err := db.Query(ctx, `SELECT d."domainId",d."composeId",d.host,COALESCE(d.path,'/'),COALESCE(to_jsonb(d)->>'internalPath','/'),COALESCE((to_jsonb(d)->>'stripPath')::boolean,false),COALESCE(d."serviceName",''),COALESCE(d.port,3000),d.https,d.enabled,COALESCE(d."customCertResolver",'') FROM domain d JOIN compose c ON c."composeId"=d."composeId" JOIN environment e ON e."environmentId"=c."environmentId" JOIN project p ON p."projectId"=e."projectId" WHERE p."organizationId"=$1 AND d."composeId" IS NOT NULL ORDER BY d."domainId"`, org)
	if err != nil {
		return nil, fmt.Errorf("read Dokploy routes: %w", err)
	}
	defer rows.Close()
	items := []sourceRoute{}
	for rows.Next() {
		var v sourceRoute
		if err = rows.Scan(&v.id, &v.composeID, &v.host, &v.path, &v.internalPath, &v.stripPath, &v.serviceName, &v.port, &v.tls, &v.enabled, &v.resolver); err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return items, rows.Err()
}

func mappedID(options DokployOptions, kind, sourceID string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("dockyard:dokploy:"+options.TargetOrganizationID.String()+":"+options.SourceOrganizationID+":"+kind+":"+sourceID))
}

var (
	tagColorPattern = regexp.MustCompile(`^#[0-9A-F]{6}$`)
	nonSlug         = regexp.MustCompile(`[^a-z0-9]+`)
)

func migratedSlug(name string, id uuid.UUID) string {
	base := strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if base == "" {
		base = "imported"
	}
	if len(base) > 52 {
		base = base[:52]
	}
	return base + "-" + strings.Split(id.String(), "-")[0]
}

func decryptDokploy(value string, keys [][]byte) (string, error) {
	if !strings.HasPrefix(value, "enc:v1:") {
		return value, nil
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, "enc:v1:"))
	if err != nil {
		return "", err
	}
	if len(payload) < 28 {
		return "", errors.New("encrypted value is too short")
	}
	for _, key := range keys {
		if len(key) != 32 {
			continue
		}
		block, e := aes.NewCipher(key)
		if e != nil {
			continue
		}
		var aead cipher.AEAD
		aead, e = cipher.NewGCM(block)
		if e != nil {
			continue
		}
		ciphertextAndTag := append(append([]byte{}, payload[28:]...), payload[12:28]...)
		plain, e := aead.Open(nil, payload[:12], ciphertextAndTag, nil)
		if e == nil {
			return string(plain), nil
		}
	}
	return "", errors.New("no Dokploy encryption key could decrypt the value")
}
func ParseDokployKeys(data []byte) ([][]byte, error) {
	keys := [][]byte{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		key, err := hex.DecodeString(line)
		if err != nil || len(key) != 32 {
			return nil, errors.New("Dokploy encryption keys must be 32-byte hex values")
		}
		keys = append(keys, key)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}
func parseEnv(value string) map[string]string {
	result := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(value))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		val = strings.TrimSpace(val)
		if len(val) >= 2 && ((val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'')) {
			val = val[1 : len(val)-1]
		}
		result[key] = val
	}
	return result
}
