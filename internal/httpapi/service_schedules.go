package httpapi

import (
	"net/http"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

type serviceScheduleInput struct {
	Name           string `json:"name"`
	Description    string `json:"description"`
	CronExpression string `json:"cronExpression"`
	Timezone       string `json:"timezone"`
	TargetService  string `json:"targetService"`
	Shell          string `json:"shell"`
	Command        string `json:"command"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
	Enabled        *bool  `json:"enabled"`
}

func (input serviceScheduleInput) schedule(serviceID uuid.UUID) store.ServiceSchedule {
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	return store.ServiceSchedule{ComposeServiceID: serviceID, Name: input.Name, Description: input.Description, CronExpression: input.CronExpression, Timezone: input.Timezone, TargetService: input.TargetService, Shell: input.Shell, Command: input.Command, TimeoutSeconds: input.TimeoutSeconds, Enabled: enabled}
}

func serviceAndScheduleIDs(w http.ResponseWriter, r *http.Request) (uuid.UUID, uuid.UUID, bool) {
	serviceID, serviceErr := uuid.Parse(r.PathValue("serviceID"))
	scheduleID, scheduleErr := uuid.Parse(r.PathValue("scheduleID"))
	if serviceErr != nil || scheduleErr != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service or schedule id")
		return uuid.Nil, uuid.Nil, false
	}
	return serviceID, scheduleID, true
}

func (s *Server) listServiceSchedules(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service id")
		return
	}
	items, err := s.Store.ListServiceSchedules(r.Context(), principal(r).OrganizationID, serviceID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) createServiceSchedule(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service id")
		return
	}
	var input serviceScheduleInput
	if !decode(w, r, &input) {
		return
	}
	p := principal(r)
	item, err := s.Store.CreateServiceScheduleWithAudit(r.Context(), p, input.schedule(serviceID), r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) getServiceSchedule(w http.ResponseWriter, r *http.Request) {
	serviceID, scheduleID, ok := serviceAndScheduleIDs(w, r)
	if !ok {
		return
	}
	item, err := s.Store.GetServiceSchedule(r.Context(), principal(r).OrganizationID, serviceID, scheduleID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) updateServiceSchedule(w http.ResponseWriter, r *http.Request) {
	serviceID, scheduleID, ok := serviceAndScheduleIDs(w, r)
	if !ok {
		return
	}
	var input serviceScheduleInput
	if !decode(w, r, &input) {
		return
	}
	p := principal(r)
	request := input.schedule(serviceID)
	request.ID = scheduleID
	item, err := s.Store.UpdateServiceScheduleWithAudit(r.Context(), p, serviceID, request, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) deleteServiceSchedule(w http.ResponseWriter, r *http.Request) {
	serviceID, scheduleID, ok := serviceAndScheduleIDs(w, r)
	if !ok {
		return
	}
	p := principal(r)
	if err := s.Store.DeleteServiceScheduleWithAudit(r.Context(), p, serviceID, scheduleID, r.RemoteAddr); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) runServiceSchedule(w http.ResponseWriter, r *http.Request) {
	serviceID, scheduleID, ok := serviceAndScheduleIDs(w, r)
	if !ok {
		return
	}
	p := principal(r)
	item, err := s.Store.QueueServiceScheduleExecutionWithAudit(r.Context(), p, serviceID, scheduleID, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, item)
}

func (s *Server) listServiceScheduleExecutions(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service id")
		return
	}
	items, err := s.Store.ListServiceScheduleExecutions(r.Context(), principal(r).OrganizationID, serviceID, 50)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) cancelServiceScheduleExecution(w http.ResponseWriter, r *http.Request) {
	serviceID, serviceErr := uuid.Parse(r.PathValue("serviceID"))
	executionID, executionErr := uuid.Parse(r.PathValue("executionID"))
	if serviceErr != nil || executionErr != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service or execution id")
		return
	}
	p := principal(r)
	if err := s.Store.CancelServiceScheduleExecutionWithAudit(r.Context(), p, serviceID, executionID, r.RemoteAddr); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"id": executionID, "cancelRequested": true})
}
