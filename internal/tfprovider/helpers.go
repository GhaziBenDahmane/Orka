package tfprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/GhaziBenDahmane/Orka/internal/apiclient"
)

func call[T any](ctx context.Context, client *apiclient.Client, method, path string, input any) (T, error) {
	var result T
	var output bytes.Buffer
	if err := client.Do(ctx, method, path, input, &output); err != nil {
		return result, err
	}
	if output.Len() == 0 {
		return result, nil
	}
	return result, json.Unmarshal(output.Bytes(), &result)
}

func notFound(err error) bool {
	var apiError *apiclient.APIError
	return errors.As(err, &apiError) && apiError.Status == http.StatusNotFound
}
