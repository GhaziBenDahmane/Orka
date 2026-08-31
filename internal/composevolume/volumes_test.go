package composevolume

import (
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestNamesReturnsOnlyMountedDeclaredVolumes(t *testing.T) {
	source := `services:
  app:
    image: example/app
    volumes:
      - uploads:/data
      - type: volume
        source: cache
        target: /cache
      - ./config:/etc/app
volumes:
  cache: {}
  unused: {}
  uploads: {}
`
	got, err := Names(source)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"cache", "uploads"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("names=%v want=%v", got, want)
	}
}

func TestNamesFromDocumentMatchesParsedSource(t *testing.T) {
	source := "services: {app: {image: example/app, volumes: [data:/data]}}\nvolumes: {data: {}}\n"
	var document map[string]any
	if err := yaml.Unmarshal([]byte(source), &document); err != nil {
		t.Fatal(err)
	}
	fromSource, err := Names(source)
	if err != nil {
		t.Fatal(err)
	}
	fromDocument, err := NamesFromDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fromSource, fromDocument) {
		t.Fatalf("source names=%v document names=%v", fromSource, fromDocument)
	}
}

func TestNamesRejectsMalformedVolumeDefinitions(t *testing.T) {
	for _, source := range []string{
		"services: []\n",
		"services: {app: invalid}\n",
		"services: {app: {image: example/app}}\nvolumes: []\n",
		"services: {app: {image: example/app, volumes: invalid}}\n",
		"services: {app: {image: example/app, volumes: [42]}}\n",
	} {
		if _, err := Names(source); err == nil {
			t.Fatalf("accepted malformed Compose document %q", source)
		}
	}
}
