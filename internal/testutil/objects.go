// Package testutil loads Kubernetes objects from YAML fixtures for tests.
package testutil

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/scheme"
)

// Objects decodes every document of a multi-document YAML file.
func Objects(t testing.TB, path string) []runtime.Object {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	var out []runtime.Object
	for {
		var raw runtime.RawExtension
		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatal(err)
		}
		if len(bytes.TrimSpace(raw.Raw)) == 0 {
			continue
		}
		obj, _, err := scheme.Codecs.UniversalDeserializer().Decode(raw.Raw, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, obj)
	}
	return out
}
