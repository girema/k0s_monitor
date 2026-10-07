// Package scenarios holds the broken-on-purpose objects of the end-to-end
// test. The test here catches typos before a slow run against real k0s.
package scenarios

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/scheme"
)

func TestScenariosDecode(t *testing.T) {
	// Strict: unknown or misspelled fields are errors.
	strict := serializer.NewCodecFactory(scheme.Scheme, serializer.EnableStrict).UniversalDeserializer()
	files, _ := filepath.Glob("*.yaml")
	if len(files) == 0 {
		t.Fatal("no scenarios")
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
		for i := 0; ; i++ {
			var raw runtime.RawExtension
			if err := dec.Decode(&raw); err != nil {
				if !errors.Is(err, io.EOF) {
					t.Errorf("%s document %d: %v", f, i, err)
				}
				break
			}
			if len(bytes.TrimSpace(raw.Raw)) == 0 {
				continue
			}
			if _, _, err := strict.Decode(raw.Raw, nil, nil); err != nil {
				t.Errorf("%s document %d: %v", f, i, err)
			}
		}
	}
}
