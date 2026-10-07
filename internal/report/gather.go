package report

import (
	"context"
	"errors"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/kubectl/pkg/describe"

	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/podview"
	"k0s_monitor/internal/remedy"
)

// describeObject returns `kubectl describe` output for an object, with
// environment values of secret-looking names and recognizable credentials
// masked.
func describeObject(ctx context.Context, conn *cluster.Conn, ref findings.ObjectRef, group string) (string, error) {
	d, err := describer(conn, ref.Kind, group)
	if err != nil {
		return "", err
	}
	// Describers take no context: run it aside and stop waiting when the
	// context ends. The client's own timeout ends the call itself.
	type result struct {
		out string
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := d.Describe(ref.Namespace, ref.Name, describe.DescriberSettings{ShowEvents: true, ChunkSize: 500})
		done <- result{out, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			return "", r.err
		}
		return remedy.RedactText(podview.MaskDescribe(r.out)), nil
	case <-ctx.Done():
		return "", fmt.Errorf("no answer in time: %w", ctx.Err())
	}
}

func describer(conn *cluster.Conn, kind, group string) (describe.ResourceDescriber, error) {
	if conn.Config != nil {
		cfg := rest.CopyConfig(conn.Config)
		cfg.Timeout = callTimeout
		if d, ok := describe.DescriberFor(schema.GroupKind{Group: group, Kind: kind}, cfg); ok {
			return d, nil
		}
		return nil, fmt.Errorf("kubectl can't describe a %s", kind)
	}
	// Without a REST configuration (tests), the describers that need only
	// a clientset.
	var cs kubernetes.Interface = conn.Client
	switch kind {
	case "Pod":
		return &describe.PodDescriber{Interface: cs}, nil
	case "Node":
		return &describe.NodeDescriber{Interface: cs}, nil
	case "Service":
		return &describe.ServiceDescriber{Interface: cs}, nil
	case "PersistentVolumeClaim":
		return &describe.PersistentVolumeClaimDescriber{Interface: cs}, nil
	case "PersistentVolume":
		return &describe.PersistentVolumeDescriber{Interface: cs}, nil
	case "ReplicaSet":
		return &describe.ReplicaSetDescriber{Interface: cs}, nil
	case "DaemonSet":
		return &describe.DaemonSetDescriber{Interface: cs}, nil
	case "Job":
		return &describe.JobDescriber{Interface: cs}, nil
	}
	return nil, fmt.Errorf("kubectl can't describe a %s here", kind)
}

// readLog reads the end of a container's log.
func readLog(ctx context.Context, conn *cluster.Conn, ref findings.ObjectRef, container string, previous bool) (string, error) {
	text, err := podview.ReadLog(ctx, conn.Client, ref.Namespace, ref.Name, podview.LogOptions{Container: container, Previous: previous, Tail: logTail})
	if err != nil {
		if errors.Is(err, podview.ErrLogGone) {
			return "", errors.New("the node no longer has this run of the container, so its log is gone")
		}
		if text == "" {
			return "", err
		}
	}
	if len(text) > maxLogBytes {
		text = "[… the beginning is cut: the report keeps the last " + fmt.Sprint(maxLogBytes>>10) + " KiB]\n" + text[len(text)-maxLogBytes:]
	}
	return text, nil
}
