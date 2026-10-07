package remedy

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func template() *corev1.PodTemplateSpec {
	return &corev1.PodTemplateSpec{Spec: corev1.PodSpec{
		ServiceAccountName: "api",
		Volumes:            []corev1.Volume{{Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "api-v1"}}}}},
		Containers: []corev1.Container{{
			Name:  "api",
			Image: "shop/api:2.4.0",
			Env: []corev1.EnvVar{
				{Name: "DB_HOST", Value: "postgres"},
				{Name: "DB_PASSWORD", Value: "hunter22"},
				{Name: "API_TOKEN", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "api"}, Key: "token"}}},
			},
			Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")}},
			LivenessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/health", Port: intstr.FromInt(8080)}},
				InitialDelaySeconds: 10},
			VolumeMounts: []corev1.VolumeMount{{Name: "config", MountPath: "/etc/api", ReadOnly: true}},
			Ports:        []corev1.ContainerPort{{ContainerPort: 8080, Protocol: corev1.ProtocolTCP}},
		}},
	}}
}

func TestTemplateChanges(t *testing.T) {
	old, cur := template(), template()
	c := &cur.Spec.Containers[0]
	c.Image = "shop/api:2.5.0"
	c.Env[0].Value = "postgresql"
	c.Env[1].Value = "correct-horse"
	c.Env = append(c.Env, corev1.EnvVar{Name: "LOG_LEVEL", Value: "debug"}, corev1.EnvVar{Name: "DATABASE_URL", Value: "postgres://shop:s3cret@db/shop"})
	c.Args = []string{"--db-password=s3cret"}
	c.Resources.Limits[corev1.ResourceMemory] = resource.MustParse("128Mi")
	c.LivenessProbe.InitialDelaySeconds = 0
	cur.Spec.Volumes[0].ConfigMap.Name = "api-v2"
	cur.Spec.InitContainers = []corev1.Container{{Name: "migrate", Image: "shop/api:2.5.0"}}

	var got []string
	for _, ch := range TemplateChanges(old, cur) {
		got = append(got, ch.String())
	}
	want := []string{
		"volume config ConfigMap api-v1 → ConfigMap api-v2",
		"migrate: container added (shop/api:2.5.0)",
		"api: image shop/api:2.4.0 → shop/api:2.5.0",
		"api: args added (--db-password=" + Mask + ")",
		"api: env DATABASE_URL added (postgres://shop:" + Mask + "@db/shop)",
		"api: env DB_HOST postgres → postgresql",
		"api: env DB_PASSWORD changed (value hidden)",
		"api: env LOG_LEVEL added (debug)",
		"api: memory limit 256Mi → 128Mi",
		"api: liveness probe GET :8080/health after 10s, every 10s, timeout 1s, 3 failures → GET :8080/health after 0s, every 10s, timeout 1s, 3 failures",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("changes:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, g := range got {
		if strings.Contains(g, "hunter22") || strings.Contains(g, "correct-horse") || strings.Contains(g, "s3cret") {
			t.Errorf("a secret value shows: %s", g)
		}
	}
}

func TestTemplateChangesSecretSame(t *testing.T) {
	// A password that didn't change isn't reported, though both are masked.
	if ch := TemplateChanges(template(), template()); len(ch) != 0 {
		t.Errorf("identical templates: %+v", ch)
	}
}

func TestTemplateChangesRestartOnly(t *testing.T) {
	old, cur := template(), template()
	cur.Annotations = map[string]string{restartedAt: "2026-09-27T14:00:00Z"}
	ch := TemplateChanges(old, cur)
	if len(ch) != 1 || !strings.Contains(ch[0].String(), "nothing else changed") {
		t.Errorf("restart only: %+v", ch)
	}
	// A restart with a real change reports only the change.
	cur.Spec.Containers[0].Image = "shop/api:2.5.0"
	if ch := TemplateChanges(old, cur); len(ch) != 1 || ch[0].What != "image" {
		t.Errorf("restart and image: %+v", ch)
	}
	if TemplateChanges(nil, cur) != nil {
		t.Error("a missing template has changes")
	}
}

func TestTemplateChangesRemoved(t *testing.T) {
	old, cur := template(), template()
	cur.Spec.Containers[0].LivenessProbe = nil
	cur.Spec.Containers[0].Env = cur.Spec.Containers[0].Env[:1]
	var got []string
	for _, ch := range TemplateChanges(old, cur) {
		got = append(got, ch.String())
	}
	want := []string{
		"api: env API_TOKEN removed (was Secret api key token)",
		"api: env DB_PASSWORD removed (was " + Mask + ")",
		"api: liveness probe removed (was GET :8080/health after 10s, every 10s, timeout 1s, 3 failures)",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("changes:\n%s", strings.Join(got, "\n"))
	}
}
