package findings

import "testing"

func TestK0sKubectl(t *testing.T) {
	cases := map[string]string{
		"kubectl -n shop logs api-1":                                  "k0s kubectl -n shop logs api-1",
		"kubectl get nodes\nkubectl top nodes":                        "k0s kubectl get nodes\nk0s kubectl top nodes",
		"kubectl get ns x -o json | kubectl replace -f -":             "k0s kubectl get ns x -o json | k0s kubectl replace -f -",
		"kubectl api-resources -o name | xargs -n 1 kubectl get -n x": "k0s kubectl api-resources -o name | xargs -n 1 k0s kubectl get -n x",
		"a && kubectl get pods; kubectl get svc":                      "a && k0s kubectl get pods; k0s kubectl get svc",
		"echo $(kubectl get pods -o name)":                            "echo $(k0s kubectl get pods -o name)",
		"k0s kubectl get pods":                                        "k0s kubectl get pods",
		"sudo crictl rmi --prune":                                     "sudo crictl rmi --prune",
		"df -h /var/lib/k0s":                                          "df -h /var/lib/k0s",
		"":                                                            "",
		"grep kubectl /var/log/x":                                     "grep kubectl /var/log/x",
	}
	for in, want := range cases {
		if got := K0sKubectl(in); got != want {
			t.Errorf("K0sKubectl(%q)\n got %q\nwant %q", in, got, want)
		}
		if again := K0sKubectl(want); again != want {
			t.Errorf("not idempotent: %q -> %q", want, again)
		}
	}
}
