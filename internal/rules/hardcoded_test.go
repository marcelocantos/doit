package rules

import "testing"

func TestCheckRmCatastrophic(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"rf root", []string{"-rf", "/"}, true},
		{"r root", []string{"-r", "/"}, true},
		{"R root", []string{"-R", "/"}, true},
		{"rf dot", []string{"-rf", "."}, true},
		{"rf dotdot", []string{"-rf", ".."}, true},
		{"rf tilde", []string{"-rf", "~"}, true},
		{"rf tilde slash", []string{"-rf", "~/"}, true},
		{"rf root trailing slash", []string{"-rf", "//"}, true},
		{"r safe path", []string{"-rf", "/tmp/safe"}, false},
		{"no recursive flag", []string{"file.txt"}, false},
		{"f only root", []string{"-f", "/"}, false},
		{"recursive with safe path", []string{"-r", "build/"}, false},
		{"combined fr root", []string{"-fr", "/"}, true},
		{"multiple args mixed", []string{"-rf", "build/", "/"}, true},
		{"r flag separate", []string{"-r", "-f", "/"}, true},

		// Non-rm capabilities should be ignored.
		{"not rm", []string{"-rf", "/"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capName := "rm"
			if tt.name == "not rm" {
				capName = "grep"
			}
			err := checkRmCatastrophic(capName, tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkRmCatastrophic(%q, %v) error = %v, wantErr %v",
					capName, tt.args, err, tt.wantErr)
			}
		})
	}
}

func TestCheckGitCheckoutAll(t *testing.T) {
	tests := []struct {
		name    string
		cap     string
		args    []string
		wantErr bool
	}{
		{"checkout dot", "git", []string{"checkout", "."}, true},
		{"checkout -- dot", "git", []string{"checkout", "--", "."}, true},
		{"checkout branch", "git", []string{"checkout", "feature"}, false},
		{"checkout file", "git", []string{"checkout", "--", "file.go"}, false},
		{"not git", "grep", []string{"checkout", "."}, false},
		{"not checkout", "git", []string{"status"}, false},
		{"checkout dot slash", "git", []string{"checkout", "./"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckGitCheckoutAll(tt.cap, tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckGitCheckoutAll(%q, %v) error = %v, wantErr %v",
					tt.cap, tt.args, err, tt.wantErr)
			}
		})
	}
}
