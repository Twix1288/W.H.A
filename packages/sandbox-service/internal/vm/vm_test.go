package vm

import "testing"

// ValidateLanguage must fail closed on anything outside the known set, so an
// unexpected value can never fall through to a shell in a backend's dispatch.
func TestValidateLanguage(t *testing.T) {
	cases := []struct {
		lang    string
		wantErr bool
	}{
		{"python", false},
		{"bash", false},
		{"", false}, // empty is treated as bash by the backends
		{"sh", true},
		{"ruby", true},
		{"python; rm -rf /", true},
		{"PYTHON", true}, // case-sensitive on purpose
	}
	for _, c := range cases {
		err := ValidateLanguage(c.lang)
		if (err != nil) != c.wantErr {
			t.Errorf("ValidateLanguage(%q) error = %v, wantErr = %v", c.lang, err, c.wantErr)
		}
	}
}
