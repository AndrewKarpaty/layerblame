package attribute

import "testing"

func TestParseCreatedBy(t *testing.T) {
	tests := []struct {
		in       string
		cmd      string
		text     string
		buildkit bool
	}{
		{"RUN /bin/sh -c apt-get update # buildkit", "RUN", "apt-get update", true},
		{"COPY . /app # buildkit", "COPY", ". /app", true},
		{"WORKDIR /app", "WORKDIR", "/app", false},
		{"ENV NODE_VERSION=18.19.0", "ENV", "NODE_VERSION=18.19.0", false},
		{"/bin/sh -c #(nop)  ENV PATH=/usr/local/bin:$PATH", "ENV", "PATH=/usr/local/bin:$PATH", false},
		{"/bin/sh -c #(nop) COPY file:abc123 in /usr/local/bin/ ", "COPY", "file:abc123 in /usr/local/bin/", false},
		{"/bin/sh -c #(nop)  CMD [\"bash\"]", "CMD", "[\"bash\"]", false},
		{"/bin/sh -c apt-get update && apt-get install -y curl", "RUN", "apt-get update && apt-get install -y curl", false},
		{"|2 VERSION=1.0 DEBUG=0 /bin/sh -c make install", "RUN", "make install", false},
		{"ADD alpine-minirootfs.tar.gz / # buildkit", "ADD", "alpine-minirootfs.tar.gz /", true},
		{"/bin/sh -c #(nop) ADD file:xyz in / ", "ADD", "file:xyz in /", false},
		{"cmd /S /C echo windows", "RUN", "echo windows", false},
		{"", "", "", false},
		{"HEALTHCHECK &{[\"CMD-SHELL\" \"curl -f localhost\"]}", "HEALTHCHECK", "&{[\"CMD-SHELL\" \"curl -f localhost\"]}", false},
	}
	for _, tt := range tests {
		got := ParseCreatedBy(tt.in)
		if got.Cmd != tt.cmd || got.Text != tt.text || got.BuildKit != tt.buildkit {
			t.Errorf("ParseCreatedBy(%q) = %+v, want cmd=%q text=%q buildkit=%v",
				tt.in, got, tt.cmd, tt.text, tt.buildkit)
		}
	}
}
