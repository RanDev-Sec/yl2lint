package schema

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEmbeddedDictionary(t *testing.T) {
	if !Valid("principal.user.userid") {
		t.Fatal("known field rejected")
	}
	if Valid("principal.user.useridd") {
		t.Fatal("typo accepted")
	}
	if !Valid("additional.fields.anything.at.all") {
		t.Fatal("prefix family rejected")
	}
	if !IsRepeated("principal.ip") {
		t.Fatal("principal.ip should be repeated")
	}
	if typ, _ := TypeOf("target.file.size"); typ != "int" {
		t.Fatalf("target.file.size type = %q, want int", typ)
	}
	if near := Nearest("principal.user.useridd"); near != "principal.user.userid" {
		t.Fatalf("Nearest = %q", near)
	}
}

func TestLoadExtraMerges(t *testing.T) {
	dir := t.TempDir()
	extra := filepath.Join(dir, "extra.yaml")
	content := "fields:\n  - {path: vendor.custom_field, type: string}\n"
	if err := os.WriteFile(extra, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := LoadExtra(extra, false); err != nil {
		t.Fatal(err)
	}
	if !Valid("vendor.custom_field") {
		t.Fatal("merged field not visible")
	}
	if !Valid("metadata.event_type") {
		t.Fatal("merge must not drop the embedded dictionary")
	}
}
