package parser

import "testing"

func TestLogicalLineGrouping(t *testing.T) {
	src := []byte("rule r {\n" +
		"  meta:\n" +
		"    author = \"a\"\n" +
		"    description = \"d\"\n" +
		"  events:\n" +
		"    $e.metadata.event_type = \"X\"\n" +
		"    re.regex(\n" +
		"      $e.principal.hostname,\n" +
		"      `^evil`\n" +
		"    )\n" +
		"    $e.target.port = 80 +\n" +
		"      1\n" +
		"  condition:\n" +
		"    $e and\n" +
		"    #e > 3\n" +
		"}\n")

	f, errs := Parse(src)
	if len(errs) != 0 {
		t.Fatalf("unexpected parse errors: %v", errs)
	}
	r := f.Rules[0]

	if got := len(r.Events.Statements); got != 3 {
		t.Fatalf("events: want 3 logical statements, got %d", got)
	}
	if got := len(r.Condition.Statements); got != 1 {
		t.Fatalf("condition: want 1 logical statement, got %d", got)
	}
	if got := len(r.Meta.Entries); got != 2 {
		t.Fatalf("meta: want 2 entries, got %d (meta lines must not merge)", got)
	}
}
