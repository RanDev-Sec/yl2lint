package lexer

import "testing"

func TestHashHandling(t *testing.T) {
	// No space after # but the yl2lint prefix: must be a comment.
	toks, comments, errs := TokenizeWithComments([]byte("#yl2lint-disable: udm-schema\n$e"))
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(comments) != 1 || comments[0].Text != "yl2lint-disable: udm-schema" {
		t.Fatalf("directive not captured as comment: %+v", comments)
	}
	for _, tok := range toks {
		if tok.Type == COUNTVAR {
			t.Fatalf("directive misclassified as count variable %q", tok.Literal)
		}
	}

	// A real count variable must be untouched.
	toks, _, _ = TokenizeWithComments([]byte("#login > 3"))
	if toks[0].Type != COUNTVAR || toks[0].Literal != "#login" {
		t.Fatalf("count variable broken: %+v", toks[0])
	}
}
