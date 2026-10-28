package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// The console must make every gated write through a store call that
// re-checks the acting administrator in its transaction. This guards the
// wiring itself: a handler switched back to an unchecked call, or an
// Access save passed without the proof, fails here even though the store
// tests still pass.
func TestConsoleWritesPassTheActorProof(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "admin.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	unchecked := map[string]string{
		"SetPassword": "SetPasswordBy", "SetAccountDisabled": "SetAccountDisabledBy",
		"SetAccountAdmin": "SetAccountAdminBy", "RevokeAllAuthSessions": "RevokeAllAuthSessionsBy",
		"CreatePasswordAccount": "CreateAccountBy", "SetApplicationDisabled": "SetApplicationDisabledBy",
		"SetAccountMFARequired": "SetAccountMFARequiredBy", "ResetMFA": "ResetMFABy",
		"SetMFAPolicy": "SetMFAPolicyBy", "SetApplicationAccess": "SaveAccountAccess",
		"SetApplicationAccessWithSettings": "SaveAccountAccess",
	}
	// The proof argument each checked call must receive (revokeProof is nil
	// only for an administrator signing themself out, which is ungated).
	proofArg := map[string]int{
		"SetPasswordBy": 5, "SetAccountDisabledBy": 4, "SetAccountAdminBy": 4, "RevokeAllAuthSessionsBy": 3,
		"CreateAccountBy": 3, "SetApplicationDisabledBy": 4, "SetAccountMFARequiredBy": 4, "ResetMFABy": 4,
		"SetMFAPolicyBy": 4, "SaveAccountAccess": 4,
	}
	seen := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if inner, ok := sel.X.(*ast.SelectorExpr); !ok || inner.Sel.Name != "store" {
			return true
		}
		name := sel.Sel.Name
		if by, bad := unchecked[name]; bad {
			t.Errorf("admin.go calls store.%s; the console must use %s with the actor proof", name, by)
		}
		if i, ok := proofArg[name]; ok {
			seen[name] = true
			arg, ok := call.Args[i].(*ast.Ident)
			if !ok || (arg.Name != "proof" && (name != "RevokeAllAuthSessionsBy" || arg.Name != "revokeProof")) {
				t.Errorf("store.%s is not passed the actor proof (argument %d)", name, i)
			}
		}
		return true
	})
	for name := range proofArg {
		if !seen[name] {
			t.Errorf("admin.go no longer calls store.%s; update this test with the call that replaced it", name)
		}
	}
}
