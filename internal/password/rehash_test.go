package password

import "testing"

func TestVerifyUpgradeNeverReducesParameters(t *testing.T) {
	cases := []struct {
		name    string
		params  Params
		upgrade bool
	}{
		{"current", Recommended, false},
		{"lower memory", Params{32768, 3, 2, 16, 32}, true},
		{"lower iterations", Params{65536, 2, 2, 16, 32}, true},
		{"shorter salt and key", Params{65536, 3, 2, 8, 16}, true},
		{"higher memory", Params{131072, 3, 2, 16, 32}, false},
		{"mixed costs", Params{32768, 4, 2, 16, 32}, false},
		{"longer salt", Params{32768, 2, 2, 32, 32}, false},
		{"longer key", Params{32768, 2, 2, 16, 64}, false},
		{"different lanes", Params{32768, 2, 1, 16, 32}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := HashWithParams("correct horse battery staple", tc.params)
			if err != nil {
				t.Fatal(err)
			}
			ok, upgrade, err := Verify(encoded, "correct horse battery staple")
			if err != nil || !ok || upgrade != tc.upgrade {
				t.Fatalf("verification: ok=%v upgrade=%v err=%v; want upgrade=%v", ok, upgrade, err, tc.upgrade)
			}
		})
	}
}

func TestRehashVerifiedPreservesLegacyPassword(t *testing.T) {
	const plain = "old-short"
	if Validate(plain) == nil {
		t.Fatal("fixture must fail current new-password policy")
	}
	old, err := hashWithParams(plain, Params{32768, 2, 2, 16, 32})
	if err != nil {
		t.Fatal(err)
	}
	if ok, upgrade, err := Verify(old, "wrong"); err != nil || ok || upgrade {
		t.Fatalf("wrong password: ok=%v upgrade=%v err=%v", ok, upgrade, err)
	}
	if ok, upgrade, err := Verify(old, plain); err != nil || !ok || !upgrade {
		t.Fatalf("legacy verification: ok=%v upgrade=%v err=%v", ok, upgrade, err)
	}
	upgraded, err := RehashVerified(plain)
	if err != nil {
		t.Fatal(err)
	}
	if ok, upgrade, err := Verify(upgraded, plain); err != nil || !ok || upgrade {
		t.Fatalf("upgraded verification: ok=%v upgrade=%v err=%v", ok, upgrade, err)
	}
}
