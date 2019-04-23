package auth

import "testing"

func TestPolicySmoke(t *testing.T) {
	p := PasswordPolicy{Length: 2}
	if p.CheckPassword("1") {
		t.Error("Policy length not work")
	}

	p = PasswordPolicy{Numbers: true}
	if p.CheckPassword("abc") {
		t.Error("Policy numbers not work")
	}

	p = PasswordPolicy{UppercaseLetters: true}
	if p.CheckPassword("abc") {
		t.Error("Policy uppercase not work")
	}

	p = PasswordPolicy{LowercaseLetters: true}
	if p.CheckPassword("ABC") {
		t.Error("Policy lowercase not work")
	}

	p = PasswordPolicy{SpecialSymbols: true}
	if p.CheckPassword("abc") {
		t.Error("Policy spec symbols not work")
	}

	p = PasswordPolicy{Length: 3, Numbers: true, UppercaseLetters: true, LowercaseLetters: true, SpecialSymbols: true}
	if !p.CheckPassword("aA.1") {
		t.Error("Policy not work")
	}
}
