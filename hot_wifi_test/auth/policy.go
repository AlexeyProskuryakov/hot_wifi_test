package auth

import (
	"regexp"
)

type PasswordPolicy struct {
	Length           int  `json:"length",bson:"length"`
	Numbers          bool `json:"numbers",bson:"numbers"`
	UppercaseLetters bool `json:"uppercase_letters",bson:"uppercase_letters"`
	LowercaseLetters bool `json:"lowercase_letters",bson:"lowercase_letters"`
	SpecialSymbols   bool `json:"special_symbols",bson:"special_symbols"`
}

func checkRegexp(reg, toCheck string) bool {
	r, _ := regexp.Compile(reg)
	f := r.FindString(toCheck)
	if len(f) == 0 {
		return false
	}
	return true
}

func (pp *PasswordPolicy) CheckPassword(password string) bool {
	if pp.Length > len(password) {
		return false
	}
	if pp.Numbers && !checkRegexp("\\d", password) {
		return false
	}
	if pp.LowercaseLetters && !checkRegexp("\\p{Ll}", password) {
		return false
	}
	if pp.SpecialSymbols && !checkRegexp("\\W", password) {
		return false
	}
	if pp.UppercaseLetters && !checkRegexp("\\p{Lu}", password) {
		return false
	}
	return true
}
