package auth

import (
	"os"
	"strconv"
	"fmt"
)

func GetVariableAsInt(varName string) int {
	val := os.Getenv(varName)
	result, err := strconv.Atoi(val)
	if err != nil {
		panic(fmt.Sprintf("Error at parse %v (%s) to int: %s", varName, val, err))
	}
	return result
}

var SESSION_TTL = GetVariableAsInt("SESSION_TTL")
var PASSWORD_TTL = GetVariableAsInt("PASSWORD_TTL")
var HEADER_NAME = os.Getenv("HEADER_NAME")

var DB_PORT = GetVariableAsInt("MONGO_PORT")
var DB_HOST = os.Getenv("MONGO_HOST")
var DB_USER = os.Getenv("MONGO_USER")
var DB_PASS = os.Getenv("MONGO_PWD")
var DB_NAME = os.Getenv("MONGO_DB")

var SUPERVISOR_LOGIN = os.Getenv("SUPERVISOR_LOGIN")
var SUPERVISOR_PASSWORD = os.Getenv("SUPERVISOR_PASSWORD")

var HOST = os.Getenv("HOST")
var PORT = GetVariableAsInt("PORT")

var DEFAULT_POLICY = &PasswordPolicy{Length: 4, LowercaseLetters: true, UppercaseLetters: true, Numbers: true}
