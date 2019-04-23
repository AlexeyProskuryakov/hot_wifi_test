package auth

import (
	"testing"
	"net/http"
	"net/http/httptest"
	"fmt"
	"context"
	"go.mongodb.org/mongo-driver/mongo"
	"os"
	"encoding/json"
	"bytes"
	"github.com/gorilla/mux"
)

var sh *ServerHandler
var am *AuthMiddleWare

var as *AccountsStorage
var ps *PolicyStorage
var ss *SessionsStorage

var db *mongo.Database

var sToken string
var router *mux.Router

func setUp() {
	DB_NAME = fmt.Sprintf("%s_test", DB_NAME)
	db, _ = InitDb()
	db.Drop(context.TODO())

	as, _ = NewAccountsStorage()
	ps, _ = NewPolicyStorage()
	ss, _ = NewSessionStorage()

	if as == nil || ps == nil || ss == nil {
		panic("Can not connect to some storage")
	}
	authManager := &AuthManager{sessionsStorage: ss, accountsStorage: as}
	sh = &ServerHandler{accountsStorage: as, policyStorage: ps, authManager: authManager}
	am = &AuthMiddleWare{manager: authManager}

	sAcc := PrepareSupervisor(as)
	session, _ := authManager.Login(sAcc)
	sToken = session.Token

	router = Router(as, ps, ss)
}

func execResp(req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func tearDown() {
	db.Drop(context.TODO())
}

func TestMain(m *testing.M) {
	setUp()
	code := m.Run()
	tearDown()
	os.Exit(code)
}

func TestAccounts(t *testing.T) {
	req, err := http.NewRequest("GET", "/accounts", nil)
	req.Header.Set(HEADER_NAME, sToken)

	if err != nil {
		t.Fatal(err)
	}

	rr := execResp(req)

	if rr.Code != 200 {
		t.Errorf("wrong status code: got %v want %v",
			rr.Code, 200)
	}

	acc, _ := as.GetAccount(SUPERVISOR_LOGIN)

	expected := fmt.Sprintf(`[{"id":"%s","login":"%s","isExternalAccount":false}]`, acc.ID.Hex(), SUPERVISOR_LOGIN)
	if rr.Body.String() != expected {
		t.Errorf("unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestAccountCycle(t *testing.T) {
	acc := Account{Login: "test", Password: "testTEST123", IsExternalAccount: false}

	data, _ := json.Marshal(&acc)
	req, _ := http.NewRequest("POST", "/accounts", bytes.NewBuffer(data))
	req.Header.Set(HEADER_NAME, sToken)
	rr := execResp(req)

	if rr.Code != 200 {
		t.Errorf("wrong status code: got %v want %v",
			rr.Code, 200)
	}
	storedAcc, _ := as.GetAccount("test")
	expected := fmt.Sprintf(`{"ok":true,"id":"%s"}`, storedAcc.ID.Hex())
	if rr.Body.String() != expected {
		t.Errorf("unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}

	data, _ = json.Marshal(&LoginData{Login: "test", Password: "testTEST123"})
	req, _ = http.NewRequest("POST", "/api/accounts/login", bytes.NewBuffer(data))
	rr = execResp(req)

	if rr.Code != 200 {
		t.Errorf("wrong status code: got %v want %v",
			rr.Code, 200)
	}
	sess, _ := ss.GetSessionByLogin("test")
	expected = fmt.Sprintf(`{"ok":true,"auth-token":"%s"}`, sess.Token)
	if rr.Body.String() != expected {
		t.Errorf("unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}

	data, _ = json.Marshal(&ChangePasswordData{Old: "testTEST123", New: "tT1o0"})
	req, _ = http.NewRequest("PUT", fmt.Sprintf("/api/accounts/%s/password", storedAcc.ID.Hex()), bytes.NewBuffer(data))
	req.Header.Set(HEADER_NAME, sess.Token)
	rr = execResp(req)

	if rr.Code != 200 {
		t.Errorf("wrong status code: got %v want %v",
			rr.Code, 200)
	}
	expected = `{"ok":true}`
	if rr.Body.String() != expected {
		t.Errorf("unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}

	req, _ = http.NewRequest("DELETE", fmt.Sprintf("/api/accounts/%s", storedAcc.ID.Hex()), nil)
	req.Header.Set(HEADER_NAME, sess.Token)
	rr = execResp(req)

	if rr.Code != 200 {
		t.Errorf("wrong status code: got %v want %v",
			rr.Code, 200)
	}
	expected = `{"ok":true}`
	if rr.Body.String() != expected {
		t.Errorf("unexpected body: got %v want %v",
			rr.Body.String(), expected)

	}
}
