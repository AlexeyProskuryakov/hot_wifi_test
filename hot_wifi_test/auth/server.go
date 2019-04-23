package auth

import (
	"net/http"
	"github.com/gorilla/mux"
	"encoding/json"
	"errors"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type ServerHandler struct {
	accountsStorage *AccountsStorage
	authManager     *AuthManager
	policyStorage   *PolicyStorage
}

func (sh *ServerHandler) getAccounts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	accounts, err := sh.accountsStorage.GetAccountsViews()
	if err != nil {
		WriteError(w, err, 500)
		return
	}
	result, err := json.Marshal(accounts)
	if err != nil {
		WriteError(w, err, 500)
		return
	}
	w.Write(result)
	w.WriteHeader(200)

}

type AccountCreateResponse struct {
	OK bool   `json:"ok"`
	Id string `json:"id"`
}

func (sh *ServerHandler) createAccount(w http.ResponseWriter, r *http.Request) {
	data, err := ReadBody(r)
	if err != nil {
		WriteError(w, err, 500)
		return
	}

	var account Account
	err = json.Unmarshal(data, &account)
	if err != nil {
		WriteError(w, err, 500)
		return
	}

	policy, err := sh.policyStorage.GetPolicy()
	if err != nil {
		WriteError(w, err, 500)
		return
	}

	if !policy.CheckPassword(account.Password) {
		WriteError(w, errors.New("Password is invalid"), 401)
		return
	}
	account.SetNewPassword(account.Password)
	id, err := sh.accountsStorage.SetAccount(&account)
	if err != nil {
		WriteError(w, err, 500)
	}
	objId := id.(primitive.ObjectID)
	WriteOK(w, AccountCreateResponse{Id: objId.Hex(), OK: true})
}

type ChangePasswordData struct {
	Old string `json:"oldPassword"`
	New string `json:"newPassword"`
}

func (sh *ServerHandler) changePassword(w http.ResponseWriter, r *http.Request, ownerAcc *Account) {
	vars := mux.Vars(r)
	id := vars["id"]

	if ownerAcc.ID.Hex() != id {
		WriteError(w, errors.New("You can change only own password"), 500)
		return
	}
	acc, err := sh.accountsStorage.GetAccountById(id)
	if err != nil {
		WriteError(w, err, 500)
		return
	}

	data, err := ReadBody(r)
	if err != nil {
		WriteError(w, err, 500)
		return
	}
	var cp ChangePasswordData
	err = json.Unmarshal(data, &cp)
	if err != nil {
		WriteError(w, err, 500)
		return
	}

	if acc.PasswordHash == CreateHash(cp.Old) {
		policy, err := sh.policyStorage.GetPolicy()
		if err != nil {
			WriteError(w, err, 500)
			return
		}
		if !policy.CheckPassword(cp.New) {
			WriteError(w, errors.New("New password is invalid"), 401)
			return
		}
		acc.SetNewPassword(cp.New)
		_, err = sh.accountsStorage.SetAccount(acc)
		if err != nil {
			WriteError(w, err, 500)
		} else {
			WriteOK(w, OkResponse{OK: true})
		}
	} else {
		WriteError(w, errors.New("Bad old password"), 401)
	}
}
func (sh *ServerHandler) deleteAccount(w http.ResponseWriter, r *http.Request, acc *Account) {
	vars := mux.Vars(r)
	id := vars["id"]
	if acc.ID.Hex() != id {
		WriteError(w, errors.New("You can delete only own account"), 401)
		return
	}
	err := sh.accountsStorage.DeleteAccount(id)
	if err != nil {
		WriteError(w, err, 500)
		return
	}
	err = sh.authManager.Logout(acc.Login)
	if err != nil {
		WriteError(w, err, 500)
		return
	}
	WriteOK(w, OkResponse{OK: true})

}

type LoginData struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}
type LoginResponse struct {
	OK    bool   `json:"ok"`
	Token string `json:"auth-token"`
}

func (sh *ServerHandler) login(w http.ResponseWriter, r *http.Request) {
	data, err := ReadBody(r)
	if err != nil {
		WriteError(w, err, 500)
		return
	}
	var loginData LoginData
	err = json.Unmarshal(data, &loginData)
	if err != nil {
		WriteError(w, err, 500)
		return
	}

	acc, err := sh.accountsStorage.GetAccount(loginData.Login)
	if acc == nil {
		WriteError(w, errors.New("Can not found account with this login"), 400)
		return
	}
	if !acc.IsPasswordExpire() {
		WriteError(w, errors.New("Password is expired, change it"), 403)
		return
	}
	sess, err := sh.authManager.Login(acc)
	if err != nil {
		WriteError(w, err, 500)
		return
	}
	WriteOK(w, &LoginResponse{OK: true, Token: sess.Token})
}

type LogoutData struct {
	Login string `json:"login"`
}

func (sh *ServerHandler) logout(w http.ResponseWriter, r *http.Request) {
	data, err := ReadBody(r)
	if err != nil {
		WriteError(w, err, 500)
		return
	}
	var logoutData LogoutData
	err = json.Unmarshal(data, &logoutData)
	if err != nil {
		WriteError(w, err, 500)
		return
	}
	err = sh.authManager.Logout(logoutData.Login)
	if err != nil {
		WriteError(w, err, 500)
	}
	WriteOK(w, &OkResponse{OK: true})
}

func (sh *ServerHandler) setPolicy(w http.ResponseWriter, r *http.Request) {
	data, err := ReadBody(r)
	if err != nil {
		WriteError(w, err, 500)
		return
	}
	var policyData PasswordPolicy
	err = json.Unmarshal(data, &policyData)
	if err != nil {
		WriteError(w, err, 500)
		return
	}
	err = sh.policyStorage.SetPolicy(&policyData)
	if err != nil {
		WriteError(w, err, 500)
	}
	WriteOK(w, &OkResponse{OK: true})
}

func Router(accountsStorage *AccountsStorage, policyStorage *PolicyStorage, sessionStorage *SessionsStorage) *mux.Router {
	authManager := AuthManager{sessionsStorage: sessionStorage, accountsStorage: accountsStorage}
	sh := ServerHandler{accountsStorage: accountsStorage, policyStorage: policyStorage, authManager: &authManager}
	am := AuthMiddleWare{manager: &authManager}

	r := mux.NewRouter()
	r.HandleFunc("/accounts", Json(am.MustBeRoot(sh.createAccount))).Methods("POST")
	r.HandleFunc("/accounts", Json(am.MustBeLoggedIn(sh.getAccounts))).Methods("GET")
	r.HandleFunc("/api/accounts/{id}", Json(am.MustChangeYourth(sh.deleteAccount))).Methods("DELETE")
	r.HandleFunc("/api/accounts/{id}/password", Json(am.MustChangeYourth(sh.changePassword))).Methods("PUT")
	r.HandleFunc("/api/accounts/login", Json(sh.login)).Methods("POST")
	r.HandleFunc("/api/accounts/logout", Json(am.MustBeLoggedIn(sh.logout))).Methods("POST")
	r.HandleFunc("/api/accounts/password/policy", Json(am.MustBeRoot(sh.setPolicy))).Methods("POST")

	return r
}
