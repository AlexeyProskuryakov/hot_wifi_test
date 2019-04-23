package auth

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"time"
	"net/http"
	"errors"
)

//TODO use https://github.com/opinary/jwt

type Session struct {
	Login string `bson:"login"`
	Token string `json:"auth-token",bson:"token"`
}

type AuthManager struct {
	sessionsStorage *SessionsStorage
	accountsStorage *AccountsStorage
}

func (a *AuthManager) FromToken(token string) (*Account, error) {
	sess, err := a.sessionsStorage.GetSession(token)
	if err != nil {
		return nil, err
	}
	if sess == nil {
		return nil, nil
	}
	acc, err := a.accountsStorage.GetAccount(sess.Login)
	if err != nil {
		return nil, err
	}
	return acc, nil
}

func CreateHash(input string) string {
	h := sha1.New()
	h.Write([]byte(input))
	sha1_hash := hex.EncodeToString(h.Sum(nil))
	return sha1_hash
}

func (a *AuthManager) Login(account *Account) (*Session, error) {
	token := CreateHash(fmt.Sprintf("%s %s %v %v", account.Login, account.Password, account.PasswordCreated, time.Now().Unix()))
	s := Session{Login: account.Login, Token: token}
	a.sessionsStorage.SetSession(&s)
	return &s, nil
}

func (a *AuthManager) Logout(login string) error {
	return a.sessionsStorage.DeleteSession(login)
}

type HttpHandlerFunc func(http.ResponseWriter, *http.Request)
type HttpHandlerFuncWithAcc func(http.ResponseWriter, *http.Request, *Account)

type AuthMiddleWare struct {
	manager *AuthManager
}

func (a *AuthMiddleWare) MustBeLoggedIn(next HttpHandlerFunc) HttpHandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		token := req.Header.Get(HEADER_NAME)
		account, _ := a.manager.FromToken(token)
		if account == nil {
			WriteError(res, errors.New("You must login"), 401)
			return
		}
		next(res, req)
	}
}

func (a *AuthMiddleWare) MustBeRoot(next HttpHandlerFunc) HttpHandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		token := req.Header.Get(HEADER_NAME)
		account, _ := a.manager.FromToken(token)

		if account == nil || !account.IsSupervisor() {
			WriteError(res, errors.New("It can do only supervisor"), 401)
			return
		}
		next(res, req)
	}
}

func (a *AuthMiddleWare) MustChangeYourth(next HttpHandlerFuncWithAcc) HttpHandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		token := req.Header.Get(HEADER_NAME)
		account, _ := a.manager.FromToken(token)
		if account == nil {
			WriteError(res, errors.New("You must login"), 401)
			return
		}
		next(res, req, account)
	}
}
