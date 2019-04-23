package auth

import (
	"time"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Account struct {
	ID                *primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Login             string              `json:"login",bson:"login"`
	PasswordHash      string              `bson:"password_hash"`
	Password          string              `json:"password"`
	PasswordCreated   int64               `bson:"password_created"`
	IsExternalAccount bool                `json:"isExternalAccount",bson:"is_external_account"`
}

func (a *Account) IsSupervisor() bool {
	return a.Login == SUPERVISOR_LOGIN
}

func (a *Account) IsPasswordExpire() bool {
	if !a.IsSupervisor() && !a.IsExternalAccount && (a.PasswordCreated+int64(PASSWORD_TTL) < time.Now().Unix()) {
		return false
	}
	return true
}

func (a *Account) SetNewPassword(new string) {
	a.Password = new
	a.PasswordHash = CreateHash(new)
	a.PasswordCreated = time.Now().Unix()
}

type AccountView struct {
	ID                *primitive.ObjectID `json:"id" bson:"_id"`
	Login             string              `json:"login",bson:"login"`
	IsExternalAccount bool                `json:"isExternalAccount",bson:"isExternalAccount"`
}
