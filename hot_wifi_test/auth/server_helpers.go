package auth

import (
	"net/http"
	"encoding/json"
	"fmt"
	"log"
	"io/ioutil"
)

type OkResponse struct {
	OK bool `json:"ok"`
}

func WriteOK(w http.ResponseWriter, data interface{}) {
	res, err := json.Marshal(data)
	if err != nil {
		WriteError(w, err, 500)
		return
	}
	w.Write(res)
	w.WriteHeader(200)
}

type ErrorResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

func WriteError(w http.ResponseWriter, err error, statusCode int) {
	res, err := json.Marshal(&ErrorResponse{Error: err.Error()})
	if err != nil {
		log.Printf(fmt.Sprintf("Can not marshall error: %s", err))
		w.WriteHeader(500)
		return
	}
	w.Write(res)
	w.WriteHeader(statusCode)
}

func ReadBody(r *http.Request) ([]byte, error) {
	bodyReader, err := r.GetBody()
	if err != nil {
		log.Printf("Error at get body from request %v", err)
		return nil, err
	}
	data, err := ioutil.ReadAll(bodyReader)
	if err != nil {
		log.Printf("Error at read body from request %v", err)
		return nil, err
	}
	return data, err
}

func Json(next HttpHandlerFunc) HttpHandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		next(writer, request)
	}
}

func PrepareSupervisor(as *AccountsStorage) *Account {
	acc, err := as.GetAccount(SUPERVISOR_LOGIN)
	if err != nil {
		panic(err)
	}
	if acc == nil {
		acc = &Account{Login: SUPERVISOR_LOGIN}
		acc.SetNewPassword(SUPERVISOR_PASSWORD)
		as.SetAccount(acc)
		log.Println("Supervisor initialised")
	}

	return acc
}
