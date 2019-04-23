package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/alexeyproskuryakov/hot_wifi_test/auth"
)

func panicConnectionErr(err error) {
	if err != nil {
		panic(err)
	}
}



func main() {
	accountsStorage, err := auth.NewAccountsStorage()
	panicConnectionErr(err)
	auth.PrepareSupervisor(accountsStorage)

	sessionStorage, err := auth.NewSessionStorage()
	panicConnectionErr(err)

	policyStorage, err := auth.NewPolicyStorage()
	panicConnectionErr(err)

	router := auth.Router(accountsStorage, policyStorage, sessionStorage)

	srv := &http.Server{
		Addr: fmt.Sprintf("%s:%v", auth.HOST, auth.PORT),
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      router,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Println(err)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	srv.Shutdown(ctx)
	os.Exit(0)
}
