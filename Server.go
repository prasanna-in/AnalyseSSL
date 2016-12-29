package main

import (
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/AnalyseSSL/Api"
	"net/http"
	"github.com/gorilla/context"
	"github.com/AnalyseSSL/Home"
	"github.com/AnalyseSSL/DB"
	"fmt"
	"os"
	"log"
)



func main() {
	con := DB.CreateDB(os.Getenv("DATABASE_URL"))
	muxInstance := mux.NewRouter()
	muxInstance.StrictSlash(true)
	cookieJar := sessions.NewCookieStore([]byte(os.Getenv("Encrypt")))
	Api.RegisterHandler(muxInstance,cookieJar,con)
	Home.RegisterHandler(muxInstance,cookieJar,con)
	http.Handle("/",muxInstance)
	muxInstance.Handle("/",http.RedirectHandler("/public/login.html",http.StatusTemporaryRedirect))
	muxInstance.PathPrefix("/public/").Handler(http.StripPrefix("/public/",http.FileServer(http.Dir("public/"))))
	muxInstance.HandleFunc("/Setup", func(resp http.ResponseWriter, req *http.Request) {
		DB.Setup(con)
		fmt.Fprintln(resp,"Setup Completed....")
	})
	log.Fatal(http.ListenAndServe(":"+os.Getenv("PORT"),context.ClearHandler(http.DefaultServeMux)))
}
