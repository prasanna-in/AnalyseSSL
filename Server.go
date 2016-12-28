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
	con := DB.CreateDB("postgres://sohkwhdpapullr:xw8J0GQF_ayLAM7yTLYx1hm6tU@ec2-107-20-166-28.compute-1.amazonaws.com:5432/d53bk542g9i5p6")
	muxInstance := mux.NewRouter()
	muxInstance.StrictSlash(true)
	cookieJar := sessions.NewCookieStore([]byte("ThisShouldBeReallySecret"))
	Api.RegisterHandler(muxInstance,cookieJar,con)
	Home.RegisterHandler(muxInstance,cookieJar)
	http.Handle("/",muxInstance)
	muxInstance.PathPrefix("/public/").Handler(http.StripPrefix("/public/",http.FileServer(http.Dir("public/"))))
	muxInstance.HandleFunc("/pk", func(resp http.ResponseWriter, req *http.Request) {
		DB.Setup(con)
		fmt.Fprintln(resp,"PK was Here....")
	})
	if os.Getenv("Env") == "heroku"{
		log.Fatal(http.ListenAndServe(":"+os.Getenv("PORT"),context.ClearHandler(http.DefaultServeMux)))

	}else {
		log.Fatal(http.ListenAndServe(":8902",context.ClearHandler(http.DefaultServeMux)))
	}
}
