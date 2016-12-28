package Api

import (
	"net/http"
	"github.com/gorilla/sessions"
	"errors"

	"fmt"
)

func return404(w http.ResponseWriter) {
	http.Error(w, "404 page not found", 404)
}

func getSession(r *http.Request, jar *sessions.CookieStore)  (*sessions.Session,error){
	session, err := jar.Get(r, "Session")
	if err !=nil{
		return &sessions.Session{},errors.New("Could not Create Session")
	}
	return session,nil
}

func ErorrHandlerWithHTTPError(resp http.ResponseWriter,e error) {
	if e != nil {
		http.Error(resp,e.Error(),http.StatusInternalServerError)
	}
}

func IsUserLoggedin(req *http.Request, resp http.ResponseWriter,jar *sessions.CookieStore) (bool) {
	userloggedin := false
	session, err := getSession(req,jar)
	ErorrHandlerWithHTTPError(resp,err)
	user,found := session.Values["username"]
	if !found||user==""{
		//http.Redirect(resp,req,"/public/login.html",http.StatusSeeOther)
		return userloggedin
	}
	userloggedin = true
	return userloggedin
}

func GetUser(resp http.ResponseWriter,req *http.Request, jar *sessions.CookieStore)  string{
	session,err := getSession(req,jar)
	ErorrHandlerWithHTTPError(resp,err)
	username := fmt.Sprint(session.Values["username"])
	return username
}