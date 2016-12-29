package Api

import (
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"net/http"
	"fmt"
	"github.com/AnalyseSSL/DB"
)



func loginHandler(jar *sessions.CookieStore, db DB.DbManager) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter,req *http.Request) {
		if req.Method==http.MethodPost{
			if IsUserLoggedin(req,resp,jar){
				http.Redirect(resp,req,"/home",http.StatusTemporaryRedirect)
				return
			}
			req.ParseForm()
			Username := req.Form.Get("username")
			Password :=  req.Form.Get("password")
			Dbuser := db.Login(Username,Password)
			if Dbuser.Username!=""{
				session,err := getSession(req,jar)
				ErorrHandlerWithHTTPError(resp,err)
				session.Values["username"] = Dbuser.Username
				e := session.Save(req,resp)
				fmt.Println("Session Saved ....")
				ErorrHandlerWithHTTPError(resp,e)
			}

		}else {
			return404(resp)
		}
		fmt.Println("Calling Redirect to Home ....")
		http.Redirect(resp,req,"/home",http.StatusTemporaryRedirect)

	})
}
func logoutHandler(jar *sessions.CookieStore) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		if IsUserLoggedin(req,resp,jar){
			session, error := getSession(req,jar)
			ErorrHandlerWithHTTPError(resp,error)
			session.Values["username"] = ""
			e:= session.Save(req,resp)
			ErorrHandlerWithHTTPError(resp,e)
			http.Redirect(resp,req,"/public/login.html",http.StatusTemporaryRedirect)
		}

	})
}

func createUserHandler(jar *sessions.CookieStore,db DB.DbManager)http.Handler  {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		if !IsUserLoggedin(req,resp,jar){
			http.Redirect(resp,req,"/public/login.html",http.StatusTemporaryRedirect)
		}
		req.ParseForm()
		var u DB.User
		u.Username = req.Form.Get("username")
		u.Password= req.Form.Get("password")
		u.Access=req.Form.Get("access")
		db.CreateUser(u)
	})
}

func RegisterHandler(m *mux.Router,jar *sessions.CookieStore,db DB.DbManager)  {
	m.Handle("/api/auth/login",loginHandler(jar,db))
	m.Handle("/api/auth/logout",logoutHandler(jar)).Methods(http.MethodGet)
	m.Handle("/api/auth/createuser",createUserHandler(jar,db)).Methods(http.MethodPost)
}
