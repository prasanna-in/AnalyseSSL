package Home

import (
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"net/http"
	"github.com/AnalyseSSL/Api"
	"fmt"
	"github.com/AnalyseSSL/DB"
)

func handleHome(jar *sessions.CookieStore, db DB.DbManager) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		if !Api.IsUserLoggedin(req,resp,jar){
			http.Redirect(resp,req,"/public/login.html",http.StatusSeeOther)
			return
		}
		user :=Api.GetUser(resp,req,jar)
		j := db.GetHosts(user)
		host := db.GetHost(1)
		resp.Header().Add("Content-Type", "text/html")
		fmt.Fprintf(resp, "<html><head><style>body {padding-top: 40px; padding-bottom: 40px; background-color: #eee;}</style></head><body>Hello %s<br/><a href='/host'>Host</a><br/><a href='/api/auth/logout'>Logout</a></body></html>",user)
		fmt.Fprintln(resp,"</br>")
		fmt.Fprintln(resp,j)
		fmt.Fprintln(resp,"</br>")
		fmt.Fprintln(resp,"</br>", host)

	})
}
func handleHost(jar *sessions.CookieStore, db DB.DbManager) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter,req *http.Request) {
		if !Api.IsUserLoggedin(req,resp,jar){
			http.Redirect(resp,req,"/public/login.html",http.StatusSeeOther)
		}
		user :=Api.GetUser(resp,req,jar)
		hosts := db.GetHosts(user)
		scans := db.GetScans(hosts[0].ID)
		fmt.Fprintln(resp,scans)
	})
}
func RegisterHandler(m *mux.Router,jar *sessions.CookieStore, db DB.DbManager)  {
	m.Handle("/home",handleHome(jar, db))
	m.Handle("/host",handleHost(jar,db))
}


