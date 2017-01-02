package Home

import (
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"net/http"
	"github.com/AnalyseSSL/Api"
	"fmt"
	"github.com/AnalyseSSL/DB"
	"log"
	check "github.com/AnalyseSSL/Scanner"
	"time"
	"bytes"
	"encoding/csv"
)

const Version  = "4.0.0"
const API_NAME  = "SSL_SCANNER"
func handleHome(jar *sessions.CookieStore, db DB.DbManager) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		if !Api.IsUserLoggedin(req,resp,jar){
			http.Redirect(resp,req,"/public/login.html",http.StatusSeeOther)
			return
		}
		user :=Api.GetUser(resp,req,jar)
		j := db.GetHosts(user)
		resp.Header().Add("Content-Type", "text/html")
		fmt.Fprintf(resp, "<html><head><style>body {padding-top: 40px; padding-bottom: 40px; background-color: #eee;}</style></head><body>Hello %s<br/><a href='/host'>Host</a><br/><a href='/api/auth/logout'>Logout</a></body></html>",user)
		fmt.Fprintln(resp,"</br>")
		fmt.Fprintln(resp,j)
		fmt.Fprintln(resp,"</br>")
	})
}
func handleHost(jar *sessions.CookieStore, db DB.DbManager) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter,req *http.Request) {
		if !Api.IsUserLoggedin(req,resp,jar){
			http.Redirect(resp,req,"/public/login.html",http.StatusSeeOther)
			return
		}
		user :=Api.GetUser(resp,req,jar)
		hosts := db.GetHosts(user)
		scans := db.GetScans(hosts[0].ID)
		fmt.Fprintln(resp,scans)
	})
}

func handleAddHost(jar *sessions.CookieStore, db DB.DbManager) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		if !Api.IsUserLoggedin(req,resp,jar){
			http.Redirect(resp,req,"/public/login.html",http.StatusTemporaryRedirect)
			return
		}
		req.ParseForm()
		user := Api.GetUser(resp,req,jar)
		DbUser := db.GetUser(user)
		host := DB.Host{
			Hostname:req.Form.Get("hostname"),
			UserID:DbUser.ID,
		}
		db.CreateHost(host)
	})
}

type ScanResult struct {
	IPAddress string
	Poodle bool
	Drown bool
	HeartBleed bool
	FREAK bool
}

func performScan(hosts []string) []ScanResult {
	scanresults := []ScanResult{}
	scanner, err := check.NewAPI(API_NAME,Version)
	if err != nil{
		log.Println("Could Not create Scanner ....")
	}
	for _, value := range hosts {
		scanresult := ScanResult{}
		progress,_ := scanner.Analyze(value)
		info,_ := progress.Info()
		for {
			fmt.Println(info.Status)
			if info.Status ==check.STATUS_ERROR{
				panic(info.StatusMessage)
			}
			if info.Status == check.STATUS_READY{
				break
			}
			time.Sleep(5 * time.Second)
		}
		detailedinfo,_ := progress.DetailedInfo(info.Endpoints[0].IPAdress)
		details := detailedinfo.Details
		scanresult.IPAddress = info.Endpoints[0].IPAdress
		scanresult.Drown = details.DrownVulnerable
		scanresult.FREAK = details.Freak
		scanresult.Poodle = details.Poodle
		scanresults  = append(scanresults,scanresult)
	}
	return scanresults
}

func handleScan(jar *sessions.CookieStore,db DB.DbManager)http.Handler  {
	return http.HandlerFunc(func(resp http.ResponseWriter,req *http.Request) {
		if !Api.IsUserLoggedin(req,resp,jar){
			http.Redirect(resp,req,"/public/login.html",http.StatusSeeOther)
			return
		}
		var totalHosts int = 0
		user :=Api.GetUser(resp,req,jar)
		hosts := db.GetHosts(user)
		scanHosts :=[]string{}
		for _, value := range hosts {
			totalHosts++
			scanHosts = append(scanHosts,value.Hostname)
		}
		Scanrsults := performScan(scanHosts)
		record := Scanrsults
		b := &bytes.Buffer{}
		wr := csv.NewWriter(b)
		for i := 0; i < totalHosts; i++ { // make a loop for 100 rows just for testing purposes
			wr.Write(record) // converts array of string to comma seperated values for 1 row.
		}
		wr.Flush()
		resp.Header().Set("Content-Type", "text/csv")
		resp.Header().Set("Content-Disposition", "attachment;filename=TheCSVFileName.csv")
		resp.Write(b.Bytes())

	})

}

func save()  {
	
}

func RegisterHandler(m *mux.Router,jar *sessions.CookieStore, db DB.DbManager)  {
	m.Handle("/home",handleHome(jar, db))
	m.Handle("/host",handleHost(jar,db))
	m.Handle("/host/add/",handleAddHost(jar,db)).Methods(http.MethodPost)
	m.Handle("/hosts/scan",handleScan(jar,db))
}


