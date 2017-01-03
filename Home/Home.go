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
	"encoding/csv"
	"encoding/json"
	"errors"
	"strconv"
	"bytes"
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
		userDB := db.GetUser(user)
		scans :=db.GetScans(userDB.ID)
		log.Println("Logs : ",scans)
		var record []string
		b := &bytes.Buffer{}
		wr := csv.NewWriter(b)
		record = append(record,"IPAddress")
		record = append(record,"Poodle")
		record = append(record,"FREAK")
		record = append(record,"Drown")
		record = append(record,"HeartBleed")
		record = append(record,"Grade")
		record = append(record,"Poodle TLS")
		wr.Write(record)
		totalHosts :=0
		for _, value := range scans {
			totalHosts++
			log.Println("Result : ", value.Result)
			var jsval ScanResult
			json.Unmarshal([]byte(value.Result),&jsval)
			log.Println("IP Address : ", jsval.IPAddress)
			record = append(record,jsval.IPAddress)
			record = append(record,strconv.FormatBool(jsval.Poodle))
			record = append(record,strconv.FormatBool(jsval.FREAK))
			record = append(record,strconv.FormatBool(jsval.Drown))
			record = append(record,strconv.FormatBool(jsval.HeartBleed))
			record = append(record,jsval.Grade)
			record = append(record,strconv.Itoa(jsval.Poodle_TLS))
			wr.Write(record)
		}
		//Log is being created Properly
		log.Println("Record : ",fmt.Sprint(record))
		log.Println("Total Hosts : ",totalHosts)
		//for i := 0; i < totalHosts; i++ { // make a loop for 100 rows just for testing purposes
		//	wr.Write(record) // converts array of string to comma seperated values for 1 row.
		//}
		wr.Flush()
		resp.Header().Set("Content-Type", "text/csv")
		resp.Header().Set("Content-Disposition", "attachment;filename="+user+".csv")
		resp.Write(b.Bytes())
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
	Poodle_TLS int
	Grade string
}

func performScan(host string) (ScanResult,error) {
	scanresult := ScanResult{}
	scanner, err := check.NewAPI(API_NAME,Version)
	if err != nil{
		log.Println("Could Not create Scanner ....")
	}
	progress,_ := scanner.Analyze(host)
	info,_ := progress.Info()
	log.Println("scanning ... ",info.Host)
	i :=0
	for {
		fmt.Println(info.Status)
		if info.Status ==check.STATUS_ERROR{
			panic(info.StatusMessage)
		}
		if info.Status == check.STATUS_READY{
			break
		}
		time.Sleep(5 * time.Second)
		i++
		log.Println(i)
		if i <= 3000{
			return ScanResult{},errors.New("This Failed ..")
		}

	}
	detailedinfo,_ := progress.DetailedInfo(info.Endpoints[0].IPAdress)
	details := detailedinfo.Details
	scanresult.IPAddress = info.Endpoints[0].IPAdress
	scanresult.Drown = details.DrownVulnerable
	scanresult.FREAK = details.Freak
	scanresult.Poodle = details.Poodle
	scanresult.Poodle_TLS = details.PoodleTLS
	scanresult.Grade = detailedinfo.Grade
	return scanresult,nil
}

func handleScan(jar *sessions.CookieStore,db DB.DbManager)http.Handler  {
	return http.HandlerFunc(func(resp http.ResponseWriter,req *http.Request) {
		if !Api.IsUserLoggedin(req,resp,jar){
			http.Redirect(resp,req,"/public/login.html",http.StatusSeeOther)
			return
		}
		user :=Api.GetUser(resp,req,jar)
		hosts := db.GetHosts(user)
		for _, value := range hosts {
			scanResult, err := performScan(value.Hostname)
			if err != nil{
				log.Fatal("Could not get the results for",value.Hostname )
			}
			jsonScanResult,_:= json.Marshal(scanResult)
			db.SaveScan(value.ID,string(jsonScanResult))
		}
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


