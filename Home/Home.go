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
	//"bytes"
	//"encoding/csv"
	//"strconv"
	"encoding/json"
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
		if i <= 300{
			return ScanResult{},err("Scan Failed ...")
		}

	}
	detailedinfo,_ := progress.DetailedInfo(info.Endpoints[0].IPAdress)
	details := detailedinfo.Details
	scanresult.IPAddress = info.Endpoints[0].IPAdress
	scanresult.Drown = details.DrownVulnerable
	scanresult.FREAK = details.Freak
	scanresult.Poodle = details.Poodle
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

		//var record []string
		//for _, value := range as {
		//	record = append(record,value.IPAddress)
		//	record= append(record,strconv.FormatBool(value.Poodle))
		//	record= append(record,strconv.FormatBool(value.FREAK))
		//	record= append(record,strconv.FormatBool(value.Drown))
		//	record= append(record,strconv.FormatBool(value.HeartBleed))
		//}
		////Log is being created Properly
		//log.Println("Record : ",fmt.Sprint(record))
		//b := &bytes.Buffer{}
		//wr := csv.NewWriter(b)
		//log.Println("Total Hosts : ",totalHosts)
		//for i := 0; i < totalHosts; i++ { // make a loop for 100 rows just for testing purposes
		//	wr.Write(record) // converts array of string to comma seperated values for 1 row.
		//}
		//wr.Flush()
		//resp.Header().Set("Content-Type", "text/csv")
		//resp.Header().Set("Content-Disposition", "attachment;filename="+user+".csv")
		//resp.Write(b.Bytes())

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


