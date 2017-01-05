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
	"strconv"
	"bytes"
	"html/template"
)

const Version  = "4.0.0"
const API_NAME  = "SSL_SCANNER"
//
type HomeHandle struct {
	Host DB.Host
	Scan DB.Scan
	Grade string
}

func JsonfromStr(jsonstr string) ScanResult  {
	var jsval ScanResult
	json.Unmarshal([]byte(jsonstr),&jsval)
	return jsval
}

func handleHome(jar *sessions.CookieStore, db DB.DbManager) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		if !Api.IsUserLoggedin(req,resp,jar){
			http.Redirect(resp,req,"/public/login.html",http.StatusSeeOther)
			return
		}
		user :=Api.GetUser(resp,req,jar)
		z := []HomeHandle{}
		j := db.GetHosts(user)
		for _, value := range j {
			var x HomeHandle
			x.Host = value
			x.Scan = db.GetScan(value.ID)
			y := JsonfromStr(x.Scan.Result)
			x.Grade = y.Grade
			z = append(z,x)
		}
		fmt.Println(z)
		temp := template.New("Checkmmm")
		temp.Parse(("<html><body><ul>" +
			"<style>body {padding-top: 40px; padding-bottom: 40px; background-color: #eee;}" + "</style>" +
			"<h1>Snapshot view of your hosts ... </h1>" +
			"<table>" +
			"<th>Host</th>" +
			"<th>Last Scan Date</th>" +
			"<th>Grade</th>" +
			"</th>" +
			"{{range .}}" +
			"<tr>" +
			"<td>" + "{{.Host.Hostname}}" + "</td>" +
			"<td>" +"{{.Scan.ScanTime}}"+"</td>" +
			"<td>{{.Grade}}</td>"+
			"</tr>" +
			"{{end}}" +
			"</table>" +
			"<table>" +
			"<br/>" +
			"<br/>" +
			"<th><a href='/host'>Reports</a></th>" +
			//"<th><a href='/host/add'>Add Host</a></th>" +
			"<th><a href='/api/auth/logout'>Logout</a></th>" +
			"</body></html>"))
		temp.Execute(resp,z)
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
		var record [][]string
		b := &bytes.Buffer{}
		wr := csv.NewWriter(b)
		var header []string
		header = append(header,"Hostname")
		header = append(header,"IPAddress")
		header = append(header,"Poodle")
		header = append(header,"FREAK")
		header = append(header,"Drown")
		header = append(header,"HeartBleed")
		header = append(header,"Grade")
		header = append(header,"Poodle TLS")
		record = append(record,header)
		totalHosts:= 0
		for _, value := range scans {
			totalHosts++
			var jsval ScanResult
			var scanRecord []string
			json.Unmarshal([]byte(value.Result),&jsval)
			scanRecord = append(scanRecord,jsval.Hostname)
			scanRecord = append(scanRecord,jsval.IPAddress)
			scanRecord = append(scanRecord,strconv.FormatBool(jsval.Poodle))
			scanRecord = append(scanRecord,strconv.FormatBool(jsval.FREAK))
			scanRecord = append(scanRecord,strconv.FormatBool(jsval.Drown))
			scanRecord = append(scanRecord,strconv.FormatBool(jsval.HeartBleed))
			scanRecord = append(scanRecord,jsval.Grade)
			scanRecord = append(scanRecord,strconv.Itoa(jsval.Poodle_TLS))
			record = append(record,scanRecord)
		}
		log.Println("Record : ",fmt.Sprint(record))
		wr.WriteAll(record)
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
		if req.Method==http.MethodPost {
			log.Println("I am inside Post ADD")
			req.ParseForm()
			user := Api.GetUser(resp, req, jar)
			DbUser := db.GetUser(user)
			host := DB.Host{
				Hostname:req.Form.Get("hostname"),
				UserID:DbUser.ID,
			}
			db.CreateHost(host)
		}
		if req.Method==http.MethodGet{
			fmt.Fprint(resp,"<html><body><p>Please Enter Your Hostname that you like to add to the scanner</p>" +
				"<form action=/host/add method=POST>" +
				"<input type='text' id='hostname' name='hostname' placeholder='hostname' required autofocus>" +
				"<button  type='submit' name='_'>Submit</button>" +
				"</form>" +
				"</body>" +
				"</html>")
		}
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
	Hostname string
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
	i := 0
	for {
		fmt.Println(info.Status)
		fmt.Println(info.Endpoints[0].Progress)
		fmt.Println(info.Endpoints[0].StatusDetailsMessage)
		fmt.Println(info.Endpoints[0].IPAdress)
		if info.Status ==check.STATUS_ERROR{
			panic(info.StatusMessage)
		}
		if info.Status == check.STATUS_READY{
			break
		}

		if i == 10{
			break
		}
		time.Sleep(60 * time.Second)
		i++


	}
	detailedinfo,_ := progress.DetailedInfo(info.Endpoints[0].IPAdress)
	details := detailedinfo.Details
	scanresult.IPAddress = info.Endpoints[0].IPAdress
	scanresult.Drown = details.DrownVulnerable
	scanresult.FREAK = details.Freak
	scanresult.Poodle = details.Poodle
	scanresult.Poodle_TLS = details.PoodleTLS
	scanresult.Grade = detailedinfo.Grade
	scanresult.Hostname = host
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
				log.Fatal("Could not get the results for ",value.Hostname )
			}
			jsonScanResult,_:= json.Marshal(scanResult)
			db.SaveScan(value.ID,string(jsonScanResult))
		}
	})

}
func handletest(jar *sessions.CookieStore) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter,req *http.Request) {
		temp := template.New("Junk")
		temp.Parse("<html><body><ul>" +
			"{{range .}}" +
			"<li>{{.}}</li>" +
			"{{end}}" +
			"</ul></body></html>")
		temp.Execute(resp,[]int{1,2,3})

		temp,err:=template.ParseFiles("/public/home.html")
		if err !=nil{
			log.Println(err.Error())
		}
		//temp.ExecuteTemplate(resp,"home.html",[]string{"'","<"})
		temp.Execute(resp,[]int{1,2,3,4,5})

	})
}

func RegisterHandler(m *mux.Router,jar *sessions.CookieStore, db DB.DbManager)  {
	m.Handle("/home",handleHome(jar, db))
	m.Handle("/host",handleHost(jar,db))
	m.Handle("/host/add/",handleAddHost(jar,db))
	m.Handle("/hosts/scan",handleScan(jar,db))
	m.Handle("/test",handletest(jar))
}


