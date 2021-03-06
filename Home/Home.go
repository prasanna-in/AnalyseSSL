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
	"errors"
)

const Version  = "4.0.0"
const API_NAME  = "SSL_SCANNER"
//
type HomeHandle struct {
	Host DB.Host
	Scan DB.Scan
	ScanLink string
	KeySize string
	KeyAlgo string
	Grade string
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
	KeySize int
	KeyStrength int
	Signature string
}

func CreateUrl(host string) string {
	return fmt.Sprintf("https://www.ssllabs.com/ssltest/analyze.html?d=%s&hideResults=on",host)
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
			str := CreateUrl(y.Hostname)
			x.ScanLink = str
			x.KeySize = strconv.Itoa(y.KeyStrength)
			x.KeyAlgo = y.Signature
			z = append(z,x)
		}
		fmt.Println(z)
		temp := template.New("Checkmmm")
		temp.Parse(("<html><body><ul>" +
			"<style>body {padding-top: 40px; padding-bottom: 40px; background-color: #eee;} td {border: 1px solid;}" + "</style>" +
			"<center><h3>SSL Snapshot view of Hosts </h3></center>" +
			"<table>" +
			"<th>Host</th>" +
			"<th>Last Scan Date</th>" +
			"<th>Grade</th>" +
			"<th>Key Strength</th>" +
			"<th>Key Algorithm</th>" +
			"<th>Scan</th>" +
			"</th>" +
			"{{range .}}" +
			"<tr>" +
			"<td>" + "{{.Host.Hostname}}" + "</td>" +
			"<td>" +"{{.Scan.ScanTime}}"+"</td>" +
			"<td>{{.Grade}}</td>" +
			"<td>{{.KeySize}}" +
			"</td>" +
			"<td>{{.KeyAlgo}}</td>" +
			"<td> <a href={{.ScanLink}} target='_blank'>Scan Link</a></td>"+
			"</tr>" +
			"{{end}}" +
			"<tr>" +
			"<td colspan='6'>" +
			"<h5>The Grade Score is calculated as follows : </h5>" +
			"score >= 80  A " +"<br/>"+
			"score >= 65  B " +"<br/>"+
			"score >= 50  C " +"<br/>"+
			"score >= 35  D " +"<br/>"+
			"score >= 20  E " +"<br/>"+
			"score <  20  F " +"<br/>" +
			"<br/>" +
			"<br/>" +
			"** Please note a blank 'Grade' can represent that the host was not reachable." +
			"</td>"+
			"</tr>" +
			"</table>" +
			"<br/>" +
			"<br/>" +
			"<table>" +
			"<th><a href='/host'>Reports</a></th>" +
			//"<th><a href='/host/add'>Add Host</a></th>" +
			"<th><a href='/api/auth/logout'>Logout</a></th>" +
			"</table>" +
			"</body></html>"))
		temp.Execute(resp,z)
	})
}

//Report Create Function
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
		header = append(header,"Key Strength")
		header = append(header,"Key Algorithm")
		header = append(header,"Scan Link ")
		record = append(record,header)
		totalHosts:=0
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
			scanRecord = append(scanRecord,strconv.Itoa(jsval.KeyStrength))
			scanRecord = append(scanRecord,jsval.Signature)
			x := CreateUrl(jsval.Hostname)
			scanRecord = append(scanRecord,x)
			record = append(record,scanRecord)
		}
		wr.WriteAll(record)
		wr.Write([]string{"** Please note a blank 'Grade' can represent that the host was not reachable."})
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
		fmt.Println("Request Method",req.Method)
		if req.Method=="POST" {
			log.Println("I am inside Post ADD")
			req.ParseForm()
			user := Api.GetUser(resp, req, jar)
			DbUser := db.GetUser(user)
			host := DB.Host{
				Hostname:req.Form.Get("hostname"),
				UserID:DbUser.ID,
			}
			db.CreateHost(host)
			return
		}
		if req.Method==http.MethodGet{
			fmt.Fprint(resp,"<html><body><p>Please Enter Your Hostname that you like to add to the scanner</p>" +
				"<form action=/host/add method=POST>" +
				"<input type='text' id='hostname' name='hostname' placeholder='hostname' required autofocus>" +
				"<button  type='submit' name='_'>Submit</button>" +
				"</form>" +
				"</body>" +
				"</html>")
			return
		}
	})
}


func performScan(host string) (ScanResult,error) {
	scanresult := ScanResult{}
	scanner, err := check.NewAPI(API_NAME,Version)
	if err != nil{
		log.Println("Could Not create Scanner ....")
	}
	progress,err := scanner.Analyze(host)
	if err !=nil{
		log.Println(err.Error())
		return ScanResult{},err
	}
	info,_ := progress.Info()
	log.Println("scanning ... ",info.Host)
	i := 0
	dns := 0
	for {
		fmt.Println(info.Status)
		if info.Status ==check.STATUS_ERROR || dns == 8{
			return ScanResult{},errors.New("Could Not start scan ...")
		}
		if info.Status == check.STATUS_DNS{
			dns++
		}
		if info.Status == check.STATUS_READY{
			break
		}
		if i == 5{
			break
		}
		i++
		time.Sleep(60 * time.Second)

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
	scanresult.KeySize = details.Key.Size
	scanresult.KeyStrength = details.Key.Strength
	scanresult.Signature = details.Cert.SigAlg
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
		temp,err:=template.ParseFiles("public/home.html")
		if err !=nil{
			log.Println("Temp Error",err.Error())
		}
		//temp.ExecuteTemplate(resp,"home.html",[]string{"'","<"})
		temp.Execute(resp,[]int{1,2,3,4,5})

	})
}

func JsonfromStr(jsonstr string) ScanResult  {
	var jsval ScanResult
	json.Unmarshal([]byte(jsonstr),&jsval)
	return jsval
}

func RegisterHandler(m *mux.Router,jar *sessions.CookieStore, db DB.DbManager)  {
	m.Handle("/home",handleHome(jar, db))
	m.Handle("/host",handleHost(jar,db))
	m.Handle("/host/add/",handleAddHost(jar,db)).Methods(http.MethodPost)
	m.Handle("/hosts/scan",handleScan(jar,db))
	m.Handle("/test",handletest(jar))
}


