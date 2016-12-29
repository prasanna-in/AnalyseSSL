package DB

import "github.com/jinzhu/gorm"
import "log"
import (
	_ "github.com/lib/pq"

	"time"
)


type DB struct {
	*gorm.DB
}

type User struct {
	gorm.Model
	Username string `sql:"not null;unique"`
	Password string `sql:"not null"`
	Access string `sql:"-"`
	Hosts []Host
}

type Host struct {
	gorm.Model
	Hostname string
	LastScan time.Time
	NextScan time.Time
	Scans []Scan
	UserID uint
}

type Scan struct {
	gorm.Model
	ScanTime time.Time
	Result string
	HostID uint
}

func CreateDB(connectionString string) *DB  {
	db,err := gorm.Open("postgres",connectionString)
	if err != nil{
		log.Fatal("Database Connection did not happen ....")
	}
	return &DB{db}
}

func (d *DB ) close() error  {
	return d.Close()
}

func (db *DB ) Login(username string,password string) *User {
	var user User
	db.Where("Username=? AND Password=?",username,password).First(&user)
	return &user
}

func (db *DB) GetHosts(username string)([]Host){
	var h []Host
	db.Where("Username=?",username).Related(&h)
	return h
}

func Setup(db *DB) {
	//db.DropTableIfExists(User{},Host{})
	//db.CreateTable(User{},Host{})
	//user := User{Username:"Admin",Password:"Password",Hosts:[]Host{{Hostname:"google.com"},{Hostname:"Yahoo.com"}}}
	//host := Host{}
	//user2:=User{Username:"Admin",Password:"Password",Hosts:Host{Hostname:"Https://Yahoo.com"}}
	//db.Create(&user)
	var u User
	var h []Host
	db.First(&u)
	db.Model(&u).Related(&h)
	log.Println("PKKK",h)
}