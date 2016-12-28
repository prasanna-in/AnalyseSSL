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
}

type Scan struct {
	gorm.Model
	ScanTime time.Time
	Result string
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

func Setup(db *DB) {
	db.AutoMigrate(&User{})
	db.AutoMigrate(&Host{})
	//user := User{Username:"Admin",Password:"Password",Access:"Admin"}
	host := Host{Hostname:"https://ndtv.com.com",LastScan:time.Now(),NextScan:time.Now()}
	db.NewRecord(host)
	err := db.Create(&host).Error
	//err := db.DropTableIfExists(&User{}).Error
	if err != nil{
		log.Fatal("Could Create Record ..")
	}
	//db.CreateTable()
}