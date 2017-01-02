package DB


type DbManager interface {
	Close() error
	Login(string,string) *User
	GetUser(string)*User
	GetHosts(string) ([]Host)
	GetHost(uint) *Host
	GetScans(uint)[]Scan
	GetScan(uint) *Scan
	CreateUser(User)error
	CreateHost(Host)error
	SaveScan(uint,string)error
}
