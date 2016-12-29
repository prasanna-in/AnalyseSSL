package DB


type DbManager interface {
	Close() error
	Login(string,string) *User
	GetUser(string)*User
	GetHosts(string) ([]Host)
	GetHost(int) *Host
	GetScans(uint)[]Scan
	GetScan(int) Scan
}
