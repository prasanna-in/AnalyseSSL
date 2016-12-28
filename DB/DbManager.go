package DB


type DbManager interface {
	Close() error
	Login(string,string) *User
	GetHosts(string) (*User,error)
}
