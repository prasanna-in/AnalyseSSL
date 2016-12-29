package DB

func (db *DB)findByUsername(str string)*User {
	var u User
	db.Where("Username=?",str).First(&u)
	return &u
}
func (db *DB ) findHostbyID(id int) *Host  {
	var h Host
	db.Where("ID=?",id).First(&h)
	return &h
}
func (db *DB ) findByScanID(scanID int)  *Scan{
	var s Scan
	db.Where("ID=?",scanID).First(&s)
	return &s

}
