package Scanner

import (check "pkg.re/essentialkaos/sslscan.v4")

const Version  = "4.0.0"
const Api_Name  = "SSL-SCANNER"

func GetScanner() (*check.API, error) {
	return check.NewAPI(Api_Name,Version)
}
