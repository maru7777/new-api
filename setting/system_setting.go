package setting

import "os"

var ServerAddress = os.Getenv("SEVERADDRESS")
var WorkerUrl = ""
var WorkerValidKey = ""

func EnableWorker() bool {
	return WorkerUrl != ""
}
