package setting

import "one-api/common"

var ServerAddress = common.GetEnvOrDefaultString("SEVERADDRESS", "http://api.test.local") // http://localhost:4000
var WorkerUrl = ""
var WorkerValidKey = ""

func EnableWorker() bool {
	return WorkerUrl != ""
}
