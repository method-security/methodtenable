package utils

import (
	"fmt"
	"net/http"

	methodtenablefern "github.com/Method-Security/methodtenable/generated/go"
)

const TenableAPIBaseURL = "https://cloud.tenable.com"

// SetTenableAPIKeyHeader sets the X-ApiKeys header with the provided secrets
func SetTenableAPIKeyHeader(req *http.Request, secrets *methodtenablefern.SecretConfig) {
	req.Header.Set("X-ApiKeys", fmt.Sprintf("accessKey=%s;secretKey=%s",
		*secrets.GetAccessKey(), *secrets.GetSecretKey()))
}
