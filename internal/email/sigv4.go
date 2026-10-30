package email

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"time"
)

// AWS Signature Version 4, header form, for the one request this package
// makes (SES's SendEmail): a POST with a JSON body and no query string.
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html

const sigV4Algorithm = "AWS4-HMAC-SHA256"

// signV4 signs req, whose body is payload, for service in region at t. It
// sets X-Amz-Date and Authorization, signing Host, Content-Type (when set)
// and X-Amz-Date, the set the AWS SDKs sign for this request.
func signV4(req *http.Request, payload []byte, accessKeyID, secretAccessKey, region, service string, t time.Time) {
	amzDate := t.UTC().Format("20060102T150405Z")
	req.Header.Set("X-Amz-Date", amzDate)
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	headers := map[string]string{"host": host, "x-amz-date": amzDate}
	if ct := req.Header.Get("Content-Type"); ct != "" {
		headers["content-type"] = ct
	}
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	req.Header.Set("Authorization", sigV4Authorization(req.Method, path, headers, payload, accessKeyID, secretAccessKey, region, service, amzDate))
}

// sigV4Authorization is the Authorization header for a request with no query
// string. headers maps lower-case names to values and must include host and
// x-amz-date; every one of them is signed.
func sigV4Authorization(method, path string, headers map[string]string, payload []byte, accessKeyID, secretAccessKey, region, service, amzDate string) string {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	var canonicalHeaders strings.Builder
	for _, name := range names {
		canonicalHeaders.WriteString(name)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(strings.Join(strings.Fields(headers[name]), " "))
		canonicalHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(names, ";")
	canonicalRequest := strings.Join([]string{
		method,
		canonicalURIPath(path),
		"", // no query string
		canonicalHeaders.String(),
		signedHeaders,
		hexSHA256(payload),
	}, "\n")
	date := amzDate[:8]
	scope := date + "/" + region + "/" + service + "/aws4_request"
	stringToSign := sigV4Algorithm + "\n" + amzDate + "\n" + scope + "\n" + hexSHA256([]byte(canonicalRequest))
	key := hmacSHA256([]byte("AWS4"+secretAccessKey), date)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, service)
	key = hmacSHA256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(key, stringToSign))
	return sigV4Algorithm + " Credential=" + accessKeyID + "/" + scope + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature
}

// canonicalURIPath percent-encodes every byte of path outside RFC 3986's
// unreserved set and '/', as SigV4 asks for services other than S3. The
// paths this package signs are constant ASCII, so this is the identity on
// them; it keeps an unexpected byte from being signed one way and sent
// another.
func canonicalURIPath(path string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(path); i++ {
		c := path[i]
		if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' || c == '/' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&15])
	}
	return b.String()
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}
