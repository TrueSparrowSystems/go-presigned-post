package presignedpost

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"
)

// AwsCredentialsAndConfig represent AWS credentials and config.
type AwsCredentialsAndConfig struct {
	Region          string // AWS region.
	Bucket          string // AWS S3 bucket.
	AccessKeyID     string // AWS access key.
	SecretAccessKey string // AWS secret access key.
}

// PolicyOptions represent options for the policy.
type PolicyOptions struct {
	ExpiryInSeconds    *int   // Expiration time in seconds for the policy. Default is 3600.
	ContentType        string // Content type of the S3 object.
	MaxFileSizeInBytes int    // Maximum allowed file size in the policy.
	Acl                string // AWS S3 ACL (Access Control List). Default is private. Possible values are private, public-read, public-read-write, authenticated-read, and bucket-owner-read.
	CacheControl       string // Cache control header. Default is none.
}

// PresignedPostRequestFields represents presigned POST information.
type PresignedPostRequestFields struct {
	Key            string `json:"key"`              // S3 object key.
	Bucket         string `json:"bucket"`           // S3 bucket.
	XAmzAlgorithm  string `json:"X-Amz-Algorithm"`  // AWS algorithm header.
	XAmzCredential string `json:"X-Amz-Credential"` // AWS credential header.
	XAmzDate       string `json:"X-Amz-Date"`       // AWS date header.
	Policy         string `json:"Policy"`           // Base64-encoded policy.
	XAmzSignature  string `json:"X-Amz-Signature"`  // AWS signature header.
	ContentType    string `json:"Content-Type"`     // Content type header.
	CacheControl   string `json:"Cache-Control"`    // Cache control header.
	Acl            string `json:"acl"`              // AWS S3 ACL header.
}

// Policy represents a new policy.
type Policy struct {
	Expiration string // Expiration time of the policy.
	Bucket     string // AWS S3 bucket.
	Key        string // Key (file path) for the S3 object.
	Credential string // AWS credential information.
	Algorithm  string // AWS algorithm for the policy.
	Date       string // Date of the policy.
}

// PolicyTemplate is the policy template.
const PolicyTemplate = `
{ "expiration": "%s",
  "conditions": [
    {"bucket": "%s"},
    ["starts-with", "$key", "%s"],
    {"x-amz-credential": "%s"},
    {"x-amz-algorithm": "%s"},
    {"x-amz-date": "%s"}%s
  ]
}
`

// Constants.
const (
	expirationFormat = "2006-01-02T15:04:05.000Z"
	timeFormat       = "20060102T150405Z"
	shortTimeFormat  = "20060102"
	defaultExpiry    = 3600 // 1 hour
)

// PresignedPostObject returns a presigned POST object. The returned POST object can be used to upload a file to S3 using HTTP POST.
func PresignedPostObject(key string, creds AwsCredentialsAndConfig, policyOpts PolicyOptions) (string, PresignedPostRequestFields, error) {
	// Validate params
	if err := validateParams(key, creds); err != nil {
		return "", PresignedPostRequestFields{}, err
	}

	// Set default value for expiry if not provided
	if policyOpts.ExpiryInSeconds == nil {
		expiry := defaultExpiry
		policyOpts.ExpiryInSeconds = &expiry
	}

	postUrl, presignedPost, err := createPresignedPOST(key, &creds, &policyOpts)
	if err != nil {
		return "", PresignedPostRequestFields{}, err
	}

	return postUrl, *presignedPost, nil
}

// validateParams validates the parameters for PresignedPostObject.
func validateParams(key string, creds AwsCredentialsAndConfig) error {
	if key == "" {
		return fmt.Errorf("key cannot be empty")
	}

	if creds.Region == "" || creds.Bucket == "" || creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return fmt.Errorf("all AWS credentials and config fields must be provided")
	}

	return nil
}

// createPresignedPOST creates a new presigned POST.
func createPresignedPOST(key string, creds *AwsCredentialsAndConfig, policyOpts *PolicyOptions) (string, *PresignedPostRequestFields, error) {
	policy := createPolicy(key, creds, policyOpts)
	b64Policy := policy.Base64(policyOpts)
	signature := createSignature(creds, policy.Date[:8], b64Policy)
	postUrl := fmt.Sprintf("https://%s.s3.amazonaws.com/", policy.Bucket)

	postFields := &PresignedPostRequestFields{
		Key:            key,
		Bucket:         creds.Bucket,
		XAmzAlgorithm:  policy.Algorithm,
		XAmzCredential: policy.Credential,
		XAmzDate:       policy.Date,
		Policy:         b64Policy,
		XAmzSignature:  signature,
	}

	if policyOpts.ContentType != "" {
		postFields.ContentType = policyOpts.ContentType
	}
	if policyOpts.CacheControl != "" {
		postFields.CacheControl = policyOpts.CacheControl
	}
	if policyOpts.Acl != "" {
		postFields.Acl = policyOpts.Acl
	}

	return postUrl, postFields, nil
}

// createPolicy creates a new policy.
func createPolicy(key string, creds *AwsCredentialsAndConfig, policyOpts *PolicyOptions) *Policy {
	t := time.Now().Add(time.Second * time.Duration(*policyOpts.ExpiryInSeconds))
	formattedShortTime := t.UTC().Format(shortTimeFormat)
	date := t.UTC().Format(timeFormat)
	credential := fmt.Sprintf("%s/%s/%s/s3/aws4_request", creds.AccessKeyID, formattedShortTime, creds.Region)

	return &Policy{
		Expiration: t.UTC().Format(expirationFormat),
		Bucket:     creds.Bucket,
		Key:        key,
		Credential: credential,
		Algorithm:  "AWS4-HMAC-SHA256",
		Date:       date,
	}
}

// createSignature creates the signature for a string.
func createSignature(creds *AwsCredentialsAndConfig, formattedShortTime, stringToSign string) string {
	h1 := calculateHMACSHA256([]byte("AWS4"+creds.SecretAccessKey), []byte(formattedShortTime))
	h2 := calculateHMACSHA256(h1, []byte(creds.Region))
	h3 := calculateHMACSHA256(h2, []byte("s3"))
	h4 := calculateHMACSHA256(h3, []byte("aws4_request"))
	signature := calculateHMACSHA256(h4, []byte(stringToSign))

	return hex.EncodeToString(signature)
}

// calculateHMACSHA256 is a helper to make the HMAC-SHA256.
func calculateHMACSHA256(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

// Base64 returns the policy as a base64 encoded string.
func (p *Policy) Base64(policyOpts *PolicyOptions) string {
	return base64.StdEncoding.EncodeToString([]byte(p.String(policyOpts)))
}

// String returns the policy as a string.
func (p *Policy) String(options *PolicyOptions) string {
	var optionalParams string

	if options != nil {
		if options.ContentType != "" {
			optionalParams += fmt.Sprintf(",\n    {\"Content-Type\": \"%s\"}", options.ContentType)
		}
		if options.MaxFileSizeInBytes > 0 {
			optionalParams += fmt.Sprintf(",\n    [\"content-length-range\", 1, %d]", options.MaxFileSizeInBytes)
		}
		if options.Acl != "" {
			optionalParams += fmt.Sprintf(",\n    {\"acl\": \"%s\"}", options.Acl)
		}
		if options.CacheControl != "" {
			optionalParams += fmt.Sprintf(",\n    {\"Cache-Control\": \"%s\"}", options.CacheControl)
		}
	}

	policyTemplateString := fmt.Sprintf(PolicyTemplate,
		p.Expiration,
		p.Bucket,
		p.Key,
		p.Credential,
		p.Algorithm,
		p.Date,
		optionalParams,
	)

	return policyTemplateString
}
