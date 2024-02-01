package presignedpost

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"
)

// PresignedPostObject returns a presigned POST object. The returned POST object can be used to upload a file to S3 using HTTP POST.
// The POST object contains the URL and fields required to upload a file to S3. The URL is valid for the duration specified by the policy.
// The fields are valid for the duration of the policy.
func PresignedPostObject(key string, awsCredentialsAndConfig AwsCredentialsAndConfig, policyOpts PolicyOptions) (string, PresignedPostRequestFields, error) {

	// validate params
	err := validateParams(key, awsCredentialsAndConfig)
	if err != nil {
		return "", PresignedPostRequestFields{}, err
	}

	// set default value for expiry if not provided
	if policyOpts.ExpiryInSeconds == nil {
		policyOpts.ExpiryInSeconds = new(int)
		*policyOpts.ExpiryInSeconds = 3600 // 1 hour
	}

	postUrl, presignedPost, err := createPresignedPOST(key, &awsCredentialsAndConfig, &policyOpts)
	if err != nil {
		return "", PresignedPostRequestFields{}, err
	}

	return postUrl, *presignedPost, nil
}

// PolicyOptions represent options for the policy.
type PolicyOptions struct {

	// Expiration time in seconds for the policy.
	// Default is 3600
	ExpiryInSeconds *int

	// Content type of the S3 object.
	ContentType string

	// Maximum allowed file size in the policy.
	MaxFileSizeInBytes int

	// AWS S3 ACL (Access Control List).
	// Default is private
	// Valid Values: private | public-read | public-read-write | aws-exec-read | authenticated-read | bucket-owner-read | bucket-owner-full-control
	Acl string

	// Cache control header.
	// Default is none
	CacheControl string
}

func validateParams(key string, awsCredentialsAndConfig AwsCredentialsAndConfig) error {
	// validate key
	if key == "" {
		return fmt.Errorf("key cannot be empty")
	}

	// validate aws credentials and config
	if awsCredentialsAndConfig.Region == "" {
		return fmt.Errorf("region cannot be empty")
	}
	if awsCredentialsAndConfig.Bucket == "" {
		return fmt.Errorf("bucket cannot be empty")
	}
	if awsCredentialsAndConfig.AccessKeyID == "" {
		return fmt.Errorf("access key id cannot be empty")
	}
	if awsCredentialsAndConfig.SecretAccessKey == "" {
		return fmt.Errorf("secret access key cannot be empty")
	}

	return nil
}

// AwsCredentialsAndConfig represent AWS credentials and config.
type AwsCredentialsAndConfig struct {
	Region          string // AWS region.
	Bucket          string // AWS S3 bucket.
	AccessKeyID     string // AWS access key.
	SecretAccessKey string // AWS secret access key.
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

// Policy represents a new policy.
type Policy struct {
	Expiration string // Expiration time of the policy.
	Bucket     string // AWS S3 bucket.
	Key        string // Key (file path) for the S3 object.
	Credential string // AWS credential information.
	Algorithm  string // AWS algorithm for the policy.
	Date       string // Date of the policy.
}

// String returns the policy as a string.
func (p *Policy) String(options *PolicyOptions) string {
	// Format the policy using the PolicyTemplate.

	// Optional parameters.
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

// PresignedPostRequestFields represents presigned POST information.
type PresignedPostRequestFields struct {
	Key            string `json:"key"`              // S3 object key.
	Bucket         string `json:"bucket"`           // S3 bucket.
	XAmzAlgorithm  string `json:"X-Amz-Algorithm"`  // AWS algorithm header.
	XAmzCredential string `json:"X-Amz-Credential"` // AWS credential header.
	XAmzDate       string `json:"X-Amz-Date"`       // AWS date header.
	Policy         string `json:"Policy"`           // Base64-encoded policy.  // imp
	XAmzSignature  string `json:"X-Amz-Signature"`  // AWS signature header.    // imp
	ContentType    string `json:"Content-Type"`     // Content type header.
	CacheControl   string `json:"Cache-Control"`    // Cache control header.
	Acl            string `json:"acl"`              // AWS S3 ACL header.
}

// Constants.
const (
	expirationFormat = "2006-01-02T15:04:05.000Z"
	timeFormat       = "20060102T150405Z"
	shortTimeFormat  = "20060102"
)

// createPresignedPOST creates a new presigned POST.
func createPresignedPOST(key string, awsCredentialsAndConfig *AwsCredentialsAndConfig, policyOpts *PolicyOptions) (string, *PresignedPostRequestFields, error) {

	// Create a new policy.
	policy := createPolicy(key, awsCredentialsAndConfig, policyOpts)
	// Base64 encode the policy.
	b64Policy := policy.Base64(policyOpts)
	// Create the AWS signature for the policy.
	signature := createSignature(awsCredentialsAndConfig, policy.Date[:8], b64Policy)
	// Construct the presigned POST URL.
	postUrl := fmt.Sprintf("https://%s.s3.amazonaws.com/", policy.Bucket)
	// Construct the presigned POST fields.
	postFields := &PresignedPostRequestFields{
		Key:            key,
		Bucket:         awsCredentialsAndConfig.Bucket,
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
func createPolicy(key string, awsCredentialsAndConfig *AwsCredentialsAndConfig, policyOpts *PolicyOptions) *Policy {
	// Calculate the expiration time.
	// todo: optional handling
	t := time.Now().Add(time.Second * time.Duration(*policyOpts.ExpiryInSeconds))
	// Format time for AWS requirements.
	formattedShortTime := t.UTC().Format(shortTimeFormat)
	date := t.UTC().Format(timeFormat)
	// Construct AWS credential information.
	credential := fmt.Sprintf("%s/%s/%s/s3/aws4_request", awsCredentialsAndConfig.AccessKeyID, formattedShortTime, awsCredentialsAndConfig.Region)
	// Create and return the policy.

	return &Policy{
		Expiration: t.UTC().Format(expirationFormat),
		Bucket:     awsCredentialsAndConfig.Bucket,
		Key:        key,
		Credential: credential,
		Algorithm:  "AWS4-HMAC-SHA256",
		Date:       date,
	}
}

// createSignature creates the signature for a string.
func createSignature(creds *AwsCredentialsAndConfig, formattedShortTime, stringToSign string) string {
	// Calculate HMAC-SHA256 for each step of the AWS signature process.
	h1 := calculateHMACSHA256([]byte("AWS4"+creds.SecretAccessKey), []byte(formattedShortTime))
	h2 := calculateHMACSHA256(h1, []byte(creds.Region))
	h3 := calculateHMACSHA256(h2, []byte("s3"))
	h4 := calculateHMACSHA256(h3, []byte("aws4_request"))
	// Final signature.
	signature := calculateHMACSHA256(h4, []byte(stringToSign))
	// Convert signature to hex.
	return hex.EncodeToString(signature)
}

// calculateHMACSHA256 is a helper to make the HMAC-SHA256.
func calculateHMACSHA256(key []byte, data []byte) []byte {
	// Create and calculate HMAC-SHA256.
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

// Base64 returns the policy as a base64 encoded string.
func (p *Policy) Base64(policyOpts *PolicyOptions) string {
	// Base64 encode the policy string.
	return base64.StdEncoding.EncodeToString([]byte(p.String(policyOpts)))
}
