package presignedpost

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"time"
)

// Credentials represent AWS credentials and config.
type Credentials struct {
	Region          string // AWS region.
	Bucket          string // AWS S3 bucket.
	AccessKeyID     string // AWS access key.
	SecretAccessKey string // AWS secret access key.
}

// GetCredentials from the environment.
func GetCredentials() (*Credentials, error) {
	// Get AWS credentials from environment variables.
	region := os.Getenv("AWS_REGION")
	bucket := os.Getenv("AWS_S3_BUCKET")
	accessKeyID := os.Getenv("AWS_ACCESS_KEY_ID")
	secretAccessKey := os.Getenv("AWS_SECRET_ACCESS_KEY")

	// Check for missing required environment variables.
	if region == "" || bucket == "" || accessKeyID == "" || secretAccessKey == "" {
		return nil, fmt.Errorf("missing required environment variables")
	}

	// Return the credentials.
	return &Credentials{
		Region:          region,
		Bucket:          bucket,
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
	}, nil
}

// PolicyOptions represent policy options.
type PolicyOptions struct {
	ExpiryInMinutes    int // Expiration time in minutes for the policy.
	MaxFileSizeInBytes int // Maximum allowed file size in the policy.
}

// PolicyConditions represent policy conditions.
type PolicyConditions struct {
	Acl          string // AWS S3 ACL (Access Control List).
	CacheControl string // Cache control header.
}

// PolicyTemplate is the policy template.
const PolicyTemplate = `
{ "expiration": "%s",
  "conditions": [
    {"bucket": "%s"},
    ["starts-with", "$key", "%s"],
    {"acl": "%s"},
    ["content-length-range", 1, %d],
    {"x-amz-credential": "%s"},
    {"x-amz-algorithm": "%s"},
    {"x-amz-date": "%s" },
    {"Content-Type": "%s"},
    {"Cache-Control": "%s"},
  ]
}
`

// Policy represents a new policy.
type Policy struct {
	Expiration   string         // Expiration time of the policy.
	Region       string         // AWS region.
	Bucket       string         // AWS S3 bucket.
	Key          string         // Key (file path) for the S3 object.
	Acl          string         // AWS S3 ACL (Access Control List).
	Credential   string         // AWS credential information.
	Algorithm    string         // AWS algorithm for the policy.
	Date         string         // Date of the policy.
	C            *Credentials   // AWS credentials.
	O            *PolicyOptions // Policy options.
	ContentType  string         // Content type of the S3 object.
	CacheControl string         // Cache control header.
}

// String returns the policy as a string.
func (p *Policy) String() string {
	// Format the policy using the PolicyTemplate.
	s1 := fmt.Sprintf(PolicyTemplate,
		p.Expiration,
		p.Bucket,
		p.Key,
		p.Acl,
		p.O.MaxFileSizeInBytes,
		p.Credential,
		p.Algorithm,
		p.Date,
		p.ContentType,
		p.CacheControl,
	)

	fmt.Println(s1)
	return s1
}

// PresignedPostRequest represents presigned POST information.
type PresignedPostRequest struct {
	Url            string `json:"url"`              // Presigned POST URL.
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

// Constants.
const (
	expirationFormat = "2006-01-02T15:04:05.000Z"
	timeFormat       = "20060102T150405Z"
	shortTimeFormat  = "20060102"
)

// PresignedPostObject is used to create a presigned post response.
func PresignedPostObject(key string, contentType string, policyOpts PolicyOptions, policyConditions PolicyConditions) (PresignedPostRequest, error) {
	creds, err := GetCredentials()
	if err != nil {
		return PresignedPostRequest{}, err
	}

	presignedPost, err := createPresignedPOST(key, contentType, creds, &policyOpts, &policyConditions)
	if err != nil {
		return PresignedPostRequest{}, err
	}

	return *presignedPost, nil
}

// createPresignedPOST creates a new presigned POST.
func createPresignedPOST(key string, contentType string, creds *Credentials, policyOpts *PolicyOptions, policyConditions *PolicyConditions) (*PresignedPostRequest, error) {
	// Create a new policy.
	policy := createPolicy(key, contentType, creds, policyOpts, policyConditions)
	// Base64 encode the policy.
	b64Policy := policy.Base64()
	// Create the AWS signature for the policy.
	signature := createSignature(policy.C, policy.Date[:8], b64Policy)
	// Construct the presigned POST URL.
	postUrl := fmt.Sprintf("https://%s.s3.amazonaws.com/", policy.Bucket)
	// Construct the presigned POST fields.
	postFields := &PresignedPostRequest{
		Url:            postUrl,
		Key:            policy.Key,
		Bucket:         policy.Bucket,
		XAmzAlgorithm:  policy.Algorithm,
		XAmzCredential: policy.Credential,
		XAmzDate:       policy.Date,
		Policy:         b64Policy,
		XAmzSignature:  signature,
		ContentType:    contentType,
		CacheControl:   policy.CacheControl,
		Acl:            policy.Acl,
	}

	return postFields, nil
}

// createPolicy creates a new policy.
func createPolicy(key string, contentType string, creds *Credentials, policyOpts *PolicyOptions, policyConditions *PolicyConditions) *Policy {
	// Calculate the expiration time.
	t := time.Now().Add(time.Minute * time.Duration(policyOpts.ExpiryInMinutes))
	// Format time for AWS requirements.
	formattedShortTime := t.UTC().Format(shortTimeFormat)
	date := t.UTC().Format(timeFormat)
	// Construct AWS credential information.
	cred := fmt.Sprintf("%s/%s/%s/s3/aws4_request", creds.AccessKeyID, formattedShortTime, creds.Region)
	// Create and return the policy.
	return &Policy{
		Expiration:   t.UTC().Format(expirationFormat),
		Region:       creds.Region,
		Bucket:       creds.Bucket,
		Key:          key,
		Acl:          policyConditions.Acl,
		Credential:   cred,
		Algorithm:    "AWS4-HMAC-SHA256",
		Date:         date,
		C:            creds,
		O:            policyOpts,
		ContentType:  contentType,
		CacheControl: policyConditions.CacheControl,
	}
}

// createSignature creates the signature for a string.
func createSignature(creds *Credentials, formattedShortTime, stringToSign string) string {
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
func (p *Policy) Base64() string {
	// Base64 encode the policy string.
	return base64.StdEncoding.EncodeToString([]byte(p.String()))
}
