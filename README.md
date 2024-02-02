
# Go Presigned Post


The `go-presigned-post` package provides a convenient way to generate a presigned POST URL and fields for uploading files to Amazon S3 using HTTP POST requests.

## Installation

```bash
go get -u github.com/TrueSparrowSystems/go-presigned-post
```

## Usage

```go
package main

import (
	"fmt"
	"github.com/TrueSparrowSystems/go-presigned-post"
)

func main() {
	// Set your AWS credentials and configuration
	awsCredentials := presignedpost.AwsCredentialsAndConfig{
		Region:          "your-aws-region",
		Bucket:          "your-s3-bucket",
		AccessKeyID:     "your-access-key-id",
		SecretAccessKey: "your-secret-access-key",
	}

	// Set the key for the S3 object
	key := "path/to/upload/file.txt"

	// Set optional policy options
	policyOptions := presignedpost.PolicyOptions{
		ExpiryInSeconds:    nil, // Default is 1 hour
		ContentType:        "",  // Content type of the S3 object
		MaxFileSizeInBytes: 0,   // Maximum allowed file size in the policy
		Acl:                "",  // AWS S3 ACL (Access Control List)
		CacheControl:       "",  // Cache control header
	}

	// Generate presigned POST URL and fields
	postUrl, postFields, err := presignedpost.PresignedPostObject(key, awsCredentials, policyOptions)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Use postUrl and postFields to upload a file using HTTP POST
	// ...

	fmt.Println("Presigned POST URL:", postUrl)
	fmt.Println("Presigned POST Fields:", postFields)
}
```

## Documentation

### `PresignedPostObject`

```go
func PresignedPostObject(key string, awsCredentialsAndConfig presignedpost.AwsCredentialsAndConfig, policyOpts presignedpost.PolicyOptions) (string, presignedpost.PresignedPostRequestFields, error)
```

Generates a presigned POST URL and fields for uploading a file to S3.

- `key`: Key (file path) for the S3 object.
- `awsCredentialsAndConfig`: AWS credentials and configuration.
- `policyOpts`: Policy options (expiration time, content type, etc.).

### `AwsCredentialsAndConfig`

```go
type AwsCredentialsAndConfig struct {
	Region          string // AWS region.
	Bucket          string // AWS S3 bucket.
	AccessKeyID     string // AWS access key.
	SecretAccessKey string // AWS secret access key.
}
```

Represents AWS credentials and configuration.

### `PolicyOptions`

```go
type PolicyOptions struct {
	ExpiryInSeconds     *int    // Expiration time in seconds for the policy. Default is 3600.
	ContentType         string  // Content type of the S3 object.
	MaxFileSizeInBytes  int     // Maximum allowed file size in the policy.
	Acl                 string  // AWS S3 ACL (Access Control List). Default is private.
	CacheControl        string  // Cache control header. Default is none.
}
```

Represents options for the policy.

### `PresignedPostRequestFields`

```go
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
```

Represents presigned POST information.

### `Policy`

```go
type Policy struct {
	Expiration string // Expiration time of the policy.
	Bucket     string // AWS S3 bucket.
	Key        string // Key (file path) for the S3 object.
	Credential string // AWS credential information.
	Algorithm  string // AWS algorithm for the policy.
	Date       string // Date of the policy.
}
```

Represents a new policy.

## License

This package is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.