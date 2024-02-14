package presignedpost

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/joho/godotenv"
)

type TestCase struct {
	number                     int
	title                      string
	expectedResponseStatusCode int
	key                        string
	fileUploadPath             string
}

func TestPresignedPostObject(t *testing.T) {
	err := godotenv.Load()
	if err != nil {
		t.Fatal("Error loading .env file")
	}

	awsCredentialsAndConfig := AwsCredentialsAndConfig{
		Region:          os.Getenv("AWS_REGION"),
		Bucket:          os.Getenv("AWS_S3_BUCKET"),
		AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
	}

	expiryInSeconds := 3600 // 1 hour

	policyOpts := PolicyOptions{
		ExpiryInSeconds:    &expiryInSeconds,
		Acl:                "public-read",
		ContentType:        "image/jpeg",
		MaxFileSizeInBytes: 10485760, // 10MB
		CacheControl:       "public, max-age=315360000",
	}

	executeTestCase(TestCase{
		number:                     1,
		title:                      "Upload an image file to S3",
		expectedResponseStatusCode: 204,
		key:                        "bird-image.jpeg",
		fileUploadPath:             "assets/bird-image.jpeg",
	}, awsCredentialsAndConfig, policyOpts, t)

	executeTestCase(TestCase{
		number:                     2,
		title:                      "Upload a file with a greater file size than the max file size",
		expectedResponseStatusCode: 400,
		key:                        "bird-image.jpeg",
		fileUploadPath:             "assets/bird-image.jpeg",
	}, awsCredentialsAndConfig, PolicyOptions{
		ExpiryInSeconds:    &expiryInSeconds,
		Acl:                "public-read",
		ContentType:        "image/jpeg",
		MaxFileSizeInBytes: 1000, // 1KB
		CacheControl:       "public, max-age=315360000",
	}, t)

	expiryIn0Seconds := 0 // 0 seconds
	executeTestCase(TestCase{
		number:                     3,
		title:                      "Upload a file after the expiry time",
		expectedResponseStatusCode: 403,
		key:                        "bird-image.jpeg",
		fileUploadPath:             "assets/bird-image.jpeg",
	}, awsCredentialsAndConfig, PolicyOptions{
		ExpiryInSeconds:    &expiryIn0Seconds,
		Acl:                "public-read",
		ContentType:        "image/jpeg",
		MaxFileSizeInBytes: 10485760, // 10MB
		CacheControl:       "public, max-age=315360000",
	}, t)

	executeTestCase(TestCase{
		number:                     4,
		title:                      "Upload a zip file to S3",
		expectedResponseStatusCode: 204,
		key:                        "zipped-bird-image.zip",
		fileUploadPath:             "assets/zipped-bird-image.zip",
	}, awsCredentialsAndConfig, PolicyOptions{
		ExpiryInSeconds:    &expiryInSeconds,
		Acl:                "public-read",
		ContentType:        "application/zip",
		MaxFileSizeInBytes: 10485760, // 10MB
		CacheControl:       "public, max-age=315360000",
	}, t)

	executeTestCase(TestCase{
		number:                     5,
		title:                      "Upload a csv file to S3",
		expectedResponseStatusCode: 204,
		key:                        "sample.csv",
		fileUploadPath:             "assets/sample.csv",
	}, awsCredentialsAndConfig, PolicyOptions{
		ExpiryInSeconds:    &expiryInSeconds,
		Acl:                "public-read",
		ContentType:        "text/csv",
		MaxFileSizeInBytes: 10485760, // 10MB
		CacheControl:       "public, max-age=315360000",
	}, t)
}

func executeTestCase(testCase TestCase, awsCredentialsAndConfig AwsCredentialsAndConfig, policyOpts PolicyOptions, t *testing.T) {
	fmt.Printf("** Test Case: %d - %s **\n", testCase.number, testCase.title)

	postUrl, presignedPostRequestFields, err := PresignedPostObject(testCase.key, awsCredentialsAndConfig, policyOpts)
	if err != nil {
		t.Errorf("Error generating presigned post object: %v", err)
	}

	// Assert that postUrl is generated
	if postUrl == "" {
		t.Error("Empty post URL")
	}

	// Assert that presignedPostRequestFields has necessary fields
	if presignedPostRequestFields.Key != testCase.key ||
		presignedPostRequestFields.Bucket != awsCredentialsAndConfig.Bucket ||
		presignedPostRequestFields.ContentType != policyOpts.ContentType ||
		presignedPostRequestFields.CacheControl != policyOpts.CacheControl ||
		presignedPostRequestFields.Acl != policyOpts.Acl {
		t.Error("Presigned post fields do not match expected values")
	}

	responseStatusCode, err := makeFormPostRequest(postUrl, presignedPostRequestFields, testCase.fileUploadPath)
	if err != nil {
		t.Errorf("Error uploading file: %v", err)
	}

	if responseStatusCode != testCase.expectedResponseStatusCode {
		t.Errorf("Test case failed. \n Expected Status Code: %d. Response Status Code: %d", testCase.expectedResponseStatusCode, responseStatusCode)
	}

	fmt.Println("---------- Status: Passed ✅---------- ")
}

func makeFormPostRequest(postUrl string, presignedPostRequestFields PresignedPostRequestFields, fileUploadPath string) (int, error) {
	// extract file name from file path
	filePathParts := strings.Split(fileUploadPath, "/")
	fileName := filePathParts[len(filePathParts)-1]

	// Test upload
	fields := map[string]string{
		"key":              presignedPostRequestFields.Key,
		"bucket":           presignedPostRequestFields.Bucket,
		"X-Amz-Algorithm":  presignedPostRequestFields.XAmzAlgorithm,
		"X-Amz-Credential": presignedPostRequestFields.XAmzCredential,
		"X-Amz-Date":       presignedPostRequestFields.XAmzDate,
		"Policy":           presignedPostRequestFields.Policy,
		"X-Amz-Signature":  presignedPostRequestFields.XAmzSignature,
	}

	if presignedPostRequestFields.ContentType != "" {
		fields["Content-Type"] = presignedPostRequestFields.ContentType
	}

	if presignedPostRequestFields.CacheControl != "" {
		fields["Cache-Control"] = presignedPostRequestFields.CacheControl
	}

	if presignedPostRequestFields.Acl != "" {
		fields["acl"] = presignedPostRequestFields.Acl
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	for field, value := range fields {
		_ = writer.WriteField(field, value)
	}

	file, err := os.Open(fileUploadPath)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return 0, err
	}
	defer file.Close()

	part, err := writer.CreateFormFile("file", fileName)
	if err != nil {
		fmt.Println("Error creating form file:", err)
		return 0, err
	}

	_, err = io.Copy(part, file)
	if err != nil {
		fmt.Println("Error copying file:", err)
		return 0, err
	}

	err = writer.Close()
	if err != nil {
		fmt.Println("Error closing writer:", err)
		return 0, err
	}

	request, err := http.NewRequest("POST", postUrl, &body)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return 0, err
	}

	request.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		fmt.Println("Error making request:", err)
		return 0, err
	}
	defer response.Body.Close()

	fmt.Println("File upload response status code:", response.StatusCode)

	return response.StatusCode, nil
}
