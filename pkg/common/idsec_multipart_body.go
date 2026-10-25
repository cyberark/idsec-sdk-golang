// Package common provides shared utilities and types for the IDSEC SDK.
package common

import (
	"bytes"
	"mime/multipart"
)

// IdsecMultipartFile is a file part of an IdsecMultipartBody.
type IdsecMultipartFile struct {
	FieldName string
	FileName  string
	Content   []byte
}

// IdsecMultipartBody is a request body sent as multipart/form-data, for endpoints that read
// uploaded files. Pass it as the body of IdsecClient.Post; the client encodes it on every attempt,
// so retries resend the whole body, and sets the Content-Type with the part boundary itself.
type IdsecMultipartBody struct {
	Fields map[string]string
	Files  []IdsecMultipartFile
}

// encode returns the encoded body and its Content-Type.
func (b *IdsecMultipartBody) encode() (*bytes.Buffer, string, error) {
	buffer := &bytes.Buffer{}
	writer := multipart.NewWriter(buffer)
	for key, value := range b.Fields {
		if err := writer.WriteField(key, value); err != nil {
			return nil, "", err
		}
	}
	for _, file := range b.Files {
		part, err := writer.CreateFormFile(file.FieldName, file.FileName)
		if err != nil {
			return nil, "", err
		}
		if _, err := part.Write(file.Content); err != nil {
			return nil, "", err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, "", err
	}
	return buffer, writer.FormDataContentType(), nil
}
