// Package common provides shared utilities and types for the IDSEC SDK.
package common

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPostSendsMultipartBody(t *testing.T) {
	var gotField, gotFile, gotName string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Errorf("ParseMultipartForm() error = %v", err)
			return
		}
		gotField = r.FormValue("Name")
		file, header, err := r.FormFile("Upload")
		if err != nil {
			t.Errorf("FormFile() error = %v", err)
			return
		}
		defer func() { _ = file.Close() }()
		content, _ := io.ReadAll(file)
		gotFile, gotName = string(content), header.Filename
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewSimpleIdsecClient(server.URL)
	// A session Content-Type, as a form client sets, must not override the multipart one.
	client.UpdateHeaders(map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	response, err := client.Post(context.Background(), "upload", &IdsecMultipartBody{
		Fields: map[string]string{"Name": "value"},
		Files:  []IdsecMultipartFile{{FieldName: "Upload", FileName: "a.xml", Content: []byte("<xml/>")}},
	})
	if err != nil {
		t.Fatalf("Post() error = %v", err)
	}
	_ = response.Body.Close()
	if gotField != "value" || gotFile != "<xml/>" || gotName != "a.xml" {
		t.Errorf("server received field %q, file %q named %q", gotField, gotFile, gotName)
	}
}

func TestPostResendsMultipartBodyAfterRefresh(t *testing.T) {
	var calls int
	var gotFile string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			// Read part of the body, as a server does before rejecting the token.
			_, _ = io.CopyN(io.Discard, r.Body, 16)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Errorf("ParseMultipartForm() error = %v", err)
			return
		}
		file, _, err := r.FormFile("Upload")
		if err != nil {
			t.Errorf("FormFile() error = %v", err)
			return
		}
		defer func() { _ = file.Close() }()
		content, _ := io.ReadAll(file)
		gotFile = string(content)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	refreshed := false
	client := NewIdsecClient(server.URL, "", "", "Authorization", nil, func(*IdsecClient) error {
		refreshed = true
		return nil
	}, "", false)
	response, err := client.Post(context.Background(), "upload", &IdsecMultipartBody{
		Files: []IdsecMultipartFile{{FieldName: "Upload", FileName: "a.xml", Content: []byte("<xml/>")}},
	})
	if err != nil {
		t.Fatalf("Post() error = %v", err)
	}
	_ = response.Body.Close()
	if !refreshed || calls != 2 || response.StatusCode != http.StatusOK {
		t.Fatalf("refreshed = %t, calls = %d, status = %d, want a refresh and a second call", refreshed, calls, response.StatusCode)
	}
	if gotFile != "<xml/>" {
		t.Errorf("retried request carried file %q, want the full body again", gotFile)
	}
}
