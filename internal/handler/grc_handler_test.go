package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestGrcErrorResponse(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "test error message")

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	errObj, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatal("response missing error object")
	}
	if errObj["code"] != "INVALID_REQUEST" {
		t.Errorf("error code = %q, want INVALID_REQUEST", errObj["code"])
	}
	if errObj["message"] != "test error message" {
		t.Errorf("error message = %q, want 'test error message'", errObj["message"])
	}
}

func TestCreateCheck_MissingISMSPItemID(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	c.Request = httptest.NewRequest("POST", "/compliance/check", nil)
	c.Request.Header.Set("Content-Type", "multipart/form-data")

	h := &GRCHandler{}
	h.CreateCheck(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	errObj := resp["error"].(map[string]any)
	if errObj["code"] != "INVALID_REQUEST" {
		t.Errorf("error code = %q, want INVALID_REQUEST", errObj["code"])
	}
}

func TestGetCheck_MissingJobID(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/compliance/check/", nil)
	c.Params = gin.Params{{Key: "job_id", Value: ""}}

	h := &GRCHandler{}
	h.GetCheck(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestGrcErrorCodes(t *testing.T) {
	tests := []struct {
		status  int
		code    string
		message string
	}{
		{400, "INVALID_REQUEST", "필수 필드 누락"},
		{400, "INVALID_EVIDENCE_METADATA", "files와 evidence_metadata 길이 불일치"},
		{400, "UNSUPPORTED_FILE_FORMAT", "허용 확장자 외"},
		{400, "UNSUPPORTED_ITEM", "isms_p_item_id 미지원"},
		{400, "INVALID_EVIDENCE_TYPE", "evidence_type 허용값 외"},
		{404, "JOB_NOT_FOUND", "job_id 미존재"},
		{413, "PAYLOAD_TOO_LARGE", "크기 초과"},
		{500, "INTERNAL_ERROR", "예외"},
	}

	for _, tt := range tests {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		grcError(c, tt.status, tt.code, tt.message)

		if w.Code != tt.status {
			t.Errorf("code=%s: status = %d, want %d", tt.code, w.Code, tt.status)
		}

		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		errObj := resp["error"].(map[string]any)
		if errObj["code"] != tt.code {
			t.Errorf("error code = %q, want %q", errObj["code"], tt.code)
		}
	}
}
