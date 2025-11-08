package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"

	"github.com/rs/zerolog/log"
)

// stdioRequest represents an incoming JSON request from stdin
type stdioRequest struct {
	ID     string                 `json:"id"`
	Method string                 `json:"method"`
	Params map[string]interface{} `json:"params,omitempty"`
}

// stdioResponse represents an outgoing JSON response to stdout
type stdioResponse struct {
	ID      string      `json:"id"`
	Success bool        `json:"success"`
	Code    int         `json:"code"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// stdioServer handles stdin/stdout JSON-based API by wrapping HTTP handlers
type stdioServer struct {
	server *server
	stdin  io.Reader
	stdout io.Writer
}

// NewStdioServer creates a new stdio server instance
func NewStdioServer(s *server) *stdioServer {
	return &stdioServer{
		server: s,
		stdin:  os.Stdin,
		stdout: os.Stdout,
	}
}

// newStdioServerWithIO creates a stdio server with custom IO streams (for testing)
func newStdioServerWithIO(s *server, stdin io.Reader, stdout io.Writer) *stdioServer {
	return &stdioServer{
		server: s,
		stdin:  stdin,
		stdout: stdout,
	}
}

func (ss *stdioServer) Start() error {
	log.Info().Msg("Starting stdio mode - reading JSON requests from stdin")

	scanner := bufio.NewScanner(ss.stdin)

	const maxCapacity = 512 * 1024 // 512KB
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue // Skip empty lines
		}
		ss.handleRequest(line)
	}

	// Scanner stopped, check why
	if err := scanner.Err(); err != nil {
		log.Error().Err(err).Msg("Error reading from stdin")
		return err
	}

	log.Info().Msg("EOF reached on stdin, shutting down")
	return nil
}

func (ss *stdioServer) handleRequest(requestBytes []byte) {
	var req stdioRequest
	if err := json.Unmarshal(requestBytes, &req); err != nil {
		ss.sendError("", 400, fmt.Sprintf("invalid JSON request: %v", err))
		return
	}
	if req.ID == "" {
		ss.sendError("", 400, "missing request id")
		return
	}
	if req.Method == "" {
		ss.sendError(req.ID, 400, "missing method")
		return
	}
	log.Info().
		Str("id", req.ID).
		Str("method", req.Method).
		Msg("Processing stdio request")
	ss.routeRequest(&req)
}

// routeRequest dispatches the request to the appropriate HTTP handler
func (ss *stdioServer) routeRequest(req *stdioRequest) {
	// Map stdio method to HTTP route and method
	var httpMethod, httpPath string

	switch req.Method {
	case "health":
		httpMethod = "GET"
		httpPath = "/health"
	default:
		ss.sendError(req.ID, 404, fmt.Sprintf("unknown method: %s", req.Method))
		return
	}
	ss.executeHTTPHandler(req, httpMethod, httpPath)
}

// executeHTTPHandler wraps the existing HTTP handler and adapts it for stdio
func (ss *stdioServer) executeHTTPHandler(req *stdioRequest, httpMethod, httpPath string) {
	// Create a mock HTTP request
	var body io.Reader
	if req.Params != nil && len(req.Params) > 0 {
		jsonParams, err := json.Marshal(req.Params)
		if err != nil {
			ss.sendError(req.ID, 400, fmt.Sprintf("invalid params: %v", err))
			return
		}
		body = bytes.NewReader(jsonParams)
	}

	httpReq := httptest.NewRequest(httpMethod, httpPath, body)
	httpReq.Header.Set("Content-Type", "application/json")

	// Set user token header (for user authentication)
	if token, ok := req.Params["token"].(string); ok {
		httpReq.Header.Set("token", token)
	}
	// Set admin token header (for admin authentication)
	if adminToken, ok := req.Params["adminToken"].(string); ok {
		httpReq.Header.Set("Authorization", adminToken)
	}

	recorder := httptest.NewRecorder()
	ss.server.router.ServeHTTP(recorder, httpReq)
	ss.convertHTTPResponse(req.ID, recorder)
}

// convertHTTPResponse converts an HTTP response to a stdio response
func (ss *stdioServer) convertHTTPResponse(requestID string, recorder *httptest.ResponseRecorder) {
	statusCode := recorder.Code
	responseBody := recorder.Body.Bytes()

	var responseData interface{}
	if len(responseBody) > 0 {
		if err := json.Unmarshal(responseBody, &responseData); err != nil {
			// If it's not JSON, just use the raw string
			responseData = string(responseBody)
		}
	}

	success := statusCode >= 200 && statusCode < 300

	if respMap, ok := responseData.(map[string]interface{}); ok {
		// If it's already in wuzapi format, extract the data/error
		if data, hasData := respMap["data"]; hasData {
			ss.sendSuccess(requestID, statusCode, data)
			return
		}
		if errMsg, hasError := respMap["error"]; hasError {
			if errStr, ok := errMsg.(string); ok {
				ss.sendError(requestID, statusCode, errStr)
				return
			}
		}
		ss.sendSuccess(requestID, statusCode, respMap)
		return
	}

	// For non-JSON or simple responses
	if success {
		ss.sendSuccess(requestID, statusCode, responseData)
	} else {
		errorMsg := "request failed"
		if str, ok := responseData.(string); ok && str != "" {
			errorMsg = str
		}
		ss.sendError(requestID, statusCode, errorMsg)
	}
}

func (ss *stdioServer) sendSuccess(id string, code int, data interface{}) {
	response := stdioResponse{
		ID:      id,
		Success: true,
		Code:    code,
		Data:    data,
	}
	ss.writeResponse(response)
}

func (ss *stdioServer) sendError(id string, code int, errorMsg string) {
	response := stdioResponse{
		ID:      id,
		Success: false,
		Code:    code,
		Error:   errorMsg,
	}
	ss.writeResponse(response)
}

func (ss *stdioServer) writeResponse(response stdioResponse) {
	// Marshalled response as single line
	responseBytes, err := json.Marshal(response)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal response")
		fallback := stdioResponse{
			ID:      response.ID,
			Success: false,
			Code:    500,
			Error:   "internal error: failed to marshal response",
		}
		responseBytes, err = json.Marshal(fallback)
		if err != nil {
			log.Error().Err(err).Msg("Failed to marshal fallback response")
			return
		}
	}

	// Write to stdout with newline
	fmt.Fprintf(ss.stdout, "%s\n", string(responseBytes))

	log.Debug().
		Str("id", response.ID).
		Bool("success", response.Success).
		Int("code", response.Code).
		Msg("Sent stdio response")
}
