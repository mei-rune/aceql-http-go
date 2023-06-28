package aceql_http



const (
ERROR_JDBC_ERROR = 1
ERROR_ACEQL_ERROR = 2
ERROR_ACEQL_UNAUTHORIZED = 3
ERROR_ACEQL_FAILURE = 4
)

type ErrorResult struct {
	Status string `json:"status"`
	ErrorType int `json:"error_type"`
	ErrorMessage string `json:"error_message"`
	StackTrace string `json:"stack_trace"`
	HTTPStatus int `json:"http_status"`
}

type LoginResult struct {
	Status string `json:"status"`
	ConnectionID string `json:"connection_id"`
	SessionID string `json:"session_id"`
}
