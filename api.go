package aceql_http

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const (
	ERROR_JDBC_ERROR         = 1
	ERROR_ACEQL_ERROR        = 2
	ERROR_ACEQL_UNAUTHORIZED = 3
	ERROR_ACEQL_FAILURE      = 4
)

const (
	OK   = "OK"   // if the call was successful.
	FAIL = "FAIL" // if an error occurred.
)

// { "status": "FAIL", "error_type": 1, "error_message": "传回预期之外的结果。", "http_status": 400 }
type ErrorResult struct {
	Status       string `json:"status"`
	ErrorType    int    `json:"error_type"`
	ErrorMessage string `json:"error_message"`
	StackTrace   string `json:"stack_trace"`
	HTTPStatus   int    `json:"http_status"`
}

func (e *ErrorResult) Error() string {
	return e.ErrorMessage
}

type Session struct {
	ConnectionID string `json:"connection_id"`
	SessionID    string `json:"session_id"`
}

type LoginResult struct {
	Status string `json:"status"`

	Session
}

type UpdateResult struct {
	Status   string `json:"status"`
	RowCount int    `json:"row_count"`
}

type SavepointResult struct {
	Status   string `json:"status"`
	ID       int    `json:"id"`
	Name     string    `json:"name"`
} 

const (
	BIGINT           = "BIGINT"
	BINARY           = "BINARY"
	BIT              = "BIT"
	BLOB             = "BLOB"
	CHAR             = "CHAR"
	CHARACTER        = "CHARACTER"
	CLOB             = "CLOB"
	DATE             = "DATE"
	DECIMAL          = "DECIMAL"
	DOUBLE_PRECISION = "DOUBLE_PRECISION"
	FLOAT            = "FLOAT"
	INTEGER          = "INTEGER"
	LONGVARBINARY    = "LONGVARBINARY"
	LONGVARCHAR      = "LONGVARCHAR"
	NUMERIC          = "NUMERIC"
	REAL             = "REAL"
	SMALLINT         = "SMALLINT"
	TIME             = "TIME"
	TIMESTAMP        = "TIMESTAMP"
	TINYINT          = "TINYINT"
	URL              = "URL"
	VARBINARY        = "VARBINARY"
	VARCHAR          = "VARCHAR"
)

type ParamValue struct {
	// BIGINT, BINARY, BIT, BLOB, CHAR, CHARACTER, CLOB, DATE, DECIMAL, DOUBLE_PRECISION, FLOAT, INTEGER, LONGVARBINARY, LONGVARCHAR, NUMERIC, REAL, SMALLINT, TIME, TIMESTAMP, TINYINT, URL, VARBINARY, VARCHAR.
	Type  string
	Value string
	Blob  []byte
}

type QueryResult struct {
	Status     string                                `json:"status"`
	QueryTypes []string                              `json:"column_types"`
	QueryRows  []map[string][]map[string]interface{} `json:"query_rows"`
	RowCount   int                                   `json:"row_count"`
}

func (qr *QueryResult) ToSelectResult() SelectResult {
	var result = SelectResult{
		Status:   qr.Status,
		RowCount: qr.RowCount,
	}

	for _, set := range qr.QueryRows {
		seed := int64(-1)
		var rowList []struct {
			Idx int64
			Row Row
		}

		for key, row := range set {
			id := strings.TrimPrefix(key, "row_")
			idx, _ := strconv.ParseInt(id, 10, 64)
			if idx == 0 {
				seed--
				idx = seed
			}
			var record Row
			for vidx, values := range row {
				var typeStr string
				if vidx < len(qr.QueryTypes) {
					typeStr = qr.QueryTypes[vidx]
				}
				for key, value := range values {
					record = append(record, FieldValue{
						Type:  typeStr,
						Name:  key,
						Value: value,
					})
				}
			}

			rowList = append(rowList, struct {
				Idx int64
				Row Row
			}{
				Idx: idx,
				Row: record,
			})
		}

		sort.Slice(rowList, func(a, b int) bool {
			return rowList[a].Idx < rowList[b].Idx
		})
		var resultSet ResultSet

		for _, row := range rowList {
			resultSet.Rows = append(resultSet.Rows, row.Row)
		}
		result.ResultSets = append(result.ResultSets, resultSet)
	}
	return result
}

type SelectResult struct {
	Status     string      `json:"status"`
	ResultSets []ResultSet `json:"resultSets"`
	RowCount   int         `json:"row_count"`
}

type ResultSet struct {
	Rows []Row `json:"rows"`
}

type FieldValue struct {
	Type  string      `json:"type"`
	Name  string      `json:"name"`
	Value interface{} `json:"value"`
}
type Row []FieldValue

type QueryRow struct {
	CustomerID    int    `json:"customer_id,omitempty"`
	CustomerTitle string `json:"customer_title,omitempty"`
	Fname         string `json:"fname,omitempty"`
}

type Client struct {
	Hc *http.Client

	BaseURL       string
	LobAutoUpload bool
}

func (c *Client) CreateURL(s string, q url.Values) string {
	if strings.HasSuffix(c.BaseURL, "/") {
		if strings.HasPrefix(s, "/") {
			s = c.BaseURL + strings.TrimPrefix(s, "/")
		} else {
			s = c.BaseURL + s
		}
	} else if strings.HasPrefix(s, "/") {
		s = c.BaseURL + s
	} else {
		s = c.BaseURL + "/" + s
	}

	if len(q) > 0 {
		if strings.Contains(s, "?") {
			s = s + "&" + q.Encode()
		} else {
			s = s + "?" + q.Encode()
		}
	}
	return s
}

func formatBool(b bool) string {
	if b {
		return "true"
	}

	return "false"
}

// /aceql/session/{session_id}/connection/{connection_id}/execute_query
func (c *Client) Login(database, username, password string) (*LoginResult, error) {
	u := c.CreateURL("/database/sampledb/username/"+username+"/login",
		url.Values{"password": []string{password}})
	var result LoginResult
	err := c.httpGet(u, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// /aceql/session/{session_id}/connection/{connection_id}/set_savepoint
func (c *Client) SetSavepoint(sess *Session) (*SavepointResult, error) {
	u := c.CreateURL("session/"+sess.SessionID+"/connection/"+sess.ConnectionID+"/set_savepoint", nil)

	var result SavepointResult
	err := c.httpGet(u, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// /aceql/session/{session_id}/connection/{connection_id}/set_named_savepoint
func (c *Client) SetNamedSavepoint(sess *Session, name string) (*SavepointResult, error) {
	if name == "" {
		return nil, errors.New("savepoint name is missing")
	}

	u := c.CreateURL("session/"+sess.SessionID+"/connection/"+sess.ConnectionID+"/set_named_savepoint", nil)

	var params url.Values
	params.Set("name", name)

	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, errors.New("new request: " + err.Error())
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	var result SavepointResult
	err = c.httpDo(req, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// /aceql/session/{session_id}/connection/{connection_id}/rollback_savepoint
func (c *Client) RollbackSavepoint(sess *Session, id int, name string) error {
	u := c.CreateURL("session/"+sess.SessionID+"/connection/"+sess.ConnectionID+"/rollback_savepoint", nil)

	var params url.Values
	if id > 0 {
		params.Set("id", strconv.FormatInt(int64(id), 10))
	}
	if name != "" {
		params.Set("name", name)
	}
	if len(params) == 0 {
		return errors.New("savepoint id or name is missing")
	}

	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(params.Encode()))
	if err != nil {
		return errors.New("new request: " + err.Error())
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	var result struct {
		Status string `json:"status"`
	}
	err = c.httpDo(req, &result)
	if err != nil {
		return err
	}
	if result.Status == OK {
		return nil
	}
	return errors.New(result.Status)
}

// /aceql/session/{session_id}/connection/{connection_id}/release_savepoint
func (c *Client) ReleaseSavepoint(sess *Session, id int, name string) error {
	u := c.CreateURL("session/"+sess.SessionID+"/connection/"+sess.ConnectionID+"/release_savepoint", nil)

	var params url.Values
	if id > 0 {
		params.Set("id", strconv.FormatInt(int64(id), 10))
	}
	if name != "" {
		params.Set("name", name)
	}
	if len(params) == 0 {
		return errors.New("savepoint id or name is missing")
	}

	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(params.Encode()))
	if err != nil {
		return errors.New("new request: " + err.Error())
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	var result struct {
		Status string `json:"status"`
	}
	err = c.httpDo(req, &result)
	if err != nil {
		return err
	}
	if result.Status == OK {
		return nil
	}
	return errors.New(result.Status)
}


// /aceql/session/{session_id}/connection/{connection_id}/execute_update
func (c *Client) ExecuteUpdate(sess *Session, sql string, args []ParamValue, preparedStatement bool) (int, error) {
	var params = url.Values{
		"sql":                []string{sql},
		"prepared_statement": []string{formatBool(preparedStatement)},
	}

	var req *http.Request
	if len(args) > 0 {
		params.Set("prepared_statement", "true")
		// "prepared_statement": []string{formatBool(preparedStatement)},

		if c.LobAutoUpload {
			for idx, arg := range args {
				if arg.Type == BLOB || arg.Type == CLOB {
					blobID := GenerateID() + "." + arg.Type
					bs := arg.Blob
					if len(bs) == 0 && arg.Value != "" {
						bs = []byte(arg.Value)
					}
					err := c.BlobUpload(sess, blobID, bs)
					if err != nil {
						return 0, err
					}
					args[idx].Value = blobID
				}
			}
		}

		for idx, arg := range args {
			idxstr := strconv.Itoa(idx + 1)
			params.Set("param_type_"+idxstr, arg.Type)
			params.Set("param_value_"+idxstr, arg.Value)
		}

		u := c.CreateURL("session/"+sess.SessionID+"/connection/"+sess.ConnectionID+"/execute_update", nil)

		var err error
		req, err = http.NewRequest(http.MethodPost, u, strings.NewReader(params.Encode()))
		if err != nil {
			return 0, errors.New("new request: " + err.Error())
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		u := c.CreateURL("session/"+sess.SessionID+"/connection/"+sess.ConnectionID+"/execute_update", params)

		var err error
		req, err = http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return 0, err
		}
	}

	req.Header.Set("Accept", "application/json")

	var result UpdateResult
	err := c.httpDo(req, &result)
	if err != nil {
		return 0, err
	}
	return result.RowCount, nil
}

// /aceql/session/{session_id}/connection/{connection_id}/execute_query
func (c *Client) ExecuteQuery(sess *Session, sql string, args []ParamValue, columnTypes bool) (*QueryResult, error) {
	var params = url.Values{
		"sql":          []string{sql},
		"column_types": []string{formatBool(columnTypes)},
	}

	var req *http.Request
	if len(args) > 0 {
		for idx, arg := range args {
			idxstr := strconv.Itoa(idx + 1)
			params.Set("param_type_"+idxstr, arg.Type)
			params.Set("param_value_"+idxstr, arg.Value)
		}
		u := c.CreateURL("session/"+sess.SessionID+"/connection/"+sess.ConnectionID+"/execute_query", nil)

		var err error
		req, err = http.NewRequest(http.MethodPost, u, strings.NewReader(params.Encode()))
		if err != nil {
			return nil, errors.New("new request: " + err.Error())
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		u := c.CreateURL("session/"+sess.SessionID+"/connection/"+sess.ConnectionID+"/execute_query", params)

		var err error
		req, err = http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
	}

	req.Header.Set("Accept", "application/json")

	var result QueryResult
	err := c.httpDo(req, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// session/{session_id}/connection/{connection_id}/blob_upload
func (c *Client) BlobUpload(sess *Session, blobID string, data []byte) error {
	u := c.CreateURL("session/"+sess.SessionID+"/connection/"+sess.ConnectionID+"/blob_upload", nil)

	var b bytes.Buffer
	w := multipart.NewWriter(&b)           //返回一个设定了一个随机boundary的Writer w，并将数据写入&b
	err := w.WriteField("blob_id", blobID) //WriteField方法调用CreateFormField，设置属性名（对应name）为"key",并在下一行写入该属性值对应的value = "val"
	if err != nil {
		return errors.New("set blob_id error: " + err.Error())
	}

	part, err := w.CreateFormFile("file", "file.txt") //使用给出的属性名（对应name）和文件名（对应filename）创建一个新的form-data头，part为io.Writer类型
	if err != nil {
		return errors.New("create form file error: " + err.Error())
	}
	_, err = part.Write(data) //然后将文件的内容添加到form-data头中
	if err != nil {
		return errors.New("write form file error: " + err.Error())
	}
	err = w.Close()
	if err != nil {
		return errors.New("flush from error: " + err.Error())
	}

	req, err := http.NewRequest(http.MethodPost, u, &b)
	if err != nil {
		return errors.New("new request: " + err.Error())
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Accept", "application/json")

	return c.httpDo(req, nil)
}

// session/{session_id}/connection/{connection_id}/get_blob_length
func (c *Client) GetBlobLength(sess *Session, blobID string) (int64, error) {
	u := c.CreateURL("session/"+sess.SessionID+"/connection/"+sess.ConnectionID+"/get_blob_length", nil)

	body := url.Values{}
	body.Set("blob_id", blobID)

	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(body.Encode()))
	if err != nil {
		return 0, errors.New("new request: " + err.Error())
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	var result struct {
		Status string `json:"status"`
		Length int64  `json:"length"`
	}
	err = c.httpDo(req, &result)
	if err != nil {
		return 0, err
	}
	return result.Length, nil
}

// session/{session_id}/connection/{connection_id}/blob_download
func (c *Client) GetBlob(sess *Session, blobID string) ([]byte, error) {
	u := c.CreateURL("session/"+sess.SessionID+"/connection/"+sess.ConnectionID+"/blob_download", nil)

	body := url.Values{}
	body.Set("blob_id", blobID)

	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, errors.New("new request: " + err.Error())
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var result []byte
	err = c.httpDo(req, &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (c *Client) httpGet(u string, result interface{}) error {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	return c.httpDo(req, result)
}

func (c *Client) httpDo(req *http.Request, result interface{}) error {
	hc := c.Hc
	if hc == nil {
		hc = http.DefaultClient
	}

	response, err := hc.Do(req)
	if err != nil {
		return err
	}

	if response.StatusCode != http.StatusOK {
		return ToResponseError(response)
	}

	if response.Body != nil {
		defer func() {
			io.Copy(ioutil.Discard, response.Body)
			response.Body.Close()
		}()
	}
	if result == nil {
		return nil
	}

	bs, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return &ErrorResult{
			Status:       FAIL,
			ErrorType:    ERROR_ACEQL_ERROR,
			ErrorMessage: err.Error(),
			// StackTrace   string `json:"stack_trace"`
			HTTPStatus: response.StatusCode,
		}
	}
	switch v := result.(type) {
	case *[]byte:
		*v = bs
		return nil
	case *string:
		*v = string(bs)
		return nil
	}
	return json.Unmarshal(bs, result)
}

func ToResponseError(response *http.Response) *ErrorResult {
	if response.Body == nil {
		return &ErrorResult{
			Status:       FAIL,
			ErrorType:    ERROR_ACEQL_ERROR,
			ErrorMessage: "No content",
			// StackTrace   string `json:"stack_trace"`
			HTTPStatus: response.StatusCode,
		}
	}
	bs, _ := ioutil.ReadAll(response.Body)

	var result ErrorResult
	err := json.Unmarshal(bs, &result)
	if err != nil {
		if len(bs) == 0 {
			return &ErrorResult{
				Status:       FAIL,
				ErrorType:    ERROR_ACEQL_ERROR,
				ErrorMessage: response.Status,
				// StackTrace   string `json:"stack_trace"`
				HTTPStatus: response.StatusCode,
			}
		}
		return &ErrorResult{
			Status:       FAIL,
			ErrorType:    ERROR_ACEQL_ERROR,
			ErrorMessage: string(bs),
			// StackTrace   string `json:"stack_trace"`
			HTTPStatus: response.StatusCode,
		}
	}
	return &result
}
