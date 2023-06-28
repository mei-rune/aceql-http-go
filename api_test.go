package aceql_http

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

var (
	DefaultPgResetSQL = `drop table tpt_data_channel`
	DefaultPgInitSQL  = `CREATE TABLE IF NOT EXISTS tpt_data_channel (
  id                SERIAL PRIMARY KEY,
  uuid              varchar(200) NOT NULL,
  partitioning_count             int,
  partitioning_sequence          int,
  data              text,
  created_at        timestamp
);`
	DefaultPgInsertSQL = `insert into tpt_data_channel(uuid, partitioning_count, partitioning_sequence, data, created_at) values(?, ?, ?, ?, now());`
	DefaultPgReadSQL   = `select id, uuid, partitioning_count, partitioning_sequence, data, created_at from tpt_data_channel;`
	DefaultPgDeleteSQL = `delete from tpt_data_channel where id = ?;`
)

func TestSQL(t *testing.T) {
	var c = &Client{
		BaseURL:       "http://localhost:9090/aceql",
		LobAutoUpload: true,
	}

	loginRes, err := c.Login(os.Getenv("sqlhttp_db_name"), os.Getenv("sqlhttp_db_username"), os.Getenv("sqlhttp_db_password"))
	if err != nil {
		t.Error(err)
		return
	}
	sess := &loginRes.Session

	// _, err = c.ExecuteUpdate(sess, DefaultPgResetSQL, nil, false)
	// if err != nil {
	//   t.Error(err)
	//   return
	// }

	_, err = c.ExecuteUpdate(sess, DefaultPgInitSQL, nil, false)
	if err != nil {
		t.Error(err)
		return
	}

	for i := 0; i < 10; i++ {
		fmt.Println("======", i)
		_, err = c.ExecuteUpdate(sess, DefaultPgInsertSQL, []ParamValue{
			{
				Type:  VARCHAR,
				Value: "abc",
			},
			{
				Type:  INTEGER,
				Value: "0",
			},
			{
				Type:  INTEGER,
				Value: "0",
			},
			{
				Type:  CLOB,
				Value: strings.Repeat("a", 100*1024*1024),
			},
		}, true)
		if err != nil {
			t.Error(err)
			return
		}
		fmt.Println("======")
	}

	_, err = c.ExecuteQuery(sess, DefaultPgReadSQL, nil, true)
	if err != nil {
		t.Error(err)
		return
	}
	// t.Log(*result)
	// t.Log(result.ToSelectResult())

	_, err = c.ExecuteUpdate(sess, DefaultPgDeleteSQL, []ParamValue{
		{
			Type:  INTEGER,
			Value: "0", // strconv.FormatInt(result.ID, 10),
		},
	}, false)
	if err != nil {
		t.Error(err)
		return
	}
}
