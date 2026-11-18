//go:build go1.27 && goexperiment.jsonv2

package decisions

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
)

func decodeStrictJSON(raw []byte, out any) error {
	// The token reader rejects duplicate names. Preserve encoding/json's UTF-8
	// replacement behavior and v1 typed binding rules.
	d := jsontext.NewDecoder(bytes.NewReader(raw), jsontext.AllowInvalidUTF8(true))
	for {
		depth := d.StackDepth()
		token, err := d.ReadToken()
		if err != nil {
			return err
		}
		if depth > strictJSONMaxDepth && token.Kind() != '}' && token.Kind() != ']' {
			return errors.New("JSON nesting limit")
		}
		if d.StackDepth() == 0 {
			break
		}
	}
	if _, err := d.ReadToken(); err != io.EOF {
		return errors.New("one JSON value required")
	}
	return jsonv2.Unmarshal(raw, out, json.DefaultOptionsV1(), jsonv2.RejectUnknownMembers(true))
}
