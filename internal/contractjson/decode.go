// Package contractjson decodes bounded signed contracts without aliases,
// duplicate/missing/unknown members, nulls, or silently padded fixed vectors.
package contractjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"time"
)

var ErrInvalid = errors.New("invalid exact contract")

func Decode(raw []byte, target any, maxBytes, maxItems int) error {
	if len(raw) == 0 || len(raw) > maxBytes || maxBytes < 1 || maxItems < 1 {
		return ErrInvalid
	}
	t := reflect.TypeOf(target)
	if t == nil || t.Kind() != reflect.Pointer || t.Elem().Kind() != reflect.Struct {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := value(d, t.Elem(), maxItems, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalid
	}
	return json.Unmarshal(raw, target)
}
func value(d *json.Decoder, t reflect.Type, limit, depth int) error {
	if depth > 32 {
		return ErrInvalid
	}
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	tok, err := d.Token()
	if err != nil || tok == nil {
		return ErrInvalid
	}
	if t == reflect.TypeOf(time.Time{}) {
		if _, ok := tok.(string); !ok {
			return ErrInvalid
		}
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		if tok != json.Delim('{') {
			return ErrInvalid
		}
		fields := map[string]reflect.Type{}
		required := map[string]bool{}
		seen := map[string]bool{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")
			if tag[0] == "-" {
				continue
			}
			fields[tag[0]] = f.Type
			required[tag[0]] = len(tag) == 1 || tag[1] != "omitempty"
		}
		for d.More() {
			key, e := d.Token()
			if e != nil {
				return ErrInvalid
			}
			name, ok := key.(string)
			ft, exists := fields[name]
			if !ok || !exists || seen[name] {
				return ErrInvalid
			}
			seen[name] = true
			if err := value(d, ft, limit, depth+1); err != nil {
				return err
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return ErrInvalid
		}
		for name, must := range required {
			if must && !seen[name] {
				return ErrInvalid
			}
		}
	case reflect.Array, reflect.Slice:
		if tok != json.Delim('[') {
			return ErrInvalid
		}
		n := 0
		for d.More() {
			n++
			if n > limit {
				return ErrInvalid
			}
			if err := value(d, t.Elem(), limit, depth+1); err != nil {
				return err
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') || (t.Kind() == reflect.Array && n != t.Len()) {
			return ErrInvalid
		}
	default:
		if _, ok := tok.(json.Delim); ok {
			return ErrInvalid
		}
	}
	return nil
}
