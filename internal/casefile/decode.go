package casefile

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// wire rejects duplicate/aliased keys, null and excessive nesting before Go's
// struct decoder can silently merge duplicate objects or zero a null value.
func wire(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return errors.New("JSON nesting limit")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		if token == nil {
			return errors.New("null contract field")
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] || name != strings.ToLower(name) {
					return errors.New("duplicate or noncanonical JSON field")
				}
				seen[name] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("one JSON value required")
	}
	return nil
}

func Decode(r io.Reader) (Bundle, error) {
	var b Bundle
	data, err := io.ReadAll(io.LimitReader(r, MaxBundle+1))
	if err != nil {
		return b, err
	}
	if len(data) > MaxBundle {
		return b, errors.New("case fixture byte limit")
	}
	if err = wire(data); err != nil {
		return b, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	err = d.Decode(&b)
	return b, err
}
