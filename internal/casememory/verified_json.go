package casememory

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"time"
)

// DecodeLearningJSON requires the exact field names, once each, in every
// nested object. Decoder.DisallowUnknownFields alone permits duplicates and
// case-insensitive aliases; neither is acceptable for signed contracts.
func DecodeLearningJSON(raw []byte, target any) error {
	return DecodeLearningDocument(raw, target, 32768, 32)
}

func DecodeLearningDocument(raw []byte, target any, maxBytes, maxItems int) error {
	if maxBytes < 1 || maxBytes > 2<<20 || maxItems < 1 || maxItems > 4096 || len(raw) == 0 || len(raw) > maxBytes {
		return ErrInvalid
	}
	t := reflect.TypeOf(target)
	if t == nil || t.Kind() != reflect.Pointer || t.Elem().Kind() != reflect.Struct {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := exactLearningValue(decoder, t.Elem(), maxItems); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInvalid
	}
	if json.Unmarshal(raw, target) != nil {
		return ErrInvalid
	}
	return nil
}
func exactLearningValue(d *json.Decoder, t reflect.Type, maxItems int) error {
	token, err := d.Token()
	if err != nil || token == nil {
		return ErrInvalid
	}
	if t == reflect.TypeOf(time.Time{}) {
		if _, ok := token.(string); !ok {
			return ErrInvalid
		}
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		if token != json.Delim('{') {
			return ErrInvalid
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			fields[strings.Split(f.Tag.Get("json"), ",")[0]] = f.Type
		}
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return ErrInvalid
			}
			name, ok := key.(string)
			field, exists := fields[name]
			if !ok || !exists || seen[name] {
				return ErrInvalid
			}
			seen[name] = true
			if err := exactLearningValue(d, field, maxItems); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') || len(seen) != len(fields) {
			return ErrInvalid
		}
	case reflect.Slice, reflect.Array:
		if token != json.Delim('[') {
			return ErrInvalid
		}
		count := 0
		for d.More() {
			count++
			if count > maxItems {
				return ErrLimit
			}
			if err := exactLearningValue(d, t.Elem(), maxItems); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') || (t.Kind() == reflect.Array && count != t.Len()) {
			return ErrInvalid
		}
	default:
		if _, structured := token.(json.Delim); structured {
			return ErrInvalid
		}
	}
	return nil
}
