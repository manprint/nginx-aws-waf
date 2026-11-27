package awsexport

import (
	"bytes"
	"encoding/json"
)

// JSON renders the document (or only web_acl with aclOnly), indented, keys sorted.
func JSON(d *Document, aclOnly bool) ([]byte, error) {
	var v any = d
	if aclOnly {
		v = d.WebACL
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
