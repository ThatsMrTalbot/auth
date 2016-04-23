// DO NOT EDIT!
// Code generated by ffjson <https://github.com/pquerna/ffjson>
// source: response.go
// DO NOT EDIT!

package auth

import (
	fflib "github.com/pquerna/ffjson/fflib/v1"
)

func (mj *Response) MarshalJSON() ([]byte, error) {
	var buf fflib.Buffer
	if mj == nil {
		buf.WriteString("null")
		return buf.Bytes(), nil
	}
	err := mj.MarshalJSONBuf(&buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
func (mj *Response) MarshalJSONBuf(buf fflib.EncodingBuffer) error {
	if mj == nil {
		buf.WriteString("null")
		return nil
	}
	var err error
	var obj []byte
	_ = obj
	_ = err
	buf.WriteString(`{ `)
	if len(mj.Error) != 0 {
		buf.WriteString(`"error":`)
		fflib.WriteJsonString(buf, string(mj.Error))
		buf.WriteByte(',')
	}
	if len(mj.Token) != 0 {
		buf.WriteString(`"token":`)
		fflib.WriteJsonString(buf, string(mj.Token))
		buf.WriteByte(',')
	}
	if len(mj.RefreshToken) != 0 {
		buf.WriteString(`"refresh_token":`)
		fflib.WriteJsonString(buf, string(mj.RefreshToken))
		buf.WriteByte(',')
	}
	buf.Rewind(1)
	buf.WriteByte('}')
	return nil
}
