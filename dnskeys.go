package dkimcrypt

import (
	"crypto/rsa"
	"fmt"
	"net"
	"reflect"
	"strings"
)

// A DKIM TXT record
type DKrecord struct {
	Version     string `fs:"v"`
	Granularity string `fs:"g"`
	KeyType     string `fs:"k"`
	PublicKey   string `fs:"p"`
	Notes       string `fs:"n"`
	// Yeah, we'll not support 'tags' at all, since it's of no importance to us, and adds much complexity.
	//	Testing     bool   `fs:"y"`  // Abstraction of 't/tags'. They only legal tag is 'y=<bool>' which denotes
	// 'testing'. RFC 4870 sec 3.2.3

}

func setField(obj interface{}, name string, value interface{}) error {

	var tag string

	structValue := reflect.ValueOf(obj).Elem()
	structFieldValue := structValue.FieldByName(name)

	if !structFieldValue.IsValid() {
		// find the field that is tagged if the names don't match
		for i := 0; i < reflect.TypeOf(obj).Elem().NumField(); i++ {
			tag = reflect.TypeOf(obj).Elem().Field(i).Tag.Get("fs")
			if tag == name {
				structFieldValue = structValue.Field(i)
				break
			}
		}
		if !structFieldValue.IsValid() {
			return fmt.Errorf("No such field: %s in obj", name)
		}
	}

	if !structFieldValue.CanSet() {
		return fmt.Errorf("Cannot set %s field value", name)
	}

	structFieldType := structFieldValue.Type()
	/*
		// Don't handle tags (here as a bool handling) for reasons explained at struct declaration
		if structFieldType.Name() == "bool" && reflect.TypeOf(value).Name() == "string" {
			value, _ = strconv.ParseBool(value.(string))
		}
	*/
	val := reflect.ValueOf(value)
	if structFieldType != val.Type() {
		return fmt.Errorf("Provided value type didn't match obj field type")
	}

	structFieldValue.Set(val)
	return nil
}

func fillStruct(s interface{}, m map[string]interface{}) error {

	for k, v := range m {
		err := setField(s, k, v)
		if err != nil {
			return err
		}
	}
	return nil
}

func GetDNSKey(domain string) ([]DKrecord, error) {
	txt, err := net.LookupTXT(domain)
	if err != nil {
		return []DKrecord{}, err
	}
	return parseTXTrecord(txt)
}

func GetPubKey(selector, domain string) (*rsa.PublicKey, error) {

	rep, _, err := newPubKeyFromDnsTxt(selector, domain)

	if err != nil {
		return nil, err
	}

	return &rep.PubKey, nil

}

func parseTXTrecord(record []string) (rv []DKrecord, err error) {

	opts := make([]map[string]interface{}, 0)

	for _, rec := range record {

		res := strings.Split(rec, ";")
		tmp := make(map[string]interface{})

		for s := range res {
			trim := strings.TrimSpace(res[s])
			kv := strings.Split(trim, "=")
			if len(kv) < 2 {
				continue
			}
			/*
				** Don't handle 'tags'/'t' part for reasons explained by the struct declaration

						// Handle t/tags, of which there is only one legal, 'y'
						if kv[0] == "t" {
							t := strings.Split(kv[0], "=")
							if len(t) < 2 && t[0] != "y" {
								continue
							}
							kv[0] = "y"
							kv[1] = t[1]
						}

			*/

			tmp[kv[0]] = kv[1]
		}
		opts = append(opts, tmp)
	}
	r := make([]DKrecord, len(opts))

	for i, v := range opts {
		err = fillStruct(&r[i], v)
	}

	return r, err
}
