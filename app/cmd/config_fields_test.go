package cmd

import (
	"reflect"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

// unsetFields returns the mapstructure paths of every leaf field left at its
// zero value, so a config test fixture can be checked for fields it forgot to
// exercise. Nil pointers, empty slices and empty maps count as unset.
//
// For a slice of structs the results are intersected across elements: an entry
// list where each entry only fills the sub-struct matching its own type still
// counts as covering all of them.
func unsetFields(v reflect.Value, path string) []string {
	switch v.Kind() {
	case reflect.Struct:
		var unset []string
		for i := range v.NumField() {
			f := v.Type().Field(i)
			name := f.Tag.Get("mapstructure")
			if name == "" {
				name = f.Name
			}
			unset = append(unset, unsetFields(v.Field(i), path+"."+name)...)
		}
		return unset
	case reflect.Pointer:
		if v.IsNil() {
			return []string{path}
		}
		return unsetFields(v.Elem(), path)
	case reflect.Slice, reflect.Map:
		if v.Len() == 0 {
			return []string{path}
		}
		if v.Kind() != reflect.Slice || v.Index(0).Kind() != reflect.Struct {
			return nil
		}
		unset := unsetFields(v.Index(0), path+"[]")
		for i := 1; i < v.Len(); i++ {
			unset = intersect(unset, unsetFields(v.Index(i), path+"[]"))
		}
		return unset
	default:
		if v.IsZero() {
			return []string{path}
		}
		return nil
	}
}

func intersect(a, b []string) []string {
	inB := make(map[string]struct{}, len(b))
	for _, s := range b {
		inB[s] = struct{}{}
	}
	var out []string
	for _, s := range a {
		if _, ok := inB[s]; ok {
			out = append(out, s)
		}
	}
	return out
}

// assertAllFieldsSet fails with the list of config fields the fixture leaves at
// their zero value. A new config field is only covered once the fixture sets it
// to something distinguishable from the default.
func assertAllFieldsSet(t *testing.T, config any, name string) {
	t.Helper()
	unset := unsetFields(reflect.ValueOf(config), name)
	sort.Strings(unset)
	assert.Empty(t, unset, "config fields not covered by the test fixture")
}
