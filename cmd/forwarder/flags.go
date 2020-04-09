package main

import (
	"strconv"
	"strings"
)

type optionalBoolFlag struct {
	Exists bool
	Value  bool
}

func (flag *optionalBoolFlag) String() string {
	return strconv.FormatBool(flag.Value)
}

func (flag *optionalBoolFlag) Set(s string) error {
	v, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	flag.Exists = true
	flag.Value = v
	return nil
}

func (o *optionalBoolFlag) IsBoolFlag() bool {
	return true
}

type stringSliceFlag []string

func (flag *stringSliceFlag) String() string {
	return strings.Join(*flag, ";")
}

func (flag *stringSliceFlag) Set(s string) error {
	*flag = append(*flag, s)
	return nil
}
