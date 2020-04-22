package main

import (
	"strconv"
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

func (flag *optionalBoolFlag) IsBoolFlag() bool {
	return true
}
