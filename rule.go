// The MIT License (MIT)
// Copyright (c) 2016 Jason Ish
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use, copy,
// modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package idsrules

// RuleOption is a struct representing an IDS rule option.
type RuleOption struct {
	Option string `json:"option"`
	Args   string `json:"args"`
}

// Rule is a struct representing an IDS rule.
type Rule struct {
	// The raw rule string.
	Raw string `json:"raw"`

	Enabled bool `json:"enabled"`

	// Header components.
	Action     string `json:"action"`
	Proto      string `json:"proto"`
	SourceAddr string `json:"source_addr"`
	SourcePort string `json:"source_port"`
	Direction  string `json:"direction"`
	DestAddr   string `json:"destination_addr"`
	DestPort   string `json:"destination_port"`

	// List of options in order.
	Options []RuleOption `json:"options"`

	// Some options are also pulled out for easy access.
	Msg string `json:"msg"`
	Sid uint64 `json:"sid"`
	Gid uint64 `json:"gid"`
}
