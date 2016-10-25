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

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

var errIncompleteRule = fmt.Errorf("incomplete rule")

// Remove leading and trailing quotes from a string.
func trimQuotes(buf string) string {
	buflen := len(buf)
	if buflen == 0 {
		return buf
	}
	if buf[0:1] == "\"" && buf[buflen-1:buflen] == "\"" {
		return buf[1 : buflen-1]
	}
	return buf
}

// Remove leading white space from a string.
func trimLeadingWhiteSpace(buf string) string {
	return strings.TrimLeft(buf, " ")
}

func splitAt(buf string, sep string) (string, string) {
	var leading string
	var trailing string

	parts := strings.SplitN(buf, sep, 2)
	if len(parts) > 1 {
		trailing = strings.TrimSpace(parts[1])
	}
	leading = strings.TrimSpace(parts[0])

	return leading, trailing
}

// Parse the next rule option from the provided rule.
//
// The option, argument and the remainder of the rule are returned.
func parseOption(rule string) (string, string, string, error) {
	var option string
	var arg string

	// Strip any leading space.
	rule = trimLeadingWhiteSpace(rule)

	hasArg := false
	optend := strings.IndexFunc(rule, func(r rune) bool {
		switch r {
		case ';':
			return true
		case ':':
			hasArg = true
			return true
		}
		return false
	})
	if optend < 0 {
		return option, arg, rule, fmt.Errorf("unterminated option")
	}

	option = rule[0:optend]

	rule = rule[optend+1:]

	if hasArg {
		if len(rule) == 0 {
			return option, arg, rule, fmt.Errorf("no argument")
		}
		escaped := false
		argend := strings.IndexFunc(rule, func(r rune) bool {
			if escaped {
				escaped = false
			} else if r == '\\' {
				escaped = true
			} else if r == ';' {
				return true
			}
			return false
		})
		if argend < 0 {
			return option, arg, rule,
				fmt.Errorf("unterminated option argument")
		}
		arg = rule[:argend]
		rule = rule[argend+1:]
	}

	return option, trimQuotes(arg), rule, nil
}

// Parse an IDS rule from the provided string buffer.
func Parse(buf string) (Rule, error) {
	rule := Rule{}

	// Removing leading space.
	buf = trimLeadingWhiteSpace(buf)

	// Check enable/disable status.
	if !strings.HasPrefix(buf, "#") {
		rule.Enabled = true
	} else {
		buf = strings.TrimPrefix(buf, "#")
		buf = trimLeadingWhiteSpace(buf)
	}

	action, rem := splitAt(buf, " ")
	rule.Action = action
	if len(rem) == 0 {
		return rule, errIncompleteRule
	}

	proto, rem := splitAt(rem, " ")
	rule.Proto = proto
	if len(rem) == 0 {
		return rule, errIncompleteRule
	}

	sourceAddr, rem := splitAt(rem, " ")
	rule.SourceAddr = sourceAddr
	if len(rem) == 0 {
		return rule, errIncompleteRule
	}

	sourcePort, rem := splitAt(rem, " ")
	rule.SourcePort = sourcePort
	if len(rem) == 0 {
		return rule, errIncompleteRule
	}

	direction, rem := splitAt(rem, " ")
	if !validateDirection(direction) {
		return rule, fmt.Errorf("invalid direction: %s", direction)
	}
	rule.Direction = direction
	if len(rem) == 0 {
		return rule, errIncompleteRule
	}

	destAddr, rem := splitAt(rem, " ")
	rule.DestAddr = destAddr
	if len(rem) == 0 {
		return rule, errIncompleteRule
	}

	destPort, rem := splitAt(rem, " ")
	rule.DestPort = destPort
	if len(rem) == 0 {
		return rule, errIncompleteRule
	}

	offset := 0

	// Check that then next char is a (.
	if rem[offset:offset+1] != "(" {
		return rule, fmt.Errorf("expected (, got %s", rem[0:1])
	}
	offset++

	buf = rem[offset:]

	// Parse options.
	var option string
	var arg string
	var err error
	for {
		if len(buf) == 0 {
			return rule, errIncompleteRule
		}

		buf = trimLeadingWhiteSpace(buf)

		if strings.HasPrefix(buf, ")") {
			// Done.
			break
		}

		option, arg, buf, err = parseOption(buf)
		if err != nil {
			return rule, err
		}

		ruleOption := RuleOption{option, arg}
		rule.Options = append(rule.Options, ruleOption)

		switch option {
		case "msg":
			rule.Msg = arg
		case "sid":
			sid, err := strconv.ParseUint(arg, 10, 64)
			if err != nil {
				return rule, fmt.Errorf("failed to parse sid: %s", arg)
			}
			rule.Sid = sid
		case "gid":
			gid, err := strconv.ParseUint(arg, 10, 64)
			if err != nil {
				return rule, fmt.Errorf("failed to parse sid: %s", arg)
			}
			rule.Gid = gid
		}
	}

	return rule, nil
}

// ParseReader parses multiple rules from a reader.
func ParseReader(reader io.Reader) ([]Rule, error) {

	br := bufio.NewReader(reader)

	rules := make([]Rule, 0)

	buffered := ""

	for {
		bytes, err := br.ReadBytes('\n')
		if err != nil && err != io.EOF {
			return nil, err
		}

		if len(bytes) > 0 {

			line := strings.TrimSpace(string(bytes))

			if strings.HasSuffix(line, "\\") {
				buffered = fmt.Sprintf("%s %s",
					buffered, line[0:len(line)-1])
			} else {
				buffered = fmt.Sprintf("%s %s", buffered, line)
				rule, err := Parse(strings.TrimSpace(buffered))
				if err == nil {
					rules = append(rules, rule)
				}
				buffered = ""
			}
		}

		if err != nil && err == io.EOF {
			break
		}
	}

	return rules, nil
}
