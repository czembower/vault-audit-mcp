package loki

import (
	"fmt"
	"sort"
	"strings"
)

type Selector struct {
	Labels map[string]string
}

func (s Selector) String() string {
	if len(s.Labels) == 0 {
		return "{}"
	}
	keys := make([]string, 0, len(s.Labels))
	for k := range s.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString("{")
	for i, k := range keys {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(fmt.Sprintf(`%s=%q`, k, s.Labels[k]))
	}
	b.WriteString("}")
	return b.String()
}
