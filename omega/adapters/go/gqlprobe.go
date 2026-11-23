// gqlprobe — OMEGA GraphQL endpoint prober (Go core).
//
// Read-only GraphQL abuse detection across candidate endpoints:
//  1. endpoint discovery (GET + POST to common graphql paths)
//  2. introspection enabled check (full __schema query)
//  3. field-suggestion leak ("Did you mean" on a typo field)
//  4. GET-based query injection (query via query-string)
//  5. array batching accepted check
//  6. depth-limit probe (deep but harmless alias query)
//
// All probes are syntactically valid, read-only queries.
//
// Input (JSON stdin):
//
//	{"target":"http://h","endpoints":["/graphql"],"timeout_ms":3000}
//
// Output (JSON stdout):
//
//	{"endpoints":[{"path","introspection":bool,"suggestions":bool,
//	               "get_query":bool,"batch":bool,"deep":bool,"note":...}]}
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type input struct {
	Target    string   `json:"target"`
	Endpoints []string `json:"endpoints"`
	TimeoutMs int      `json:"timeout_ms"`
}

func emit(v interface{}) {
	out, _ := json.Marshal(v)
	fmt.Println(string(out))
}

var defaultEndpoints = []string{
	"/graphql", "/graphql/", "/api/graphql", "/v1/graphql", "/gql",
	"/graphiql", "/api/v1/graphql", "/graphql/console",
}

func main() {
	raw, _ := io.ReadAll(bufio.NewReaderSize(os.Stdin, 1<<20))
	var in input
	if err := json.Unmarshal(raw, &in); err != nil || in.Target == "" {
		emit(map[string]interface{}{"error": "invalid input"})
		return
	}
	base := strings.TrimRight(in.Target, "/")
	if !strings.HasPrefix(base, "http") {
		base = "http://" + base
	}
	endpoints := in.Endpoints
	if len(endpoints) == 0 {
		endpoints = defaultEndpoints
	}
	timeout := 3 * time.Second
	if in.TimeoutMs > 0 {
		timeout = time.Duration(in.TimeoutMs) * time.Millisecond
	}
	client := &http.Client{Timeout: timeout}

	probe := func(path, body, method, qstring string) (int, string) {
		url := base + path
		var req *http.Request
		var err error
		if method == "GET" {
			url += "?" + qstring
			req, err = http.NewRequest("GET", url, nil)
		} else {
			req, err = http.NewRequest("POST", url,
				bytes.NewBufferString(body))
			if err == nil {
				req.Header.Set("Content-Type", "application/json")
			}
		}
		if err != nil {
			return 0, ""
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; browser)")
		resp, err := client.Do(req)
		if err != nil {
			return 0, ""
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		return resp.StatusCode, string(b)
	}

	found := []map[string]interface{}{}
	for _, ep := range endpoints {
		// discovery: simple valid query
		st, body := probe(ep,
			`{"query":"{ __typename }"}`, "POST", "")
		if st == 0 {
			continue
		}
		low := strings.ToLower(body)
		isGql := st != 404 && st != 405 &&
			(strings.Contains(low, "__typename") ||
				strings.Contains(low, "graphql") ||
				strings.Contains(low, "query") ||
				strings.Contains(low, "error"))
		if !isGql && st >= 400 {
			continue
		}
		res := map[string]interface{}{"path": ep, "status": st}

		// 1. introspection
		_, iBody := probe(ep,
			`{"query":"{ __schema { queryType { name } } }"}`,
			"POST", "")
		introspection := strings.Contains(strings.ToLower(iBody),
			"__schema") && !strings.Contains(
			strings.ToLower(iBody), "not allowed")
		res["introspection"] = introspection

		// 2. field suggestions (typo field)
		_, sBody := probe(ep,
			`{"query":"{ heroTypo { id } }"}`, "POST", "")
		res["suggestions"] = strings.Contains(strings.ToLower(sBody),
			"did you mean")

		// 3. GET-based query
		gSt, gBody := probe(ep, "", "GET",
			"query=%7B+__typename+%7D")
		res["get_query"] = gSt == 200 && strings.Contains(
			strings.ToLower(gBody), "__typename")

		// 4. array batching accepted
		_, bBody := probe(ep,
			`[{"query":"{ __typename }"},{"query":"{ __typename }"}]`,
			"POST", "")
		res["batch"] = strings.HasPrefix(strings.TrimSpace(bBody), "[")

		// 5. deep alias chain (harmless depth test)
		deep := "{ "
		for i := 0; i < 60; i++ {
			deep += fmt.Sprintf("a%d: __typename ", i)
		}
		deep += "}"
		dSt, dBody := probe(ep,
			fmt.Sprintf(`{"query":%q}`, deep), "POST", "")
		res["deep_ok"] = dSt == 200 && !strings.Contains(
			strings.ToLower(dBody), "depth")

		found = append(found, res)
	}
	emit(map[string]interface{}{"target": in.Target,
		"endpoints": found, "probed": len(endpoints)})

}
