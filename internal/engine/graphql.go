package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

type GraphQLObservation struct {
	IsGraphQL     bool
	BodySHA256    string
	BodyBytes     int
	Operation     string
	OperationName string
	Fields        []string
	Introspection bool
}

var graphqlFieldRE = regexp.MustCompile(`(?m)(?:^|[,{\s])([_A-Za-z][_0-9A-Za-z]*)\s*(?:\(|\{|\n|\r|\t|\s|$)`)

func AnalyzeGraphQLRequest(pathValue, rawQuery, bodySample string) GraphQLObservation {
	obs := GraphQLObservation{IsGraphQL: strings.Contains(strings.ToLower(pathValue), "graphql")}
	if !obs.IsGraphQL {
		return obs
	}
	bodySample = strings.TrimSpace(bodySample)
	if bodySample != "" {
		sum := sha256.Sum256([]byte(bodySample))
		obs.BodySHA256 = hex.EncodeToString(sum[:])
		obs.BodyBytes = len(bodySample)
	}
	query := ""
	operationName := ""
	if bodySample != "" {
		var payload struct {
			Query         string `json:"query"`
			OperationName string `json:"operationName"`
		}
		if json.Unmarshal([]byte(bodySample), &payload) == nil && payload.Query != "" {
			query = payload.Query
			operationName = payload.OperationName
		} else if strings.HasPrefix(bodySample, "{") || strings.HasPrefix(strings.ToLower(bodySample), "query") || strings.HasPrefix(strings.ToLower(bodySample), "mutation") || strings.HasPrefix(strings.ToLower(bodySample), "subscription") {
			query = bodySample
		}
	}
	if query == "" {
		for _, part := range strings.Split(rawQuery, "&") {
			if strings.HasPrefix(part, "query=") {
				query = strings.TrimPrefix(part, "query=")
				if decoded, err := url.QueryUnescape(query); err == nil {
					query = decoded
				}
				break
			}
		}
	}
	obs.OperationName = strings.TrimSpace(operationName)
	low := strings.ToLower(query)
	switch {
	case strings.Contains(low, "__schema") || strings.Contains(low, "__type"):
		obs.Operation = "introspection"
		obs.Introspection = true
	case strings.Contains(low, "__typename"):
		obs.Operation = "typename"
	case strings.Contains(low, "mutation"):
		obs.Operation = "mutation"
	case strings.Contains(low, "subscription"):
		obs.Operation = "subscription"
	case strings.TrimSpace(query) != "":
		obs.Operation = "query"
	default:
		obs.Operation = "missing-query"
	}
	reserved := map[string]bool{
		"query": true, "mutation": true, "subscription": true, "fragment": true, "on": true,
		"true": true, "false": true, "null": true,
	}
	seen := map[string]bool{}
	for _, m := range graphqlFieldRE.FindAllStringSubmatch(query, 32) {
		if len(m) < 2 {
			continue
		}
		name := m[1]
		if reserved[strings.ToLower(name)] || strings.HasPrefix(name, "__") || seen[name] {
			continue
		}
		seen[name] = true
		obs.Fields = append(obs.Fields, name)
		if len(obs.Fields) >= 8 {
			break
		}
	}
	sort.Strings(obs.Fields)
	return obs
}
