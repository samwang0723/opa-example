package main

import (
	"context"
	"log"

	"github.com/open-policy-agent/opa/rego"
)

var policyFile = "ads.rego"
var defaultQuery = "x = data.rbac.authz.allow"

type input struct {
	User   string `json:"user"`
	Action string `json:"action"`
	Object string `json:"object"`
}

func main() {
	//simulate input for evaluation
	s := input{
		User:   "campaign_manager",
		Action: "update",
		Object: "flight",
	}

	input := map[string]interface{}{
		"user":   []string{s.User},
		"action": s.Action,
		"object": s.Object,
	}

	//load policy file
	policy, err := readPolicy(policyFile)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.TODO()
	query, err := rego.New(
		rego.Query(defaultQuery),
		rego.Module(policyFile, string(policy)),
	).PrepareForEval(ctx)

	if err != nil {
		log.Fatalf("initial rego error: %v", err)
	}

	ok, _ := verify(ctx, query, input)
	log.Println("campaign_manager permission: ", ok)
}

func verify(ctx context.Context, query rego.PreparedEvalQuery, input map[string]interface{}) (bool, error) {
	results, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		log.Fatalf("evaluation error: %v", err)
	} else if len(results) == 0 {
		log.Fatal("undefined result", err)
		//TODO: Handle undefined result
	} else if result, ok := results[0].Bindings["x"].(bool); !ok {
		log.Fatalf("unexpected result type: %v", result)
	}

	return results[0].Bindings["x"].(bool), nil
}
