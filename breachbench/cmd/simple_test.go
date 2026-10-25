package cmd

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

func TestSimpleImageInputAndPrompt(t *testing.T) {
	for _, test := range []struct {
		name, input, mode string
		args              []string
		demo              bool
	}{
		{"one image", "", "argon", []string{"local/app:before"}, false},
		{"prompt", "local/app:before\n", "argon", nil, false},
		{"piped without newline", "local/app:before", "argon", nil, false},
		{"demo without key", "", "tools", []string{"local/app:before", "--mode", "tools", "--demo"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := false
			command := simpleImageCommandWith(func(ctx context.Context, image, mode string, demo bool, out io.Writer) error {
				called = true
				if image != "local/app:before" || mode != test.mode || demo != test.demo {
					t.Fatalf("unexpected input: %s %s %v", image, mode, demo)
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("image workflow has no timeout")
				}
				return nil
			})
			command.SetArgs(test.args)
			command.SetIn(strings.NewReader(test.input))
			command.SetOut(&bytes.Buffer{})
			command.SetErr(&bytes.Buffer{})
			if err := command.Execute(); err != nil || !called {
				t.Fatalf("single image flow failed: %v; called=%v", err, called)
			}
		})
	}
}

func TestSimpleImageRejectsExtraOrEmptyInput(t *testing.T) {
	for _, args := range [][]string{{"one", "two"}, nil} {
		command := simpleImageCommandWith(func(context.Context, string, string, bool, io.Writer) error {
			t.Fatal("invalid CLI input reached the engine")
			return nil
		})
		command.SetArgs(args)
		command.SetIn(strings.NewReader(""))
		command.SetOut(&bytes.Buffer{})
		command.SetErr(&bytes.Buffer{})
		if err := command.Execute(); err == nil {
			t.Fatalf("invalid input accepted: %v", args)
		}
	}
}

func TestRootNowOffersImageInputInsteadOfDiscardedTokenPrompt(t *testing.T) {
	command := newRootCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetArgs([]string{"--help"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"breachbench [IMAGE]", "--demo", "--mode", "not runtime-tested"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("root help missing %s: %s", want, output.String())
		}
	}
}
