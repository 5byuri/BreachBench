package cmd

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

func TestTokenInputPasteAndEditsStayMasked(t *testing.T) {
	for _, size := range []int{16, 2048} {
		name := "short"
		if size > 16 {
			name = "long"
		}
		t.Run(name, func(t *testing.T) {
			m := newTokenInputModel()
			if !m.input.Focused() {
				t.Fatal("token field is not focused")
			}
			// Q does not occur in the banner, so even one exposed cursor rune fails.
			token := strings.Repeat("Q", size)
			steps := []struct {
				name string
				msg  tea.Msg
				size int
			}{
				{"paste", tea.PasteMsg{Content: token}, size},
				{"move left", tea.KeyPressMsg{Code: tea.KeyLeft}, size},
				{"backspace", tea.KeyPressMsg{Code: tea.KeyBackspace}, size - 1},
				{"move home", tea.KeyPressMsg{Code: tea.KeyHome}, size - 1},
				{"delete", tea.KeyPressMsg{Code: tea.KeyDelete}, size - 2},
				{"move end", tea.KeyPressMsg{Code: tea.KeyEnd}, size - 2},
				{"type", tea.KeyPressMsg{Code: 'Q', Text: "Q"}, size - 1},
			}
			for _, step := range steps {
				next, _ := m.Update(step.msg)
				m = next.(tokenInputModel)
				if got := m.input.Value(); got != strings.Repeat("Q", step.size) {
					t.Fatalf("after %s: token was truncated or edited incorrectly (length %d, want %d)", step.name, len(got), step.size)
				}
				view := ansi.Strip(m.View().Content)
				if strings.Contains(view, "Q") {
					t.Fatalf("after %s: token data is visible", step.name)
				}
				if !strings.ContainsRune(view, '•') {
					t.Fatalf("after %s: masked token field is missing", step.name)
				}
				for _, line := range strings.Split(renderBanner(m.input.View()), "\n") {
					if width := ansi.StringWidth(line); width != 56 {
						t.Fatalf("after %s: card line width is %d, want 56", step.name, width)
					}
				}
			}
		})
	}
}

func TestTokenInputEmptyEnterKeepsPromptOpen(t *testing.T) {
	for _, value := range []string{"", "   "} {
		m := newTokenInputModel()
		m.input.SetValue(value)
		next, command := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
		m = next.(tokenInputModel)
		if command != nil || m.submitted || m.cancelled {
			t.Fatalf("Enter accepted an empty or whitespace-only token %q", value)
		}
		if m.View().Content == "" {
			t.Fatal("empty submission hid the prompt")
		}
	}
}

func TestTokenInputSubmitReturnsValueWithoutRenderingIt(t *testing.T) {
	m := newTokenInputModel()
	token := "dummy-gemini-token-Q123"
	next, _ := m.Update(tea.PasteMsg{Content: token})
	m = next.(tokenInputModel)
	next, command := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(tokenInputModel)
	assertTokenInputQuit(t, command)
	if !m.submitted || m.cancelled || m.input.Value() != token {
		t.Fatal("submission did not preserve the token for its caller")
	}
	if m.View().Content != "" {
		t.Fatal("submitted input remains rendered")
	}
}

func TestTokenInputCancelDiscardsValue(t *testing.T) {
	for _, test := range []struct {
		name string
		key  tea.KeyPressMsg
	}{
		{"escape", tea.KeyPressMsg{Code: tea.KeyEscape}},
		{"ctrl+c", tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl}},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := newTokenInputModel()
			next, _ := m.Update(tea.PasteMsg{Content: "dummy-gemini-token-Q123"})
			m = next.(tokenInputModel)
			next, command := m.Update(test.key)
			m = next.(tokenInputModel)
			assertTokenInputQuit(t, command)
			if !m.cancelled || m.submitted || m.input.Value() != "" {
				t.Fatal("cancellation did not discard the token")
			}
			if m.View().Content != "" {
				t.Fatal("cancelled input remains rendered")
			}
		})
	}
}

func assertTokenInputQuit(t *testing.T, command tea.Cmd) {
	t.Helper()
	if command == nil {
		t.Fatal("expected a quit command")
	}
	if _, ok := command().(tea.QuitMsg); !ok {
		t.Fatal("command did not quit the input")
	}
}
