package cmd

import (
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/spf13/cobra"
)

type tokenInputModel struct {
	input     textinput.Model
	submitted bool
	cancelled bool
}

func newTokenInputModel() tokenInputModel {
	input := textinput.New()
	input.Placeholder = "Paste your Gemini token"
	input.Prompt = "> "
	input.EchoMode = textinput.EchoPassword
	input.EchoCharacter = '•'
	input.SetWidth(29)
	styles := input.Styles()
	styles.Focused.Prompt = lipgloss.NewStyle().Foreground(lipgloss.Color("#53A9F4"))
	styles.Focused.Text = lipgloss.NewStyle().Foreground(lipgloss.Color("#F2F8FE"))
	styles.Focused.Placeholder = lipgloss.NewStyle().Foreground(lipgloss.Color("#94DAFE"))
	styles.Cursor.Color = lipgloss.Color("#53A9F4")
	input.SetStyles(styles)
	input.Focus()
	return tokenInputModel{input: input}
}

func (m tokenInputModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m tokenInputModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyPressMsg); ok {
		switch key.String() {
		case "enter":
			if strings.TrimSpace(m.input.Value()) == "" {
				return m, nil
			}
			m.submitted = true
			m.input.Blur()
			return m, tea.Quit
		case "ctrl+c", "esc":
			m.input.Reset()
			m.cancelled = true
			return m, tea.Quit
		}
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m tokenInputModel) View() tea.View {
	if m.submitted || m.cancelled {
		return tea.NewView("")
	}
	hint := lipgloss.NewStyle().Foreground(lipgloss.Color("#94DAFE")).
		Render("  Enter to submit · Esc to cancel")
	return tea.NewView(renderBanner(m.input.View()) + "\n" + hint)
}

func promptGeminiToken(cmd *cobra.Command) (string, error) {
	result, err := tea.NewProgram(newTokenInputModel(),
		tea.WithContext(cmd.Context()),
		tea.WithInput(cmd.InOrStdin()),
		tea.WithOutput(cmd.OutOrStdout()),
	).Run()
	if err != nil {
		return "", err
	}
	model := result.(tokenInputModel)
	if !model.submitted {
		return "", nil
	}
	return model.input.Value(), nil
}
