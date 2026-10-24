package cmd

import (
	"strings"

	"charm.land/lipgloss/v2"
)

func renderBanner(input string) string {
	// Argon accents on the terminal's own background.
	const (
		blue  = "#53A9F4"
		cyan  = "#94DAFE"
		white = "#F2F8FE"
	)
	accent := lipgloss.NewStyle().Foreground(lipgloss.Color(blue))
	value := lipgloss.NewStyle().Foreground(lipgloss.Color(white))

	title := accent.Bold(true).Render(">_") + " " + value.Bold(true).Render("BreachBench")
	field := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(blue)).
		Foreground(lipgloss.Color(cyan)).
		Padding(0, 1).
		Width(35).
		Render(input)
	details := value.Bold(true).Render("Gemini token") + "\n" + field
	body := lipgloss.JoinHorizontal(lipgloss.Center,
		lipgloss.NewStyle().Width(38).Render(details), renderGeminiLogo())
	card := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(blue)).
		Padding(0, 1).
		Width(56).
		Render(title + "\n\n" + body)
	return card
}

func renderGeminiLogo() string {
	paint := func(hex, text string) string {
		return lipgloss.NewStyle().Foreground(lipgloss.Color(hex)).Render(text)
	}
	// Half blocks keep the sparkle's curved sides compact in terminal cells.
	return strings.Join([]string{
		"      " + paint("#FF5650", "▄"),
		"     " + paint("#FF7850", "▐") + paint("#DA7C9B", "█") + paint("#9290F4", "▌"),
		"   " + paint("#FFB747", "▄▄") + paint("#ED918A", "██") + paint("#9290F4", "█") + paint("#5A9DF6", "▄▄"),
		paint("#FFD34E", "▄▄█") + paint("#B5D971", "██") + paint("#65C9C6", "██") + paint("#4F8FFF", "████▄▄"),
		"   " + paint("#4FCF87", "▀▀") + paint("#42C6AD", "██") + paint("#59ADDC", "█▀▀"),
		"     " + paint("#34C77B", "▐█") + paint("#42C6AD", "▌"),
		"      " + paint("#34C77B", "▀"),
	}, "\n")
}
