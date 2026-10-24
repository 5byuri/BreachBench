import "./globals.css";

export const metadata = {
  title: "The British Bank | Fictional banking sandbox",
  description: "A fictional banking interface with dummy data for an intentionally vulnerable, local-only container lab.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en-GB">
      <body>
        <a className="skip-link" href="#main-content">Skip to content</a>
        {children}
      </body>
    </html>
  );
}
