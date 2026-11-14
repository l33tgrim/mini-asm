import type { Metadata } from "next";
import { Poppins } from "next/font/google";
import "./globals.css";
import AppShell from "@/components/AppShell";

const poppins = Poppins({ subsets: ["latin"], weight: ["300", "400", "500", "600", "700"], variable: "--font-poppins" });

export const metadata: Metadata = {
  title: { default: "PayInc Security Validation", template: "%s | PayInc Security Validation" },
  description: "Breach and attack simulation and attack surface management for PayInc",
  robots: { index: false, follow: false },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${poppins.variable} min-h-screen bg-background`}>
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
