import type { Metadata } from "next";
import { Poppins } from "next/font/google";
import "./globals.css";
import Sidebar from "@/components/Sidebar";

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
        <Sidebar />
        <main className="min-h-screen lg:pl-64">
          <div className="mx-auto max-w-7xl p-5 sm:p-8">
            {children}
          </div>
        </main>
      </body>
    </html>
  );
}
