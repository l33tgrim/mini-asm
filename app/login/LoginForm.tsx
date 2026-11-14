'use client';

import { useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { AlertCircle, Loader2 } from 'lucide-react';
import { safeNextPath } from '@/lib/auth/session';

export default function LoginForm() {
    const params = useSearchParams();
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [busy, setBusy] = useState(false);

    async function submit(e: React.FormEvent) {
        e.preventDefault();
        setBusy(true);
        setError('');
        try {
            const res = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password }),
            });
            if (res.ok) {
                // Full navigation so every server component renders with the new session.
                window.location.assign(safeNextPath(params.get('next')));
                return;
            }
            const data = await res.json().catch(() => ({}));
            setError(data.error || 'Sign in failed.');
        } catch {
            setError('Could not reach the server.');
        }
        setBusy(false);
        setPassword('');
    }

    const field = 'mt-1.5 block w-full rounded-xl border border-input bg-white px-4 py-2.5 text-sm text-foreground outline-none transition focus:border-secondary focus:ring-2 focus:ring-ring/30';

    return (
        <form onSubmit={submit} className="mt-8 space-y-5" noValidate>
            {error && (
                <p role="alert" className="flex items-start gap-2 rounded-xl border border-sev-critical/50 bg-sev-critical/10 px-4 py-3 text-sm text-foreground">
                    <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-sev-critical" aria-hidden />
                    {error}
                </p>
            )}
            <label className="block text-sm font-medium">
                Username
                <input className={field} name="username" autoComplete="username" autoFocus required value={username} onChange={(e) => setUsername(e.target.value)} />
            </label>
            <label className="block text-sm font-medium">
                Password
                <input className={field} type="password" name="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
            </label>
            <button
                type="submit"
                disabled={busy || !username || !password}
                className="flex w-full items-center justify-center gap-2 rounded-full bg-secondary px-6 py-3 text-sm font-semibold text-white transition hover:bg-primary disabled:cursor-not-allowed disabled:opacity-50"
            >
                {busy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden />}
                Sign in
            </button>
        </form>
    );
}
