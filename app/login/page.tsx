import type { Metadata } from 'next';
import { Suspense } from 'react';
import LoginForm from './LoginForm';
import { PayIncLogo } from '@/components/ui';

export const metadata: Metadata = { title: 'Sign in' };

export default function LoginPage() {
    return (
        <div className="grid min-h-screen lg:grid-cols-2">
            <section className="hidden flex-col justify-between bg-primary p-12 text-white lg:flex">
                <PayIncLogo onDark className="h-[52px] w-auto self-start" />
                <div className="max-w-md">
                    <h1 className="text-4xl font-bold leading-tight text-white">Security Validation</h1>
                    <p className="mt-4 text-base text-white/80">
                        Attack surface mapping, vulnerability checks and safe breach confirmation for PayInc systems.
                    </p>
                </div>
                <p className="text-xs text-white/70">Only scan systems you own or are authorised to test.</p>
            </section>

            <section className="flex items-center justify-center px-4 py-12 sm:px-8">
                <div className="w-full max-w-sm">
                    <PayIncLogo className="mb-10 h-[40px] w-auto lg:hidden" />
                    <h2 className="text-2xl font-bold">Sign in</h2>
                    <p className="mt-1 text-sm text-muted-foreground">Use the account set for this server.</p>
                    <Suspense fallback={null}>
                        <LoginForm />
                    </Suspense>
                </div>
            </section>
        </div>
    );
}
