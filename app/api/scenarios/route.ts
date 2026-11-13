import { NextResponse } from 'next/server';
import { scenarioCatalog, listPlaybooks } from '@/lib/engine/registry';
import { listAllowedCommands } from '@/lib/safety/commandAllowlist';

export async function GET() {
    return NextResponse.json({
        scenarios: scenarioCatalog(),
        playbooks: listPlaybooks(),
        allowedCommands: listAllowedCommands(),
    });
}
