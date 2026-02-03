const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function main() {
    console.log('Finding fields:', Object.keys(prisma.finding));
    // Try to find the unique input type name from the client's internal metadata if possible
    // or just try to perform a lookup with the suspected key
    try {
        const f = await prisma.finding.findUnique({
            where: {
                ip_port: { ip: '1.2.3.4', port: 80 }
            }
        });
        console.log('Lookup successful (even if null)');
    } catch (e) {
        console.error('Lookup failed for ip_port:', e.message);
    }
    await prisma.$disconnect();
}

main();
