const dns = require('dns').promises;

async function test() {
    const domain = 'payinc.co.za';
    console.log(`Testing DNS resolution for ${domain}...`);
    try {
        const a = await dns.resolve4(domain);
        console.log('A Records:', a);

        const mx = await dns.resolveMx(domain);
        console.log('MX Records:', mx);

        const txt = await dns.resolveTxt(domain);
        console.log('TXT Records:', txt);
    } catch (e) {
        console.error('DNS Test Failed:', e.message);
    }
}

test();
