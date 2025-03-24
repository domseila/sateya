const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const cluster = require('cluster');
const os = require('os');

// Add stealth plugin to avoid Cloudflare bot detection
puppeteer.use(StealthPlugin());

// List of user agents
const userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Edg/122.0.1100.55 Safari/537.36',
    'Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/96.0',

];
// Function to get a random user agent
function getRandomUserAgent() {
    const randomIndex = Math.floor(Math.random() * userAgents.length);
    return userAgents[randomIndex];
}

// Function to bypass Cloudflare JS challenge
async function bypassCloudflare(url) {
    // Launch headless browser
    const browser = await puppeteer.launch({
        headless: true,
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-gpu',
            '--window-size=1920,1080'
        ]
    });
    const page = await browser.newPage();

    // Set a random user agent
    const userAgent = getRandomUserAgent();
    await page.setUserAgent(userAgent);

    try {
        console.log(`Navigating to ${url} with user agent: ${userAgent}...`);
        // Navigate to the URL and wait for network to settle
        await page.goto(url, { waitUntil: 'networkidle2', timeout: 60000 });

        // Wait for potential Cloudflare challenge resolution
        await page.waitForNavigation({ timeout: 30000 }).catch(() => {
            console.log('Challenge resolved or no challenge present');
        });

        // Extract cookies and HTML content
        const cookies = await page.cookies();
        const cfClearance = cookies.find(cookie => cookie.name === 'cf_clearance')?.value || 'Not found';
        const html = await page.content();

        // Output results
        console.log('\nResults:');
        console.log('cf_clearance cookie:', cfClearance);
        console.log('HTML Snippet (first 200 chars):', html.slice(0, 200));
        console.log('Full cookies:', JSON.stringify(cookies, null, 2));

        return {
            cfClearance,
            html,
            status: 'Success'
        };
    } catch (error) {
        console.error('Error bypassing Cloudflare:', error.message);
        return {
            cfClearance: 'Not found',
            html: '',
            status: 'Failed',
            error: error.message
        };
    } finally {
        await browser.close();
        console.log('Browser closed.');
    }
}

// Function to handle worker processes
function handleWorker(url) {
    const result = bypassCloudflare(url);
    process.send({ result });
}

// Main execution
if (cluster.isMaster) {
    const numCPUs = os.cpus().length;
    const url = process.argv[2] || 'https://example.com)'; 
    if (!url.startsWith('http')) {
        console.error('Please provide a valid URL (e.g., https://example.com)');
        process.exit(1);
    }

    console.log(`Attempting to bypass Cloudflare for: ${url} using ${numCPUs} workers`);

    for (let i = 0; i < numCPUs; i++) {
        const worker = cluster.fork();
        worker.on('message', (message) => {
            console.log(`Worker ${worker.process.pid} sent: ${JSON.stringify(message)}`);
        });
        worker.send({ url });
    }

    cluster.on('exit', (worker, code, signal) => {
        console.log(`Worker ${worker.process.pid} died with code: ${code}, and signal: ${signal}`);
    });
} else {
    process.on('message', (message) => {
        handleWorker(message.url);
    });
}