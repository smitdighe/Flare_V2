const puppeteer = require('puppeteer');

(async () => {
  try {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    page.on('console', msg => console.log('PAGE LOG:', msg.text()));
    page.on('pageerror', error => console.log('PAGE ERROR:', error.message));
    page.on('requestfailed', request => console.log('REQUEST FAILED:', request.url(), request.failure()?.errorText));

    await page.goto('http://localhost:5173/dashboard', { waitUntil: 'networkidle0' });
    await page.screenshot({ path: 'test_dashboard.png' });
    console.log('Saved screenshot to test_dashboard.png');
    await browser.close();
  } catch (err) {
    console.error(err);
  }
})();
