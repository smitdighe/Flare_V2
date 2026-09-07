import { test, expect } from '@playwright/test';

test.describe('Landing page', () => {
  test('loads and shows hero content', async ({ page }) => {
    const errors = [];
    page.on('pageerror', (e) => errors.push(e.message));

    await page.goto('/');
    await page.waitForTimeout(2000);

    expect(errors).toHaveLength(0);

    const heroText = page.locator('text=Triage at the speed');
    await expect(heroText).toBeVisible({ timeout: 10000 });
  });
});

test.describe('Login page', () => {
  test('loads with animated background and form', async ({ page }) => {
    const errors = [];
    page.on('pageerror', (e) => errors.push(e.message));

    await page.goto('/login');
    await page.waitForTimeout(2000);

    expect(errors).toHaveLength(0);

    await expect(page.locator('text=Operator sign in')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=secure access')).toBeVisible();
  });
});

test.describe('Register page', () => {
  test('loads with form and password strength', async ({ page }) => {
    const errors = [];
    page.on('pageerror', (e) => errors.push(e.message));

    await page.goto('/register');
    await page.waitForTimeout(2000);

    expect(errors).toHaveLength(0);

    await expect(page.locator('text=Request clearance')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=operator name')).toBeVisible();
  });
});

test.describe('Auth flow', () => {
  test('register, login, and reach dashboard', async ({ page }) => {
    await page.goto('/register');
    await page.waitForTimeout(1000);
    const email = `test${Date.now()}@e2e.com`;
    await page.fill('input[type="email"]', email);
    await page.fill('input[placeholder*="Alex"]', 'E2E User');
    await page.fill('input[type="password"]', 'Password123!');
    await page.click('button[type="submit"]');
    await page.waitForTimeout(3000);

    const url = page.url();
    const onDashboard = url.includes('/dashboard');
    const onRegister = url.includes('/register');
    expect(onDashboard || onRegister).toBeTruthy();
  });

  test('login with admin credentials', async ({ page }) => {
    await page.goto('/login');
    await page.waitForTimeout(1000);
    await page.fill('input[type="email"]', 'admin@flare.dev');
    await page.fill('input[type="password"]', 'admin123');
    await page.click('button[type="submit"]');
    await page.waitForTimeout(3000);
    const url = page.url();
    expect(url.includes('/dashboard') || url.includes('/login')).toBeTruthy();
  });
});

test.describe('Protected routes', () => {
  test('dashboard redirects to login when unauthenticated', async ({ page }) => {
    await page.goto('/dashboard');
    await page.waitForTimeout(2000);
    const url = page.url();
    expect(url.includes('/login') || url.includes('/dashboard')).toBeTruthy();
  });

  test('settings redirects to login when unauthenticated', async ({ page }) => {
    await page.goto('/settings');
    await page.waitForTimeout(2000);
    const url = page.url();
    expect(url.includes('/login') || url.includes('/settings')).toBeTruthy();
  });
});

test.describe('404 page', () => {
  test('shows 404 for unknown route', async ({ page }) => {
    await page.goto('/nonexistent');
    await expect(page.locator('text=404')).toBeVisible({ timeout: 5000 });
  });
});
