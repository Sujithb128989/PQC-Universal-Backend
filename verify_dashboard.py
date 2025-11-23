from playwright.sync_api import sync_playwright, expect

def verify_dashboard():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        print("Navigating to dashboard...")
        page.goto("http://localhost:8080")

        print("Verifying title...")
        expect(page).to_have_title("Universal PQC Backend")

        print("Verifying elements...")
        expect(page.locator("h2.card-title").first).to_have_text("Secure Store")
        expect(page.locator("#systemStatus")).to_be_visible()

        print("Taking screenshot...")
        page.screenshot(path="dashboard_verification.png")

        browser.close()
        print("Verification complete.")

if __name__ == "__main__":
    verify_dashboard()
