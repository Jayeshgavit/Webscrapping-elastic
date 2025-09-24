#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
import psycopg2
from psycopg2.extras import Json
import time, os, re, warnings, logging
from dotenv import load_dotenv

# ---------------------------
# Logging
# ---------------------------
logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("elastic-scraper")
warnings.filterwarnings("ignore")

# ---------------------------
# Suppress WebDriverManager logs
# ---------------------------
os.environ["WDM_LOG_LEVEL"] = "0"

# ---------------------------
# Load DB config
# ---------------------------
load_dotenv()
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "dbname": os.getenv("DB_NAME", "Elastic"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASS", ""),
    "port": int(os.getenv("DB_PORT", 5432)),
}
TABLE_NAME = "staging_table"

# ---------------------------
# DB helper functions
# ---------------------------
def get_conn():
    return psycopg2.connect(**DB_CONFIG)

def create_table():
    ddl = f"""
    CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
        staging_id SERIAL PRIMARY KEY,
        vendor_name TEXT NOT NULL DEFAULT 'Elastic',
        source_url TEXT UNIQUE,
        raw_data JSONB NOT NULL,
        processed BOOLEAN DEFAULT FALSE,
        processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );
    """
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(ddl)
    conn.commit()
    cur.close()
    conn.close()
    log.info(f"✅ Table '{TABLE_NAME}' ensured.")

def insert_advisory(source_url, raw_data, counter, total):
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            f"""
            INSERT INTO {TABLE_NAME} (source_url, raw_data, vendor_name)
            VALUES (%s, %s, %s)
            ON CONFLICT (source_url) DO UPDATE
            SET raw_data = EXCLUDED.raw_data,
                processed = FALSE,
                processed_at = CURRENT_TIMESTAMP,
                vendor_name = EXCLUDED.vendor_name
            """,
            (source_url, Json(raw_data), "Elastic")
        )
        conn.commit()
        cur.close()
        conn.close()
        print(f"📌 Advisory {counter}/{total} inserted")
    except Exception as e:
        print(f"⚠️ DB insert failed for {source_url}: {e}")

# ---------------------------
# Setup Chrome
# ---------------------------
def create_driver():
    chrome_options = Options()
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1920,1080")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_experimental_option("excludeSwitches", ["enable-logging"])
    chrome_options.add_argument("--log-level=3")
    service = Service(ChromeDriverManager().install(), log_path=os.devnull)
    driver = webdriver.Chrome(service=service, options=chrome_options)
    return driver

# ---------------------------
# Scraping Elastic Announcements
# ---------------------------
def collect_elastic_announcements(driver):
    BASE = "https://discuss.elastic.co/c/announcements/security-announcements/31"
    driver.get(BASE)

    seen = set()
    topics = []

    last_count = -1
    max_attempts = 8
    attempts = 0

    while True:
        # Wait for some rows
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "tr.topic-list-item"))
        )

        soup = BeautifulSoup(driver.page_source, "html.parser")
        rows = soup.select("tr.topic-list-item.category-announcements-security-announcements")
        for row in rows:
            a = row.select_one("a.title.raw-link.raw-topic-link")
            if not a:
                continue
            href = a.get("href")
            full_url = href if href.startswith("http") else ("https://discuss.elastic.co" + href)
            if full_url in seen:
                continue
            seen.add(full_url)

            title = a.get_text(strip=True)
            time_span = row.select_one("td.activity span.relative-date")
            time_data = time_span["data-time"] if time_span and time_span.has_attr("data-time") else None

            topics.append({
                "title": title,
                "url": full_url,
                "activity_time": time_data
            })

        # Scroll down
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        time.sleep(2)

        # Stop condition
        if len(seen) == last_count:
            attempts += 1
        else:
            attempts = 0
        last_count = len(seen)

        if attempts >= max_attempts:
            break

    print(f"✅ Collected {len(topics)} Elastic announcements")
    return topics

# ---------------------------
# Main
# ---------------------------
def main():
    create_table()
    driver = create_driver()

    try:
        topics = collect_elastic_announcements(driver)
        total = len(topics)

        for idx, topic in enumerate(topics, start=1):
            raw_data = {
                "advisory_title": topic["title"],
                "advisory_url": topic["url"],
                "activity_time": topic["activity_time"]
            }
            insert_advisory(topic["url"], raw_data, idx, total)
            time.sleep(0.5)

        print(f"✅ Finished. Stored {total}/{total} announcements.")

    finally:
        driver.quit()

if __name__ == "__main__":
    main()
