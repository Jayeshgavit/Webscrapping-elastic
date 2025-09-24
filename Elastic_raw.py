# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-

# from selenium import webdriver
# from selenium.webdriver.chrome.service import Service
# from selenium.webdriver.chrome.options import Options
# from selenium.webdriver.common.by import By
# from selenium.webdriver.support.ui import WebDriverWait
# from selenium.webdriver.support import expected_conditions as EC
# from webdriver_manager.chrome import ChromeDriverManager
# from bs4 import BeautifulSoup
# import psycopg2
# from psycopg2.extras import Json
# import time, os, re, warnings, logging
# from dotenv import load_dotenv

# # ---------------------------
# # Logging
# # ---------------------------
# logging.basicConfig(level=logging.INFO, format="%(message)s")
# log = logging.getLogger("elastic-scraper")
# warnings.filterwarnings("ignore")

# # ---------------------------
# # Suppress WebDriverManager logs
# # ---------------------------
# os.environ["WDM_LOG_LEVEL"] = "0"

# # ---------------------------
# # Load DB config
# # ---------------------------
# load_dotenv()
# DB_CONFIG = {
#     "host": os.getenv("DB_HOST", "localhost"),
#     "dbname": os.getenv("DB_NAME", "Elastic"),
#     "user": os.getenv("DB_USER", "postgres"),
#     "password": os.getenv("DB_PASS", ""),
#     "port": int(os.getenv("DB_PORT", 5432)),
# }
# TABLE_NAME = "staging_table"

# # ---------------------------
# # DB helper functions
# # ---------------------------
# def get_conn():
#     return psycopg2.connect(**DB_CONFIG)

# def create_table():
#     ddl = f"""
#     CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
#         staging_id SERIAL PRIMARY KEY,
#         vendor_name TEXT NOT NULL DEFAULT 'Elastic',
#         source_url TEXT UNIQUE,
#         raw_data JSONB NOT NULL,
#         processed BOOLEAN DEFAULT FALSE,
#         processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
#     );
#     """
#     conn = get_conn()
#     cur = conn.cursor()
#     cur.execute(ddl)
#     conn.commit()
#     cur.close()
#     conn.close()
#     log.info(f"✅ Table '{TABLE_NAME}' ensured.")

# def insert_advisory(source_url, raw_data, counter, total):
#     try:
#         conn = get_conn()
#         cur = conn.cursor()
#         cur.execute(
#             f"""
#             INSERT INTO {TABLE_NAME} (source_url, raw_data, vendor_name)
#             VALUES (%s, %s, %s)
#             ON CONFLICT (source_url) DO UPDATE
#             SET raw_data = EXCLUDED.raw_data,
#                 processed = FALSE,
#                 processed_at = CURRENT_TIMESTAMP,
#                 vendor_name = EXCLUDED.vendor_name
#             """,
#             (source_url, Json(raw_data), "Elastic")
#         )
#         conn.commit()
#         cur.close()
#         conn.close()
#         print(f"📌 Advisory {counter}/{total} inserted")
#     except Exception as e:
#         print(f"⚠️ DB insert failed for {source_url}: {e}")

# # ---------------------------
# # Setup Chrome with driver check
# # ---------------------------
# def create_driver():
#     chrome_options = Options()
#     chrome_options.add_argument("--headless=new")
#     chrome_options.add_argument("--disable-gpu")
#     chrome_options.add_argument("--window-size=1920,1080")
#     chrome_options.add_argument("--no-sandbox")
#     chrome_options.add_argument("--disable-dev-shm-usage")
#     chrome_options.add_experimental_option("excludeSwitches", ["enable-logging"])
#     chrome_options.add_argument("--log-level=3")

#     log.info("🔍 Checking ChromeDriver availability...")
#     path = ChromeDriverManager().install()

#     if os.path.exists(path):
#         log.info(f"✅ ChromeDriver ready at: {path}")
#     else:
#         log.info("⬇️ Downloading new ChromeDriver...")
#         path = ChromeDriverManager().install()
#         log.info(f"📦 Downloaded ChromeDriver at: {path}")

#     service = Service(path, log_path=os.devnull)
#     driver = webdriver.Chrome(service=service, options=chrome_options)
#     return driver

# # ---------------------------
# # Scraping Elastic Announcements
# # ---------------------------
# def collect_elastic_announcements(driver):
#     BASE = "https://discuss.elastic.co/c/announcements/security-announcements/31"
#     driver.get(BASE)

#     seen = set()
#     topics = []

#     last_count = -1
#     max_attempts = 8
#     attempts = 0

#     while True:
#         WebDriverWait(driver, 10).until(
#             EC.presence_of_element_located((By.CSS_SELECTOR, "tr.topic-list-item"))
#         )

#         soup = BeautifulSoup(driver.page_source, "html.parser")
#         rows = soup.select("tr.topic-list-item.category-announcements-security-announcements")
#         for row in rows:
#             a = row.select_one("a.title.raw-link.raw-topic-link")
#             if not a:
#                 continue
#             href = a.get("href")
#             full_url = href if href.startswith("http") else ("https://discuss.elastic.co" + href)
#             if full_url in seen:
#                 continue
#             seen.add(full_url)

#             title = a.get_text(strip=True)
#             time_span = row.select_one("td.activity span.relative-date")
#             time_data = time_span["data-time"] if time_span and time_span.has_attr("data-time") else None

#             topics.append({
#                 "title": title,
#                 "url": full_url,
#                 "activity_time": time_data
#             })

#         driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
#         time.sleep(2)

#         if len(seen) == last_count:
#             attempts += 1
#         else:
#             attempts = 0
#         last_count = len(seen)

#         if attempts >= max_attempts:
#             break

#     print(f"✅ Collected {len(topics)} Elastic announcements")
#     return topics

# # ---------------------------
# # Main
# # ---------------------------
# def main():
#     create_table()
#     driver = create_driver()

#     try:
#         topics = collect_elastic_announcements(driver)
#         total = len(topics)

#         for idx, topic in enumerate(topics, start=1):
#             raw_data = {
#                 "advisory_title": topic["title"],
#                 "advisory_url": topic["url"],
#                 "activity_time": topic["activity_time"]
#             }
#             insert_advisory(topic["url"], raw_data, idx, total)
#             time.sleep(0.5)

#         print(f"✅ Finished. Stored {total}/{total} announcements.")

#     finally:
#         driver.quit()

# if __name__ == "__main__":
#     main()









# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-

# from selenium import webdriver
# from selenium.webdriver.chrome.service import Service
# from selenium.webdriver.chrome.options import Options
# from selenium.webdriver.common.by import By
# from selenium.webdriver.support.ui import WebDriverWait
# from selenium.webdriver.support import expected_conditions as EC
# from webdriver_manager.chrome import ChromeDriverManager
# from bs4 import BeautifulSoup
# import psycopg2
# from psycopg2.extras import Json
# import requests
# import time, os, re, warnings, logging
# from dotenv import load_dotenv

# # ---------------------------
# # Logging
# # ---------------------------
# logging.basicConfig(level=logging.INFO, format="%(message)s")
# log = logging.getLogger("elastic-scraper")
# warnings.filterwarnings("ignore")

# # ---------------------------
# # Suppress WebDriverManager logs
# # ---------------------------
# os.environ["WDM_LOG_LEVEL"] = "0"

# # ---------------------------
# # Load DB config
# # ---------------------------
# load_dotenv()
# DB_CONFIG = {
#     "host": os.getenv("DB_HOST", "localhost"),
#     "dbname": os.getenv("DB_NAME", "Elastic"),
#     "user": os.getenv("DB_USER", "postgres"),
#     "password": os.getenv("DB_PASS", ""),
#     "port": int(os.getenv("DB_PORT", 5432)),
# }
# TABLE_NAME = "staging_table"

# # ---------------------------
# # DB helper functions
# # ---------------------------
# def get_conn():
#     return psycopg2.connect(**DB_CONFIG)

# def create_table():
#     ddl = f"""
#     CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
#         staging_id SERIAL PRIMARY KEY,
#         vendor_name TEXT NOT NULL DEFAULT 'Elastic',
#         source_url TEXT UNIQUE,
#         raw_data JSONB NOT NULL,
#         processed BOOLEAN DEFAULT FALSE,
#         processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
#     );
#     """
#     conn = get_conn()
#     cur = conn.cursor()
#     cur.execute(ddl)
#     conn.commit()
#     cur.close()
#     conn.close()
#     log.info(f"✅ Table '{TABLE_NAME}' ensured.")

# # ---------------------------
# # Fetch advisory details via requests
# # ---------------------------
# def fetch_advisory_details(url):
#     try:
#         resp = requests.get(url, timeout=10)
#         resp.raise_for_status()
#         soup = BeautifulSoup(resp.text, "html.parser")
#         post = soup.select_one("div.post")

#         details = {}
#         current_header = None
#         texts = []
#         cves = set()

#         for elem in post.find_all(["h2", "h3", "p", "li"], recursive=True):
#             if elem.name in ["h2", "h3"]:
#                 if current_header:
#                     details[current_header] = "\n".join(texts).strip()
#                 current_header = elem.get_text(strip=True)
#                 texts = []
#             else:
#                 text = elem.get_text(" ", strip=True)
#                 if text:
#                     texts.append(text)
#                     found = re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
#                     for c in found:
#                         cves.add(c.upper())

#         if current_header:
#             details[current_header] = "\n".join(texts).strip()

#         return {"sections": details, "cve_ids": sorted(list(cves))}
#     except Exception as e:
#         print(f"⚠️ Failed to fetch advisory {url}: {e}")
#         return {"sections": {}, "cve_ids": []}

# # ---------------------------
# # Insert advisory into DB
# # ---------------------------
# def insert_advisory(source_url, raw_data, counter, total):
#     try:
#         # Fetch advisory details
#         raw_data["cve_details"] = fetch_advisory_details(source_url)

#         # Insert into DB
#         conn = get_conn()
#         cur = conn.cursor()
#         cur.execute(
#             f"""
#             INSERT INTO {TABLE_NAME} (source_url, raw_data, vendor_name)
#             VALUES (%s, %s, %s)
#             ON CONFLICT (source_url) DO UPDATE
#             SET raw_data = EXCLUDED.raw_data,
#                 processed = FALSE,
#                 processed_at = CURRENT_TIMESTAMP,
#                 vendor_name = EXCLUDED.vendor_name
#             """,
#             (source_url, Json(raw_data), "Elastic")
#         )
#         conn.commit()
#         cur.close()
#         conn.close()
#         print(f"📌 Advisory {counter}/{total} inserted")
#     except Exception as e:
#         print(f"⚠️ DB insert failed for {source_url}: {e}")

# # ---------------------------
# # Setup Chrome driver
# # ---------------------------
# def create_driver():
#     chrome_options = Options()
#     chrome_options.add_argument("--headless=new")
#     chrome_options.add_argument("--disable-gpu")
#     chrome_options.add_argument("--window-size=1920,1080")
#     chrome_options.add_argument("--no-sandbox")
#     chrome_options.add_argument("--disable-dev-shm-usage")
#     chrome_options.add_experimental_option("excludeSwitches", ["enable-logging"])
#     chrome_options.add_argument("--log-level=3")

#     log.info("🔍 Checking ChromeDriver availability...")
#     path = ChromeDriverManager().install()
#     service = Service(path, log_path=os.devnull)
#     driver = webdriver.Chrome(service=service, options=chrome_options)
#     return driver

# # ---------------------------
# # Collect Elastic security announcement URLs
# # ---------------------------
# def collect_elastic_announcements(driver):
#     BASE = "https://discuss.elastic.co/c/announcements/security-announcements/31"
#     driver.get(BASE)

#     seen = set()
#     topics = []
#     last_count = -1
#     max_attempts = 8
#     attempts = 0

#     while True:
#         WebDriverWait(driver, 10).until(
#             EC.presence_of_element_located((By.CSS_SELECTOR, "tr.topic-list-item"))
#         )

#         soup = BeautifulSoup(driver.page_source, "html.parser")
#         rows = soup.select("tr.topic-list-item.category-announcements-security-announcements")
#         for row in rows:
#             a = row.select_one("a.title.raw-link.raw-topic-link")
#             if not a:
#                 continue
#             href = a.get("href")
#             full_url = href if href.startswith("http") else ("https://discuss.elastic.co" + href)
#             if full_url in seen:
#                 continue
#             seen.add(full_url)

#             title = a.get_text(strip=True)
#             time_span = row.select_one("td.activity span.relative-date")
#             time_data = time_span["data-time"] if time_span and time_span.has_attr("data-time") else None

#             topics.append({
#                 "title": title,
#                 "url": full_url,
#                 "activity_time": time_data
#             })

#         driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
#         time.sleep(2)

#         if len(seen) == last_count:
#             attempts += 1
#         else:
#             attempts = 0
#         last_count = len(seen)
#         if attempts >= max_attempts:
#             break

#     print(f"✅ Collected {len(topics)} Elastic announcements")
#     return topics

# # ---------------------------
# # Main
# # ---------------------------
# def main():
#     create_table()
#     driver = create_driver()

#     try:
#         topics = collect_elastic_announcements(driver)
#         total = len(topics)

#         for idx, topic in enumerate(topics, start=1):
#             raw_data = {
#                 "advisory_title": topic["title"],
#                 "advisory_url": topic["url"],
#                 "activity_time": topic["activity_time"]
#             }
#             insert_advisory(topic["url"], raw_data, idx, total)
#             time.sleep(0.5)

#         print(f"✅ Finished. Stored {total}/{total} announcements.")

#     finally:
#         driver.quit()

# if __name__ == "__main__":
#     main()


# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-

# from selenium import webdriver
# from selenium.webdriver.chrome.service import Service
# from selenium.webdriver.chrome.options import Options
# from selenium.webdriver.common.by import By
# from selenium.webdriver.support.ui import WebDriverWait
# from selenium.webdriver.support import expected_conditions as EC
# from webdriver_manager.chrome import ChromeDriverManager
# from bs4 import BeautifulSoup
# import psycopg2
# from psycopg2.extras import Json
# import requests
# import time, os, re, warnings, logging
# from dotenv import load_dotenv

# # ---------------------------
# # Logging
# # ---------------------------
# logging.basicConfig(level=logging.INFO, format="%(message)s")
# log = logging.getLogger("elastic-scraper")
# warnings.filterwarnings("ignore")

# # ---------------------------
# # Suppress WebDriverManager logs
# # ---------------------------
# os.environ["WDM_LOG_LEVEL"] = "0"

# # ---------------------------
# # Load DB config
# # ---------------------------
# load_dotenv()
# DB_CONFIG = {
#     "host": os.getenv("DB_HOST", "localhost"),
#     "dbname": os.getenv("DB_NAME", "Elastic"),
#     "user": os.getenv("DB_USER", "postgres"),
#     "password": os.getenv("DB_PASS", ""),
#     "port": int(os.getenv("DB_PORT", 5432)),
# }
# TABLE_NAME = "staging_table"

# # ---------------------------
# # DB helper functions
# # ---------------------------
# def get_conn():
#     return psycopg2.connect(**DB_CONFIG)

# def create_table():
#     ddl = f"""
#     CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
#         staging_id SERIAL PRIMARY KEY,
#         vendor_name TEXT NOT NULL DEFAULT 'Elastic',
#         source_url TEXT UNIQUE,
#         raw_data JSONB NOT NULL,
#         processed BOOLEAN DEFAULT FALSE,
#         processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
#     );
#     """
#     conn = get_conn()
#     cur = conn.cursor()
#     cur.execute(ddl)
#     conn.commit()
#     cur.close()
#     conn.close()
#     log.info(f"✅ Table '{TABLE_NAME}' ensured.")

# # ---------------------------
# # Fetch advisory details
# # ---------------------------
# def fetch_advisory_details(url):
#     try:
#         resp = requests.get(url, timeout=10)
#         resp.raise_for_status()
#         soup = BeautifulSoup(resp.text, "html.parser")

#         post = soup.select_one("article .post__body")
#         if not post:
#             return {}

#         cooked = post.select_one("div.cooked")
#         if not cooked:
#             return {}

#         sections = {}
#         cves = set()
#         severity_list = []
#         affected_versions = []
#         affected_configurations = []
#         solutions = []

#         # Use all text nodes in cooked
#         for elem in cooked.find_all(["p", "li", "strong", "span", "div"], recursive=True):
#             text = elem.get_text(" ", strip=True)
#             if not text:
#                 continue

#             # CVE IDs
#             for cve in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE):
#                 cves.add(cve.upper())

#             # Severity
#             for sev in re.findall(r"CVSSv\d\.\d:[\d\.]+\s*\(.*?\)", text, re.IGNORECASE):
#                 severity_list.append(sev)

#             # Affected Versions
#             if "Affected Versions" in text:
#                 next_text = elem.find_next_sibling(text=True)
#                 if next_text:
#                     affected_versions.append(next_text.strip())
#             else:
#                 # try inline versions
#                 found_ver = re.findall(r"(?:up to\s)?\d+\.\d+\.\d+", text, re.IGNORECASE)
#                 if found_ver:
#                     affected_versions.extend(found_ver)

#             # Affected Configurations
#             if "Affected Configurations" in text:
#                 next_text = elem.find_next_sibling(text=True)
#                 if next_text:
#                     affected_configurations.append(next_text.strip())

#             # Solutions
#             if "Solutions" in text or "Mitigations" in text:
#                 next_text = elem.find_next_sibling(text=True)
#                 if next_text:
#                     solutions.append(next_text.strip())

#             # Section-wise
#             if elem.name in ["strong", "h2", "h3"]:
#                 header = text.rstrip(":")
#                 next_texts = []
#                 for sib in elem.find_all_next(["p", "li"], limit=5):
#                     t = sib.get_text(" ", strip=True)
#                     if t:
#                         next_texts.append(t)
#                 if next_texts:
#                     sections[header] = " ".join(next_texts)

#         # Created and Updated Dates
#         created_date = updated_date = None
#         time_elem = soup.select_one("span.relative-date")
#         if time_elem and time_elem.has_attr("data-time"):
#             timestamp = int(time_elem["data-time"]) / 1000
#             created_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
#             updated_date = created_date

#         return {
#             "cve_ids": sorted(list(cves)),
#             "severity": severity_list,
#             "affected_versions": affected_versions,
#             "affected_configurations": affected_configurations,
#             "solutions_and_mitigations": solutions,
#             "sections": sections,
#             "created_date": created_date,
#             "updated_date": updated_date
#         }

#     except Exception as e:
#         print(f"⚠️ Failed to fetch advisory {url}: {e}")
#         return {}

# # ---------------------------
# # Insert advisory into DB
# # ---------------------------
# def insert_advisory(source_url, raw_data, counter, total):
#     try:
#         raw_data["cve_details"] = fetch_advisory_details(source_url)

#         conn = get_conn()
#         cur = conn.cursor()
#         cur.execute(
#             f"""
#             INSERT INTO {TABLE_NAME} (source_url, raw_data, vendor_name)
#             VALUES (%s, %s, %s)
#             ON CONFLICT (source_url) DO UPDATE
#             SET raw_data = EXCLUDED.raw_data,
#                 processed = FALSE,
#                 processed_at = CURRENT_TIMESTAMP,
#                 vendor_name = EXCLUDED.vendor_name
#             """,
#             (source_url, Json(raw_data), "Elastic")
#         )
#         conn.commit()
#         cur.close()
#         conn.close()
#         print(f"📌 Advisory {counter}/{total} inserted")
#     except Exception as e:
#         print(f"⚠️ DB insert failed for {source_url}: {e}")

# # ---------------------------
# # Setup Chrome driver
# # ---------------------------
# def create_driver():
#     chrome_options = Options()
#     chrome_options.add_argument("--headless=new")
#     chrome_options.add_argument("--disable-gpu")
#     chrome_options.add_argument("--window-size=1920,1080")
#     chrome_options.add_argument("--no-sandbox")
#     chrome_options.add_argument("--disable-dev-shm-usage")
#     chrome_options.add_experimental_option("excludeSwitches", ["enable-logging"])
#     chrome_options.add_argument("--log-level=3")

#     log.info("🔍 Checking ChromeDriver availability...")
#     path = ChromeDriverManager().install()
#     service = Service(path, log_path=os.devnull)
#     driver = webdriver.Chrome(service=service, options=chrome_options)
#     return driver

# # ---------------------------
# # Collect Elastic security announcement URLs
# # ---------------------------
# def collect_elastic_announcements(driver):
#     BASE = "https://discuss.elastic.co/c/announcements/security-announcements/31"
#     driver.get(BASE)

#     seen = set()
#     topics = []
#     last_count = -1
#     max_attempts = 8
#     attempts = 0

#     while True:
#         WebDriverWait(driver, 10).until(
#             EC.presence_of_element_located((By.CSS_SELECTOR, "tr.topic-list-item"))
#         )

#         soup = BeautifulSoup(driver.page_source, "html.parser")
#         rows = soup.select("tr.topic-list-item.category-announcements-security-announcements")
#         for row in rows:
#             a = row.select_one("a.title.raw-link.raw-topic-link")
#             if not a:
#                 continue
#             href = a.get("href")
#             full_url = href if href.startswith("http") else ("https://discuss.elastic.co" + href)
#             if full_url in seen:
#                 continue
#             seen.add(full_url)

#             title = a.get_text(strip=True)
#             time_span = row.select_one("td.activity span.relative-date")
#             time_data = time_span["data-time"] if time_span and time_span.has_attr("data-time") else None

#             topics.append({
#                 "title": title,
#                 "url": full_url,
#                 "activity_time": time_data
#             })

#         driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
#         time.sleep(2)

#         if len(seen) == last_count:
#             attempts += 1
#         else:
#             attempts = 0
#         last_count = len(seen)
#         if attempts >= max_attempts:
#             break

#     print(f"✅ Collected {len(topics)} Elastic announcements")
#     return topics

# # ---------------------------
# # Main
# # ---------------------------
# def main():
#     create_table()
#     driver = create_driver()

#     try:
#         topics = collect_elastic_announcements(driver)
#         total = len(topics)

#         for idx, topic in enumerate(topics, start=1):
#             raw_data = {
#                 "advisory_title": topic["title"],
#                 "advisory_url": topic["url"],
#                 "activity_time": topic["activity_time"]
#             }
#             insert_advisory(topic["url"], raw_data, idx, total)
#             time.sleep(0.5)

#         print(f"✅ Finished. Stored {total}/{total} announcements.")

#     finally:
#         driver.quit()

# if __name__ == "__main__":
#     main()





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
        processed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );
    """
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(ddl)
    conn.commit()
    cur.close()
    conn.close()
    log.info(f"✅ Table '{TABLE_NAME}' ensured.")

# ---------------------------
# Fetch advisory details with Selenium
# ---------------------------
def fetch_advisory_details(driver, url):
    try:
        driver.get(url)
        # Wait until the first post's cooked div loads
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "div.cooked"))
        )
        soup = BeautifulSoup(driver.page_source, "html.parser")
        cooked = soup.select_one("div.cooked")
        if not cooked:
            return {}

        cve_details = {
            "cve_ids": [],
            "severity": [],
            "affected_versions": [],
            "affected_configurations": [],
            "solutions_and_mitigations": [],
            "sections": {},
            "created_date": None,
            "updated_date": None
        }

        current_section = "Description"
        buffer = []

        for elem in cooked.find_all(["p", "li", "strong", "h2", "h3"], recursive=True):
            text = elem.get_text(" ", strip=True)
            if not text:
                continue

            # Heading detection
            if elem.name in ["strong", "h2", "h3"] and ":" in text:
                if buffer:
                    cve_details["sections"][current_section] = " ".join(buffer).strip()
                current_section = text.rstrip(":")
                buffer = []
                continue

            buffer.append(text)

            # CVE IDs
            for cve in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE):
                cve = cve.upper()
                if cve not in cve_details["cve_ids"]:
                    cve_details["cve_ids"].append(cve)

            # Severity
            for sev in re.findall(r"CVSSv\d\.\d:.*?\(.*?\)", text, re.IGNORECASE):
                if sev not in cve_details["severity"]:
                    cve_details["severity"].append(sev)

            # Affected Versions
            if "Affected Versions" in current_section or re.search(r"\d+\.\d+\.\d+", text):
                for ver in re.findall(r"\d+\.\d+\.\d+(?: up to .*?)?", text):
                    if ver not in cve_details["affected_versions"]:
                        cve_details["affected_versions"].append(ver)

            # Affected Configurations
            if "Affected Configurations" in current_section:
                if text not in cve_details["affected_configurations"]:
                    cve_details["affected_configurations"].append(text)

            # Solutions / Mitigations
            if "Solutions" in current_section or "Mitigations" in current_section:
                if text not in cve_details["solutions_and_mitigations"]:
                    cve_details["solutions_and_mitigations"].append(text)

        if buffer:
            cve_details["sections"][current_section] = " ".join(buffer).strip()

        # Created / Updated date
        time_elem = soup.select_one("span.relative-date")
        if time_elem and time_elem.has_attr("data-time"):
            timestamp = int(time_elem["data-time"]) / 1000
            formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
            cve_details["created_date"] = formatted_time
            cve_details["updated_date"] = formatted_time

        return cve_details

    except Exception as e:
        log.warning(f"⚠️ Failed to fetch advisory {url}: {e}")
        return {}

# ---------------------------
# Insert advisory into DB
# ---------------------------
def insert_advisory(source_url, raw_data, driver):
    raw_data["cve_details"] = fetch_advisory_details(driver, source_url)
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
        log.info(f"📌 Advisory stored: {source_url}")
    except Exception as e:
        log.warning(f"⚠️ DB insert failed for {source_url}: {e}")

# ---------------------------
# Setup Chrome driver
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

    log.info("🔍 Checking ChromeDriver availability...")
    path = ChromeDriverManager().install()
    service = Service(path, log_path=os.devnull)
    driver = webdriver.Chrome(service=service, options=chrome_options)
    return driver

# ---------------------------
# Collect Elastic security announcement URLs
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

        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        time.sleep(2)

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
            insert_advisory(topic["url"], raw_data, driver)
            time.sleep(0.5)

        print(f"✅ Finished. Stored {total}/{total} announcements.")

    finally:
        driver.quit()

if __name__ == "__main__":
    main()
