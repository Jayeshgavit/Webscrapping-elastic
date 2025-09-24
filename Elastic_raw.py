
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
# os.environ["WDM_LOG_LEVEL"] = "0"  # Suppress WebDriverManager logs

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
#         processed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
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
# # Check if advisory exists
# # ---------------------------
# def advisory_exists(source_url):
#     try:
#         conn = get_conn()
#         cur = conn.cursor()
#         cur.execute(f"SELECT 1 FROM {TABLE_NAME} WHERE source_url = %s", (source_url,))
#         exists = cur.fetchone() is not None
#         cur.close()
#         conn.close()
#         return exists
#     except Exception as e:
#         log.warning(f"⚠️ DB check failed for {source_url}: {e}")
#         return False

# # ---------------------------
# # Helper: Parse severity pattern
# # ---------------------------
# def parse_severity(text):
#     pattern = r"Severity:\s*CVSSv\d\.\d:\s*([\d\.]+)\s*\(?(\w+)?\)?\s*-?\s*(CVSS:.+)?"
#     match = re.search(pattern, text)
#     if match:
#         score, level, vector = match.groups()
#         return {
#             "cvss_score": float(score),
#             "severity_level": level if level else "",
#             "vector": vector if vector else ""
#         }
#     return {}

# # ---------------------------
# # Fetch advisory details
# # ---------------------------
# def fetch_advisory_details(driver, url):
#     try:
#         driver.get(url)
#         WebDriverWait(driver, 10).until(
#             EC.presence_of_element_located((By.CSS_SELECTOR, "div.cooked"))
#         )
#         soup = BeautifulSoup(driver.page_source, "html.parser")
#         cooked = soup.select_one("div.cooked")
#         if not cooked:
#             return {}

#         cve_details = {
#             "cve_ids": [],
#             "severity": [],
#             "severity_data": [],
#             "affected_versions": [],
#             "affected_products": [],
#             "affected_configurations": [],
#             "solutions_and_mitigations": [],
#             "cannot_upgrade": [],
#             "description": "",
#             "created_date": None,
#             "updated_date": None
#         }

#         blocks = cooked.find_all(["p", "li", "div"], recursive=True)
#         buffer_desc = []

#         capture_affected = False
#         capture_config = False
#         capture_solutions = False

#         for block in blocks:
#             text = block.get_text(" ", strip=True)
#             if not text:
#                 continue

#             # CVE IDs
#             for cve in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE):
#                 cve = cve.upper()
#                 if cve not in cve_details["cve_ids"]:
#                     cve_details["cve_ids"].append(cve)

#             # Severity
#             if "Severity:" in text:
#                 if text not in cve_details["severity"]:
#                     cve_details["severity"].append(text)
#                 sev = parse_severity(text)
#                 if sev and sev not in cve_details["severity_data"]:
#                     cve_details["severity_data"].append(sev)

#             # Section starts
#             if re.search(r"Affected Versions:", text, re.IGNORECASE):
#                 capture_affected = True
#                 affected_text = re.sub(r"Affected Versions:\s*", "", text, flags=re.IGNORECASE)
#                 cve_details["affected_products"].extend([v.strip() for v in re.split(r",|\n", affected_text) if v.strip()])
#                 continue

#             if re.search(r"Affected Configurations:", text, re.IGNORECASE):
#                 capture_config = True
#                 continue

#             if re.search(r"Solutions and Mitigations:", text, re.IGNORECASE):
#                 capture_solutions = True
#                 continue

#             if "For Users that Cannot Upgrade" in text:
#                 cve_details["cannot_upgrade"].append(text)
#                 capture_solutions = capture_config = capture_affected = False
#                 continue

#             # Capture multi-line sections
#             if capture_affected:
#                 cve_details["affected_products"].extend([v.strip() for v in re.split(r",|\n", text) if v.strip()])
#                 capture_affected = False
#                 continue

#             if capture_config:
#                 cve_details["affected_configurations"].append(text)
#                 capture_config = False
#                 continue

#             if capture_solutions:
#                 cve_details["solutions_and_mitigations"].append(text)
#                 capture_solutions = False
#                 continue

#             # Description buffer
#             if not re.search(r"CVE-\d{4}-\d{4,7}|Severity:|Affected Versions:|Affected Configurations:|Solutions and Mitigations:|For Users that Cannot Upgrade", text, re.IGNORECASE):
#                 buffer_desc.append(text)

#         cve_details["description"] = " ".join(buffer_desc).strip()

#         # Created / Updated date
#         time_elem = soup.select_one("span.relative-date")
#         if time_elem and time_elem.has_attr("data-time"):
#             timestamp = int(time_elem["data-time"]) / 1000
#             formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
#             cve_details["created_date"] = formatted_time
#             cve_details["updated_date"] = formatted_time

#         return cve_details

#     except Exception as e:
#         log.warning(f"⚠️ Failed to fetch advisory {url}: {e}")
#         return {}

# # ---------------------------
# # Insert advisory into DB
# # ---------------------------
# def insert_advisory(source_url, raw_data, driver):
#     if advisory_exists(source_url):
#         log.info(f"⏭ Skipping already existing advisory: {source_url}")
#         return

#     raw_data["cve_details"] = fetch_advisory_details(driver, source_url)
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
#         log.info(f"Inserted: {source_url}")
#     except Exception as e:
#         log.warning(f"⚠️ DB insert failed for {source_url}: {e}")

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

#     log.info("Collecting advisory URLs...")
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
#         time.sleep(1)

#         if len(seen) == last_count:
#             attempts += 1
#         else:
#             attempts = 0
#         last_count = len(seen)
#         if attempts >= max_attempts:
#             break

#     log.info(f"✅ Collected {len(topics)} Elastic announcements")
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

#         log.info("Fetching advisory details and inserting into DB...")
#         for topic in topics:
#             raw_data = {
#                 "advisory_title": topic["title"],
#                 "advisory_url": topic["url"],
#                 "activity_time": topic["activity_time"]
#             }
#             insert_advisory(topic["url"], raw_data, driver)
#             time.sleep(0.5)

#         log.info(f"✅ Finished. Stored {total}/{total} announcements.")
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
# import time, os, re, warnings, logging
# from dotenv import load_dotenv

# # ---------------------------
# # Logging
# # ---------------------------
# logging.basicConfig(level=logging.INFO, format="%(message)s")
# log = logging.getLogger("elastic-scraper")
# warnings.filterwarnings("ignore")
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
#         processed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
#     );
#     """
#     conn = get_conn()
#     cur = conn.cursor()
#     cur.execute(ddl)
#     conn.commit()
#     cur.close()
#     conn.close()
#     log.info(f"✅ Table '{TABLE_NAME}' ensured.")

# def advisory_exists(source_url):
#     try:
#         conn = get_conn()
#         cur = conn.cursor()
#         cur.execute(f"SELECT 1 FROM {TABLE_NAME} WHERE source_url = %s", (source_url,))
#         exists = cur.fetchone() is not None
#         cur.close()
#         conn.close()
#         return exists
#     except Exception as e:
#         log.warning(f"⚠️ DB check failed for {source_url}: {e}")
#         return False

# # ---------------------------
# # Helper: Parse severity pattern
# # ---------------------------
# def parse_severity(text):
#     pattern = r"Severity:\s*CVSSv\d\.\d:\s*([\d\.]+)\s*\(?(\w+)?\)?\s*-?\s*(CVSS:.+)?"
#     match = re.search(pattern, text)
#     if match:
#         score, level, vector = match.groups()
#         return {
#             "cvss_score": float(score),
#             "severity_level": level if level else "",
#             "vector": vector if vector else ""
#         }
#     return {}

# # ---------------------------
# # Fetch advisory details
# # ---------------------------
# def fetch_advisory_details(driver, url):
#     try:
#         driver.get(url)
#         WebDriverWait(driver, 10).until(
#             EC.presence_of_element_located((By.CSS_SELECTOR, "div.cooked"))
#         )
#         soup = BeautifulSoup(driver.page_source, "html.parser")
#         cooked = soup.select_one("div.cooked")
#         if not cooked:
#             return {}

#         cve_details = {
#             "cve_ids": [],
#             "severity": [],
#             "severity_data": [],
#             "affected_versions": [],
#             "affected_configurations": [],
#             "solutions_and_mitigations": [],
#             "cannot_upgrade": [],
#             "description": "",
#             "created_date": None,
#             "updated_date": None
#         }

#         blocks = cooked.find_all(["p", "li", "div"], recursive=True)
#         buffer_desc = []

#         # State flags
#         capture_section = None

#         for block in blocks:
#             text = block.get_text(" ", strip=True)
#             if not text:
#                 continue

#             # ---------------------------
#             # CVE IDs
#             # ---------------------------
#             for cve in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE):
#                 cve = cve.upper()
#                 if cve not in cve_details["cve_ids"]:
#                     cve_details["cve_ids"].append(cve)

#             # ---------------------------
#             # Severity
#             # ---------------------------
#             if "Severity:" in text:
#                 if text not in cve_details["severity"]:
#                     cve_details["severity"].append(text)
#                 sev = parse_severity(text)
#                 if sev and sev not in cve_details["severity_data"]:
#                     cve_details["severity_data"].append(sev)
#                 capture_section = None
#                 continue

#             # ---------------------------
#             # Detect section headers
#             # ---------------------------
#             if re.search(r"Affected Versions:", text, re.IGNORECASE):
#                 capture_section = "affected_versions"
#                 affected_text = re.sub(r"Affected Versions:\s*", "", text, flags=re.IGNORECASE)
#                 cve_details["affected_versions"].extend(
#                     [v.strip() for v in re.split(r",|\n", affected_text) if v.strip()]
#                 )
#                 continue

#             if re.search(r"Affected Configurations:", text, re.IGNORECASE):
#                 capture_section = "affected_configurations"
#                 continue

#             if re.search(r"Solutions and Mitigations:", text, re.IGNORECASE):
#                 capture_section = "solutions_and_mitigations"
#                 continue

#             if "For Users that Cannot Upgrade" in text:
#                 cve_details["cannot_upgrade"].append(text)
#                 capture_section = None
#                 continue

#             # ---------------------------
#             # Capture content until next section
#             # ---------------------------
#             if capture_section == "affected_versions":
#                 cve_details["affected_versions"].extend(
#                     [v.strip() for v in re.split(r",|\n", text) if v.strip()]
#                 )
#                 continue

#             if capture_section == "affected_configurations":
#                 cve_details["affected_configurations"].append(text)
#                 continue

#             if capture_section == "solutions_and_mitigations":
#                 cve_details["solutions_and_mitigations"].append(text)
#                 continue

#             # ---------------------------
#             # Any other text => description
#             # ---------------------------
#             buffer_desc.append(text)

#         cve_details["description"] = " ".join(buffer_desc).strip()

#         # Created / Updated date
#         time_elem = soup.select_one("span.relative-date")
#         if time_elem and time_elem.has_attr("data-time"):
#             timestamp = int(time_elem["data-time"]) / 1000
#             formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
#             cve_details["created_date"] = formatted_time
#             cve_details["updated_date"] = formatted_time

#         return cve_details

#     except Exception as e:
#         log.warning(f"⚠️ Failed to fetch advisory {url}: {e}")
#         return {}

# # ---------------------------
# # Insert advisory into DB
# # ---------------------------
# def insert_advisory(source_url, raw_data, driver):
#     if advisory_exists(source_url):
#         log.info(f"⏭ Skipping already existing advisory: {source_url}")
#         return

#     raw_data["cve_details"] = fetch_advisory_details(driver, source_url)
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
#         log.info(f"Inserted: {source_url}")
#     except Exception as e:
#         log.warning(f"⚠️ DB insert failed for {source_url}: {e}")

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

#     log.info("Collecting advisory URLs...")
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
#         time.sleep(1)

#         if len(seen) == last_count:
#             attempts += 1
#         else:
#             attempts = 0
#         last_count = len(seen)
#         if attempts >= max_attempts:
#             break

#     log.info(f"✅ Collected {len(topics)} Elastic announcements")
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

#         log.info("Fetching advisory details and inserting into DB...")
#         for topic in topics:
#             raw_data = {
#                 "advisory_title": topic["title"],
#                 "advisory_url": topic["url"],
#                 "activity_time": topic["activity_time"]
#             }
#             insert_advisory(topic["url"], raw_data, driver)
#             time.sleep(0.5)

#         log.info(f"✅ Finished. Stored {total}/{total} announcements.")
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

def advisory_exists(source_url):
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(f"SELECT 1 FROM {TABLE_NAME} WHERE source_url = %s", (source_url,))
        exists = cur.fetchone() is not None
        cur.close()
        conn.close()
        return exists
    except Exception as e:
        log.warning(f"⚠️ DB check failed for {source_url}: {e}")
        return False

# ---------------------------
# Helper: Parse severity pattern
# ---------------------------
def parse_severity(text):
    # Full line severity capture
    pattern = r"Severity:\s*(CVSSv\d\.\d:.*)"
    match = re.search(pattern, text)
    if match:
        full_line = match.group(1).strip()

        # Extract structured parts if possible
        struct_pattern = r"CVSSv\d\.\d:\s*([\d\.]+)\s*\(?(\w+)?\)?\s*-?\s*(CVSS:.+)?"
        m2 = re.search(struct_pattern, full_line)
        if m2:
            score, level, vector = m2.groups()
            return {
                "cvss_score": float(score),
                "severity_level": level if level else "",
                "vector": vector if vector else ""
            }
    return {}

# ---------------------------
# Fetch advisory details
# ---------------------------
def fetch_advisory_details(driver, url):
    try:
        driver.get(url)
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "div.cooked"))
        )
        soup = BeautifulSoup(driver.page_source, "html.parser")
        cooked = soup.select_one("div.cooked")
        if not cooked:
            return []

        # Split into sections by <hr> for multiple CVEs
        sections = [s for s in cooked.decode_contents().split("<hr")]

        all_cves = []

        for section_html in sections:
            section_soup = BeautifulSoup(section_html, "html.parser")
            blocks = section_soup.find_all(["p", "li", "div"], recursive=True)

            cve_details = {
                "cve_ids": [],
                "severity": [],
                "severity_data": [],
                "affected_versions": [],
                "affected_configurations": [],
                "solutions_and_mitigations": [],
                "cannot_upgrade": [],
                "description": "",
                "created_date": None,
                "updated_date": None
            }

            buffer_desc = []
            capture_section = None

            for block in blocks:
                text = block.get_text(" ", strip=True)
                if not text:
                    continue

                # CVE IDs
                for cve in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE):
                    cve = cve.upper()
                    if cve not in cve_details["cve_ids"]:
                        cve_details["cve_ids"].append(cve)

                # Severity
                if "Severity:" in text:
                    if text not in cve_details["severity"]:
                        cve_details["severity"].append(text)
                    sev = parse_severity(text)
                    if sev and sev not in cve_details["severity_data"]:
                        cve_details["severity_data"].append(sev)
                    capture_section = None
                    continue

                # Section headers
                if re.search(r"Affected Versions:", text, re.IGNORECASE):
                    capture_section = "affected_versions"
                    affected_text = re.sub(r"Affected Versions:\s*", "", text, flags=re.IGNORECASE)
                    cve_details["affected_versions"].extend(
                        [v.strip() for v in re.split(r",|\n", affected_text) if v.strip()]
                    )
                    continue

                if re.search(r"Affected Configurations:", text, re.IGNORECASE):
                    capture_section = "affected_configurations"
                    continue

                if re.search(r"Solutions and Mitigations:", text, re.IGNORECASE):
                    capture_section = "solutions_and_mitigations"
                    continue

                if "For Users that Cannot Upgrade" in text:
                    cve_details["cannot_upgrade"].append(text)
                    capture_section = None
                    continue

                # Capture section text
                if capture_section == "affected_versions":
                    cve_details["affected_versions"].extend(
                        [v.strip() for v in re.split(r",|\n", text) if v.strip()]
                    )
                    continue

                if capture_section == "affected_configurations":
                    cve_details["affected_configurations"].append(text)
                    continue

                if capture_section == "solutions_and_mitigations":
                    cve_details["solutions_and_mitigations"].append(text)
                    continue

                # Otherwise → description (only before structured headers)
                if capture_section is None:
                    buffer_desc.append(text)

            cve_details["description"] = " ".join(buffer_desc).strip()

            # Created / Updated date
            time_elem = soup.select_one("span.relative-date")
            if time_elem and time_elem.has_attr("data-time"):
                timestamp = int(time_elem["data-time"]) / 1000
                formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
                cve_details["created_date"] = formatted_time
                cve_details["updated_date"] = formatted_time

            # Only append if something meaningful is captured
            if cve_details["cve_ids"] or cve_details["severity"]:
                all_cves.append(cve_details)

        return all_cves

    except Exception as e:
        log.warning(f"⚠️ Failed to fetch advisory {url}: {e}")
        return []

# ---------------------------
# Insert advisory into DB
# ---------------------------
def insert_advisory(source_url, raw_data, driver):
    if advisory_exists(source_url):
        log.info(f"⏭ Skipping already existing advisory: {source_url}")
        return

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
        log.info(f"Inserted: {source_url}")
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

    log.info("Collecting advisory URLs...")
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
        time.sleep(1)

        if len(seen) == last_count:
            attempts += 1
        else:
            attempts = 0
        last_count = len(seen)
        if attempts >= max_attempts:
            break

    log.info(f"✅ Collected {len(topics)} Elastic announcements")
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

        log.info("Fetching advisory details and inserting into DB...")
        for topic in topics:
            raw_data = {
                "advisory_title": topic["title"],
                "advisory_url": topic["url"],
                "activity_time": topic["activity_time"]
            }
            insert_advisory(topic["url"], raw_data, driver)
            time.sleep(0.5)

        log.info(f"✅ Finished. Stored {total}/{total} announcements.")
    finally:
        driver.quit()

if __name__ == "__main__":
    main()
