
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
#     # Full line severity capture
#     pattern = r"Severity:\s*(CVSSv\d\.\d:.*)"
#     match = re.search(pattern, text)
#     if match:
#         full_line = match.group(1).strip()

#         # Extract structured parts if possible
#         struct_pattern = r"CVSSv\d\.\d:\s*([\d\.]+)\s*\(?(\w+)?\)?\s*-?\s*(CVSS:.+)?"
#         m2 = re.search(struct_pattern, full_line)
#         if m2:
#             score, level, vector = m2.groups()
#             return {
#                 "cvss_score": float(score),
#                 "severity_level": level if level else "",
#                 "vector": vector if vector else ""
#             }
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
#             return []

#         # Split into sections by <hr> for multiple CVEs
#         sections = [s for s in cooked.decode_contents().split("<hr")]

#         all_cves = []

#         for section_html in sections:
#             section_soup = BeautifulSoup(section_html, "html.parser")
#             blocks = section_soup.find_all(["p", "li", "div"], recursive=True)

#             cve_details = {
#                 "cve_ids": [],
#                 "severity": [],
#                 "severity_data": [],
#                 "affected_versions": [],
#                 "affected_configurations": [],
#                 "solutions_and_mitigations": [],
#                 "cannot_upgrade": [],
#                 "description": "",
#                 "created_date": None,
#                 "updated_date": None
#             }

#             buffer_desc = []
#             capture_section = None

#             for block in blocks:
#                 text = block.get_text(" ", strip=True)
#                 if not text:
#                     continue

#                 # CVE IDs
#                 for cve in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE):
#                     cve = cve.upper()
#                     if cve not in cve_details["cve_ids"]:
#                         cve_details["cve_ids"].append(cve)

#                 # Severity
#                 if "Severity:" in text:
#                     if text not in cve_details["severity"]:
#                         cve_details["severity"].append(text)
#                     sev = parse_severity(text)
#                     if sev and sev not in cve_details["severity_data"]:
#                         cve_details["severity_data"].append(sev)
#                     capture_section = None
#                     continue

#                 # Section headers
#                 if re.search(r"Affected Versions:", text, re.IGNORECASE):
#                     capture_section = "affected_versions"
#                     affected_text = re.sub(r"Affected Versions:\s*", "", text, flags=re.IGNORECASE)
#                     cve_details["affected_versions"].extend(
#                         [v.strip() for v in re.split(r",|\n", affected_text) if v.strip()]
#                     )
#                     continue

#                 if re.search(r"Affected Configurations:", text, re.IGNORECASE):
#                     capture_section = "affected_configurations"
#                     continue

#                 if re.search(r"Solutions and Mitigations:", text, re.IGNORECASE):
#                     capture_section = "solutions_and_mitigations"
#                     continue

#                 if "For Users that Cannot Upgrade" in text:
#                     cve_details["cannot_upgrade"].append(text)
#                     capture_section = None
#                     continue

#                 # Capture section text
#                 if capture_section == "affected_versions":
#                     cve_details["affected_versions"].extend(
#                         [v.strip() for v in re.split(r",|\n", text) if v.strip()]
#                     )
#                     continue

#                 if capture_section == "affected_configurations":
#                     cve_details["affected_configurations"].append(text)
#                     continue

#                 if capture_section == "solutions_and_mitigations":
#                     cve_details["solutions_and_mitigations"].append(text)
#                     continue

#                 # Otherwise → description (only before structured headers)
#                 if capture_section is None:
#                     buffer_desc.append(text)

#             cve_details["description"] = " ".join(buffer_desc).strip()

#             # Created / Updated date
#             time_elem = soup.select_one("span.relative-date")
#             if time_elem and time_elem.has_attr("data-time"):
#                 timestamp = int(time_elem["data-time"]) / 1000
#                 formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
#                 cve_details["created_date"] = formatted_time
#                 cve_details["updated_date"] = formatted_time

#             # Only append if something meaningful is captured
#             if cve_details["cve_ids"] or cve_details["severity"]:
#                 all_cves.append(cve_details)

#         return all_cves

#     except Exception as e:
#         log.warning(f"⚠️ Failed to fetch advisory {url}: {e}")
#         return []

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
#     pattern = r"Severity:\s*(CVSSv\d\.\d:.*)"
#     match = re.search(pattern, text)
#     if match:
#         full_line = match.group(1).strip()
#         struct_pattern = r"CVSSv\d\.\d:\s*([\d\.]+)\s*\(?(\w+)?\)?\s*-?\s*(CVSS:.+)?"
#         m2 = re.search(struct_pattern, full_line)
#         if m2:
#             score, level, vector = m2.groups()
#             return {
#                 "cvss_score": float(score),
#                 "severity_level": level if level else "",
#                 "vector": vector if vector else ""
#             }
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
#             return []

#         sections = [s for s in cooked.decode_contents().split("<hr")]
#         all_cves = []

#         for section_html in sections:
#             section_soup = BeautifulSoup(section_html, "html.parser")
#             blocks = section_soup.find_all(["p", "li", "div"], recursive=True)

#             cve_details = {
#                 "cve_ids": [],
#                 "severity": [],
#                 "severity_data": [],
#                 "affected_versions": [],
#                 "affected_configurations": [],
#                 "solutions_and_mitigations": [],
#                 "cannot_upgrade": [],
#                 "description": "",
#                 "created_date": None,
#                 "updated_date": None
#             }

#             buffer_desc = []
#             capture_section = None
#             skip_first_p = True  # skip first <p>

#             for block in blocks:
#                 text = block.get_text(" ", strip=True)
#                 if not text:
#                     continue

#                 # CVE IDs
#                 for cve in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE):
#                     cve = cve.upper()
#                     if cve not in cve_details["cve_ids"]:
#                         cve_details["cve_ids"].append(cve)

#                 # Severity
#                 if "Severity:" in text:
#                     if text not in cve_details["severity"]:
#                         cve_details["severity"].append(text)
#                     sev = parse_severity(text)
#                     if sev and sev not in cve_details["severity_data"]:
#                         cve_details["severity_data"].append(sev)
#                     capture_section = None
#                     continue

#                 # Section headers
#                 if re.search(r"Affected Versions:", text, re.IGNORECASE):
#                     capture_section = "affected_versions"
#                     affected_text = re.sub(r"Affected Versions:\s*", "", text, flags=re.IGNORECASE)
#                     cve_details["affected_versions"].extend(
#                         [v.strip() for v in re.split(r",|\n", affected_text) if v.strip()]
#                     )
#                     continue

#                 if re.search(r"Affected Configurations:", text, re.IGNORECASE):
#                     capture_section = "affected_configurations"
#                     continue

#                 if re.search(r"Solutions and Mitigations:", text, re.IGNORECASE):
#                     capture_section = "solutions_and_mitigations"
#                     continue

#                 if "For Users that Cannot Upgrade" in text:
#                     cve_details["cannot_upgrade"].append(text)
#                     capture_section = None
#                     continue

#                 # Capture text by section
#                 if capture_section == "affected_versions":
#                     cve_details["affected_versions"].extend(
#                         [v.strip() for v in re.split(r",|\n", text) if v.strip()]
#                     )
#                     continue
#                 if capture_section == "affected_configurations":
#                     cve_details["affected_configurations"].append(text)
#                     continue
#                 if capture_section == "solutions_and_mitigations":
#                     cve_details["solutions_and_mitigations"].append(text)
#                     continue

#                 # Description: skip first p, stop if <strong> inside p
#                 if capture_section is None:
#                     if skip_first_p:
#                         skip_first_p = False
#                         continue
#                     if block.find("strong"):
#                         continue
#                     buffer_desc.append(text)

#             cve_details["description"] = " ".join(buffer_desc).strip()

#             # Created / Updated date
#             time_elem = soup.select_one("span.relative-date")
#             if time_elem and time_elem.has_attr("data-time"):
#                 timestamp = int(time_elem["data-time"]) / 1000
#                 formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
#                 cve_details["created_date"] = formatted_time
#                 cve_details["updated_date"] = formatted_time

#             if cve_details["cve_ids"] or cve_details["severity"]:
#                 all_cves.append(cve_details)

#         return all_cves

#     except Exception as e:
#         log.warning(f"⚠️ Failed to fetch advisory {url}: {e}")
#         return []

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
# # Collect Elastic announcements
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

#             # Extract activity dates from title attribute
#             td = row.select_one("td.activity")
#             created_date, latest_date = None, None
#             if td and td.has_attr("title"):
#                 title_attr = td["title"]
#                 m1 = re.search(r"Created:\s*([^\n]+)", title_attr)
#                 m2 = re.search(r"Latest:\s*([^\n]+)", title_attr)
#                 if m1:
#                     created_date = m1.group(1).strip()
#                 if m2:
#                     latest_date = m2.group(1).strip()

#             topics.append({
#                 "title": title,
#                 "url": full_url,
#                 "created_date": created_date,
#                 "latest_date": latest_date
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
#                 "created_date": topic["created_date"],
#                 "latest_date": topic["latest_date"]
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
#     pattern = r"Severity:\s*(CVSSv\d\.\d:.*)"
#     match = re.search(pattern, text)
#     if match:
#         full_line = match.group(1).strip()
#         struct_pattern = r"CVSSv\d\.\d:\s*([\d\.]+)\s*\(?(\w+)?\)?\s*-?\s*(CVSS:.+)?"
#         m2 = re.search(struct_pattern, full_line)
#         if m2:
#             score, level, vector = m2.groups()
#             return {
#                 "cvss_score": float(score),
#                 "severity_level": level if level else "",
#                 "vector": vector if vector else ""
#             }
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
#             return []

#         sections = [s for s in cooked.decode_contents().split("<hr")]
#         all_cves = []

#         for section_html in sections:
#             section_soup = BeautifulSoup(section_html, "html.parser")
#             blocks = section_soup.find_all(["p", "li", "div"], recursive=True)

#             cve_details = {
#                 "cve_ids": [],
#                 "severity": [],
#                 "severity_data": [],
#                 "affected_versions": [],
#                 "affected_configurations": [],
#                 "solutions_and_mitigations": [],
#                 "cannot_upgrade": [],
#                 "description": "",
#                 "created_date": None,
#                 "updated_date": None
#             }

#             buffer_desc = []
#             capture_section = None
#             skip_first_p = True  # skip first <p>

#             for block in blocks:
#                 text = block.get_text(" ", strip=True)
#                 if not text:
#                     continue

#                 # CVE IDs
#                 for cve in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE):
#                     cve = cve.upper()
#                     if cve not in cve_details["cve_ids"]:
#                         cve_details["cve_ids"].append(cve)

#                 # Severity
#                 if "Severity:" in text:
#                     if text not in cve_details["severity"]:
#                         cve_details["severity"].append(text)
#                     sev = parse_severity(text)
#                     if sev and sev not in cve_details["severity_data"]:
#                         cve_details["severity_data"].append(sev)
#                     capture_section = None
#                     continue

#                 # Section headers
#                 if re.search(r"Affected Versions:", text, re.IGNORECASE):
#                     capture_section = "affected_versions"
#                     affected_text = re.sub(r"Affected Versions:\s*", "", text, flags=re.IGNORECASE)
#                     cve_details["affected_versions"].extend(
#                         [v.strip() for v in re.split(r",|\n", affected_text) if v.strip()]
#                     )
#                     continue

#                 if re.search(r"Affected Configurations:", text, re.IGNORECASE):
#                     capture_section = "affected_configurations"
#                     continue

#                 if re.search(r"Solutions and Mitigations:", text, re.IGNORECASE):
#                     capture_section = "solutions_and_mitigations"
#                     continue

#                 if "For Users that Cannot Upgrade" in text:
#                     cve_details["cannot_upgrade"].append(text)
#                     capture_section = None
#                     continue

#                 # Capture text by section
#                 if capture_section == "affected_versions":
#                     cve_details["affected_versions"].extend(
#                         [v.strip() for v in re.split(r",|\n", text) if v.strip()]
#                     )
#                     continue
#                 if capture_section == "affected_configurations":
#                     cve_details["affected_configurations"].append(text)
#                     continue
#                 if capture_section == "solutions_and_mitigations":
#                     cve_details["solutions_and_mitigations"].append(text)
#                     continue

#                 # Description: skip first p, stop if <strong> inside p
#                 if capture_section is None:
#                     if skip_first_p:
#                         skip_first_p = False
#                         continue
#                     if block.find("strong"):
#                         continue
#                     buffer_desc.append(text)

#             cve_details["description"] = " ".join(buffer_desc).strip()

#             # Created / Updated date
#             time_elem = soup.select_one("span.relative-date")
#             if time_elem and time_elem.has_attr("data-time"):
#                 timestamp = int(time_elem["data-time"]) / 1000
#                 formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
#                 cve_details["created_date"] = formatted_time
#                 cve_details["updated_date"] = formatted_time

#             if cve_details["cve_ids"] or cve_details["severity"]:
#                 all_cves.append(cve_details)

#         return all_cves

#     except Exception as e:
#         log.warning(f"⚠️ Failed to fetch advisory {url}: {e}")
#         return []

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
# # Collect Elastic announcements
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

#             # Extract activity dates from title attribute
#             td = row.select_one("td.activity")
#             created_date, latest_date = None, None
#             if td and td.has_attr("title"):
#                 title_attr = td["title"]
#                 m1 = re.search(r"Created:\s*([^\n]+)", title_attr)
#                 m2 = re.search(r"Latest:\s*([^\n]+)", title_attr)
#                 if m1:
#                     created_date = m1.group(1).strip()
#                 if m2:
#                     latest_date = m2.group(1).strip()

#             topics.append({
#                 "title": title,
#                 "url": full_url,
#                 "created_date": created_date,
#                 "latest_date": latest_date
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
#                 "created_date": topic["created_date"],
#                 "latest_date": topic["latest_date"]
#             }
#             insert_advisory(topic["url"], raw_data, driver)
#             time.sleep(0.5)
#         log.info(f"✅ Finished. Stored {total}/{total} announcements.")
#     finally:
#         driver.quit()

# if __name__ == "__main__":
#     main()



# above is working




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
#     pattern = r"Severity:\s*(CVSSv\d\.\d:.*)"
#     match = re.search(pattern, text)
#     if match:
#         full_line = match.group(1).strip()
#         struct_pattern = r"CVSSv\d\.\d:\s*([\d\.]+)\s*\(?(\w+)?\)?\s*-?\s*(CVSS:.+)?"
#         m2 = re.search(struct_pattern, full_line)
#         if m2:
#             score, level, vector = m2.groups()
#             return {
#                 "cvss_score": float(score),
#                 "severity_level": level if level else "",
#                 "vector": vector if vector else ""
#             }
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
#             return []

#         sections = [s for s in cooked.decode_contents().split("<hr")]
#         all_cves = []

#         for section_html in sections:
#             section_soup = BeautifulSoup(section_html, "html.parser")
#             blocks = section_soup.find_all(["p", "li", "div"], recursive=True)

#             cve_details = {
#                 "cve_ids": [],
#                 "severity": [],
#                 "severity_data": [],
#                 "affected_versions": [],
#                 "affected_configurations": [],
#                 "solutions_and_mitigations": [],
#                 "cannot_upgrade": [],
#                 "description": "",
#                 "created_date": None,
#                 "updated_date": None
#             }

#             buffer_desc = []
#             capture_section = None
#             skip_first_p = True  # skip first <p>

#             for block in blocks:
#                 text = block.get_text(" ", strip=True)
#                 if not text:
#                     continue

#                 # CVE IDs
#                 for cve in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE):
#                     cve = cve.upper()
#                     if cve not in cve_details["cve_ids"]:
#                         cve_details["cve_ids"].append(cve)

#                 # Severity
#                 if "Severity:" in text:
#                     if text not in cve_details["severity"]:
#                         cve_details["severity"].append(text)
#                     sev = parse_severity(text)
#                     if sev and sev not in cve_details["severity_data"]:
#                         cve_details["severity_data"].append(sev)
#                     capture_section = None
#                     continue

#                 # Section headers
#                 if re.search(r"Affected Versions:", text, re.IGNORECASE):
#                     capture_section = "affected_versions"
#                     affected_text = re.sub(r"Affected Versions:\s*", "", text, flags=re.IGNORECASE)
#                     cve_details["affected_versions"].extend(
#                         [v.strip() for v in re.split(r",|\n", affected_text) if v.strip()]
#                     )
#                     continue

#                 if re.search(r"Affected Configurations:", text, re.IGNORECASE):
#                     capture_section = "affected_configurations"
#                     continue

#                 if re.search(r"Solutions and Mitigations:", text, re.IGNORECASE):
#                     capture_section = "solutions_and_mitigations"
#                     continue

#                 if "For Users that Cannot Upgrade" in text:
#                     cve_details["cannot_upgrade"].append(text)
#                     capture_section = None
#                     continue

#                 # Capture text by section
#                 if capture_section == "affected_versions":
#                     cve_details["affected_versions"].extend(
#                         [v.strip() for v in re.split(r",|\n", text) if v.strip()]
#                     )
#                     continue
#                 if capture_section == "affected_configurations":
#                     cve_details["affected_configurations"].append(text)
#                     continue
#                 if capture_section == "solutions_and_mitigations":
#                     cve_details["solutions_and_mitigations"].append(text)
#                     continue

#                 # Description: skip first p, stop if <strong> inside p
#                 if capture_section is None:
#                     if skip_first_p:
#                         skip_first_p = False
#                         continue
#                     if block.find("strong"):
#                         continue
#                     buffer_desc.append(text)

#             cve_details["description"] = " ".join(buffer_desc).strip()

#             # Created / Updated date
#             time_elem = soup.select_one("span.relative-date")
#             if time_elem and time_elem.has_attr("data-time"):
#                 timestamp = int(time_elem["data-time"]) / 1000
#                 formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
#                 cve_details["created_date"] = formatted_time
#                 cve_details["updated_date"] = formatted_time

#             if cve_details["cve_ids"] or cve_details["severity"]:
#                 all_cves.append(cve_details)

#         return all_cves

#     except Exception as e:
#         log.warning(f"⚠️ Failed to fetch advisory {url}: {e}")
#         return []

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
# # Collect Elastic announcements
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

#             # Extract activity dates from title attribute
#             td = row.select_one("td.activity")
#             created_date, latest_date = None, None
#             if td and td.has_attr("title"):
#                 title_attr = td["title"]
#                 m1 = re.search(r"Created:\s*([^\n]+)", title_attr)
#                 m2 = re.search(r"Latest:\s*([^\n]+)", title_attr)
#                 if m1:
#                     created_date = m1.group(1).strip()
#                 if m2:
#                     latest_date = m2.group(1).strip()

#             topics.append({
#                 "title": title,
#                 "url": full_url,
#                 "created_date": created_date,
#                 "latest_date": latest_date
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
#                 "created_date": topic["created_date"],
#                 "latest_date": topic["latest_date"]
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
#     # Extract CVSS line
#     m = re.search(r"(CVSSv\d\.\d:\s*[\d\.]+.*)", text, re.IGNORECASE)
#     if not m:
#         return {}
#     full_line = m.group(1).strip()

#     struct_pattern = r"CVSSv\d\.\d:\s*([\d\.]+)\s*\(?(\w+)?\)?\s*-?\s*(CVSS:[^\s]+.*)?"
#     m2 = re.search(struct_pattern, full_line)
#     if m2:
#         score, level, vector = m2.groups()
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
#             return []

#         # split advisories by <hr>
#         sections = [s for s in cooked.decode_contents().split("<hr")]
#         all_cves = []

#         for section_html in sections:
#             section_soup = BeautifulSoup(section_html, "html.parser")
#             blocks = section_soup.find_all(["h1", "h3", "p", "li"], recursive=True)

#             cve_details = {
#                 "title": "",
#                 "cve_ids": [],
#                 "severity": [],
#                 "severity_data": [],
#                 "affected_versions": [],
#                 "affected_configurations": [],
#                 "solutions_and_mitigations": [],
#                 "cannot_upgrade": [],
#                 "description": "",
#                 "created_date": None,
#                 "updated_date": None
#             }

#             buffer_desc = []
#             capture_section = None
#             skip_first_desc = True

#             for idx, block in enumerate(blocks):
#                 text = block.get_text(" ", strip=True)
#                 if not text:
#                     continue

#                 # ----------------------
#                 # Title (from <h1>)
#                 # ----------------------
#                 if block.name == "h1":
#                     cve_details["title"] = text
#                     continue

#                 # ----------------------
#                 # CVE IDs (global)
#                 # ----------------------
#                 for cve in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE):
#                     cve = cve.upper()
#                     if cve not in cve_details["cve_ids"]:
#                         cve_details["cve_ids"].append(cve)

#                 # ----------------------
#                 # Severity (new pattern in <h3> + next <p>)
#                 # ----------------------
#                 if block.name == "h3" and "severity" in text.lower():
#                     # next <p> might have severity + CVE
#                     next_p = block.find_next_sibling("p")
#                     if next_p:
#                         sev_text = next_p.get_text(" ", strip=True)
#                         if sev_text not in cve_details["severity"]:
#                             cve_details["severity"].append(sev_text)
#                         sev = parse_severity(sev_text)
#                         if sev and sev not in cve_details["severity_data"]:
#                             cve_details["severity_data"].append(sev)
#                         # CVEs inside severity <p>
#                         for cve in re.findall(r"CVE-\d{4}-\d{4,7}", sev_text, re.IGNORECASE):
#                             if cve not in cve_details["cve_ids"]:
#                                 cve_details["cve_ids"].append(cve.upper())
#                     continue

#                 # ----------------------
#                 # Old severity pattern in <p>
#                 # ----------------------
#                 if "Severity:" in text:
#                     if text not in cve_details["severity"]:
#                         cve_details["severity"].append(text)
#                     sev = parse_severity(text)
#                     if sev and sev not in cve_details["severity_data"]:
#                         cve_details["severity_data"].append(sev)
#                     continue

#                 # ----------------------
#                 # Section headers
#                 # ----------------------
#                 if re.search(r"Affected Versions", text, re.IGNORECASE):
#                     capture_section = "affected_versions"
#                     affected_text = re.sub(r"Affected Versions:?\s*", "", text, flags=re.IGNORECASE)
#                     if affected_text:
#                         cve_details["affected_versions"].extend(
#                             [v.strip() for v in re.split(r",|\n", affected_text) if v.strip()]
#                         )
#                     continue

#                 if re.search(r"Affected Configurations", text, re.IGNORECASE):
#                     capture_section = "affected_configurations"
#                     continue

#                 if re.search(r"Solutions and Mitigations", text, re.IGNORECASE):
#                     capture_section = "solutions_and_mitigations"
#                     continue

#                 if "For Users that Cannot Upgrade" in text:
#                     cve_details["cannot_upgrade"].append(text)
#                     capture_section = None
#                     continue

#                 # ----------------------
#                 # Capture section text
#                 # ----------------------
#                 if capture_section == "affected_versions":
#                     cve_details["affected_versions"].extend(
#                         [v.strip() for v in re.split(r",|\n", text) if v.strip()]
#                     )
#                     continue
#                 if capture_section == "affected_configurations":
#                     cve_details["affected_configurations"].append(text)
#                     continue
#                 if capture_section == "solutions_and_mitigations":
#                     cve_details["solutions_and_mitigations"].append(text)
#                     continue

#                 # ----------------------
#                 # Description (skip title p)
#                 # ----------------------
#                 if capture_section is None:
#                     if skip_first_desc:
#                         skip_first_desc = False
#                         continue
#                     if block.find("strong"):
#                         continue
#                     buffer_desc.append(text)

#             cve_details["description"] = " ".join(buffer_desc).strip()

#             # Created / Updated date
#             time_elem = soup.select_one("span.relative-date")
#             if time_elem and time_elem.has_attr("data-time"):
#                 timestamp = int(time_elem["data-time"]) / 1000
#                 formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
#                 cve_details["created_date"] = formatted_time
#                 cve_details["updated_date"] = formatted_time

#             if cve_details["cve_ids"] or cve_details["severity"]:
#                 all_cves.append(cve_details)

#         return all_cves

#     except Exception as e:
#         log.warning(f"⚠️ Failed to fetch advisory {url}: {e}")
#         return []

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
# # Collect Elastic announcements
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

#             # Extract activity dates from title attribute
#             td = row.select_one("td.activity")
#             created_date, latest_date = None, None
#             if td and td.has_attr("title"):
#                 title_attr = td["title"]
#                 m1 = re.search(r"Created:\s*([^\n]+)", title_attr)
#                 m2 = re.search(r"Latest:\s*([^\n]+)", title_attr)
#                 if m1:
#                     created_date = m1.group(1).strip()
#                 if m2:
#                     latest_date = m2.group(1).strip()

#             topics.append({
#                 "title": title,
#                 "url": full_url,
#                 "created_date": created_date,
#                 "latest_date": latest_date
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
#                 "created_date": topic["created_date"],
#                 "latest_date": topic["latest_date"]
#             }
#             insert_advisory(topic["url"], raw_data, driver)
#             time.sleep(0.5)
#         log.info(f"✅ Finished. Stored {total}/{total} announcements.")
#     finally:
#         driver.quit()

# if __name__ == "__main__":
#     main()



# best work










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
# # Parse severity pattern
# # ---------------------------
# def parse_severity(text):
#     pattern = r"Severity:\s*(CVSSv\d\.\d:.*)"
#     match = re.search(pattern, text)
#     if match:
#         full_line = match.group(1).strip()
#         struct_pattern = r"CVSSv\d\.\d:\s*([\d\.]+)\s*\(?(\w+)?\)?\s*-?\s*(CVSS:.+)?"
#         m2 = re.search(struct_pattern, full_line)
#         if m2:
#             score, level, vector = m2.groups()
#             return {
#                 "cvss_score": float(score),
#                 "severity_level": level if level else "",
#                 "vector": vector if vector else ""
#             }
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
#             return []

#         # Split by <hr> or keep entire page for multi advisory
#         sections = [s for s in cooked.decode_contents().split("<hr")]
#         all_cves = []

#         for section_html in sections:
#             section_soup = BeautifulSoup(section_html, "html.parser")
#             blocks = section_soup.find_all(["p", "li", "div", "h1", "h2", "h3", "strong"], recursive=True)

#             cve_details = {
#                 "cve_ids": [],
#                 "severity": [],
#                 "severity_data": [],
#                 "affected_versions": [],
#                 "affected_configurations": [],
#                 "solutions_and_mitigations": [],
#                 "cannot_upgrade": [],
#                 "description": {},
#             }

#             current_section = None
#             buffer_desc = []

#             for block in blocks:
#                 text = block.get_text(" ", strip=True)
#                 if not text:
#                     continue

#                 # CVE IDs
#                 for cve in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE):
#                     cve = cve.upper()
#                     if cve not in cve_details["cve_ids"]:
#                         cve_details["cve_ids"].append(cve)

#                 # Severity
#                 if "Severity:" in text:
#                     if text not in cve_details["severity"]:
#                         cve_details["severity"].append(text)
#                     sev = parse_severity(text)
#                     if sev and sev not in cve_details["severity_data"]:
#                         cve_details["severity_data"].append(sev)
#                     current_section = None
#                     continue

#                 # Sections by patterns / headings
#                 heading_match = re.match(r"(Affected Versions|Affected Configurations|Solutions and Mitigations|For Users that Cannot Upgrade):?", text, re.IGNORECASE)
#                 if heading_match or block.name in ["h1", "h2", "h3", "strong"]:
#                     section_name = heading_match.group(1).lower().replace(" ", "_") if heading_match else block.get_text(" ", strip=True).lower().replace(" ", "_")
#                     current_section = section_name
#                     buffer_desc = []
#                     continue

#                 # Capture content under heading until next heading
#                 if current_section:
#                     if current_section == "affected_versions":
#                         cve_details["affected_versions"].extend([v.strip() for v in re.split(r",|\n", text) if v.strip()])
#                     elif current_section == "affected_configurations":
#                         cve_details["affected_configurations"].append(text)
#                     elif current_section == "solutions_and_mitigations":
#                         cve_details["solutions_and_mitigations"].append(text)
#                     elif current_section == "for_users_that_cannot_upgrade":
#                         cve_details["cannot_upgrade"].append(text)
#                     else:
#                         # Generic description under any heading
#                         if current_section not in cve_details["description"]:
#                             cve_details["description"][current_section] = []
#                         cve_details["description"][current_section].append(text)
#                     continue

#                 # Generic description if no section
#                 if not current_section:
#                     buffer_desc.append(text)

#             if buffer_desc:
#                 cve_details["description"]["general"] = buffer_desc

#             if cve_details["cve_ids"] or cve_details["severity"]:
#                 all_cves.append(cve_details)

#         return all_cves

#     except Exception as e:
#         log.warning(f"⚠️ Failed to fetch advisory {url}: {e}")
#         return []

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
# # Collect Elastic announcements
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

#             # Extract activity dates from title attribute
#             td = row.select_one("td.activity")
#             created_date, latest_date = None, None
#             if td and td.has_attr("title"):
#                 title_attr = td["title"]
#                 m1 = re.search(r"Created:\s*([^\n]+)", title_attr)
#                 m2 = re.search(r"Latest:\s*([^\n]+)", title_attr)
#                 if m1:
#                     created_date = m1.group(1).strip()
#                 if m2:
#                     latest_date = m2.group(1).strip()

#             topics.append({
#                 "url": full_url,
#                 "created_date": created_date,
#                 "latest_date": latest_date
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
#                 "advisory_url": topic["url"],
#                 "created_date": topic["created_date"],
#                 "latest_date": topic["latest_date"]
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
# # def parse_severity(text):
# #     m = re.search(r"(CVSSv\d\.\d:\s*[\d\.]+.*)", text, re.IGNORECASE)
# #     if not m:
# #         return {}
# #     full_line = m.group(1).strip()
# #     struct_pattern = r"CVSSv\d\.\d:\s*([\d\.]+)\s*\(?(\w+)?\)?\s*-?\s*(CVSS:[^\s]+.*)?"
# #     m2 = re.search(struct_pattern, full_line)
# #     if m2:
# #         score, level, vector = m2.groups()
# #         return {
# #             "cvss_score": float(score),
# #             "severity_level": level if level else "",
# #             "vector": vector if vector else ""
# #         }
# #     return {}



# def parse_severity(text):
#     # Match "CVSSvX.Y: score(level) vector"
#     m = re.search(r"(CVSSv\d\.\d:\s*[\d\.]+.*)", text, re.IGNORECASE)
#     if not m:
#         return {}

#     full_line = m.group(1).strip()

#     struct_pattern = (
#         r"CVSSv\d\.\d:\s*([\d\.]+)"      # Score (e.g., 4.1)
#         r"\s*\(?([A-Za-z]+)?\)?"         # Optional severity word in ()
#         r"\s*-?\s*"                      # Optional dash
#         r"(CVSS:[^\s]+.*|[A-Z]{2}:[A-Z]\/.*)?"  # Either CVSS:... or shorthand AV:L/AC:H/...
#     )

#     m2 = re.search(struct_pattern, full_line)
#     if m2:
#         score, level, vector = m2.groups()
#         return {
#             "cvss_score": float(score),
#             "severity_level": level if level else "",
#             "vector": vector if vector else ""
#         }
#     return {}

# # ---------------------------
# # Fetch advisory details with stop conditions
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
#             return []

#         sections = [s for s in cooked.decode_contents().split("<hr")]
#         all_cves = []

#         for section_html in sections:
#             section_soup = BeautifulSoup(section_html, "html.parser")
#             blocks = section_soup.find_all(["h1", "h3", "p", "li", "strong", "table"], recursive=True)

#             cve_details = {
#                 "title": "",
#                 "cve_ids": [],
#                 "severity": [],
#                 "severity_data": [],
#                 "affected_versions": [],
#                 "affected_configurations": [],
#                 "solutions_and_mitigations": [],
#                 "cannot_upgrade": [],
#                 "description": "",
#                 "created_date": None,
#                 "updated_date": None
#             }

#             buffer_desc = []
#             capture_section = None
#             skip_first_desc = True

#             for idx, block in enumerate(blocks):
#                 text = block.get_text(" ", strip=True)
#                 if not text:
#                     continue

#                 # ----------------------
#                 # Stop conditions
#                 # ----------------------
#                 if block.name in ["h1", "h2", "h3", "h4", "strong", "table"]:
#                     capture_section = None
#                     if block.name in ["h1", "h2", "h3", "h4", "table"]:
#                         continue
#                 if "<hr" in str(block):
#                     capture_section = None
#                     continue

#                 # ----------------------
#                 # Title
#                 # ----------------------
#                 if block.name == "h1":
#                     cve_details["title"] = text
#                     continue

#                 # ----------------------
#                 # CVE IDs
#                 # ----------------------
#                 for cve in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE):
#                     cve = cve.upper()
#                     if cve not in cve_details["cve_ids"]:
#                         cve_details["cve_ids"].append(cve)

#                 # ----------------------
#                 # Severity handling
#                 # ----------------------
#                 if block.name == "h3" and "severity" in text.lower():
#                     next_p = block.find_next_sibling("p")
#                     if next_p:
#                         sev_text = next_p.get_text(" ", strip=True)
#                         if sev_text and sev_text.lower() != "severity:":
#                             if sev_text not in cve_details["severity"]:
#                                 cve_details["severity"].append(sev_text)
#                             sev = parse_severity(sev_text)
#                             if sev and sev not in cve_details["severity_data"]:
#                                 cve_details["severity_data"].append(sev)
#                             # Remove CVE from description later
#                     continue

#                 if "Severity:" in text and text.strip() != "Severity:":
#                     if text not in cve_details["severity"]:
#                         cve_details["severity"].append(text)
#                     sev = parse_severity(text)
#                     if sev and sev not in cve_details["severity_data"]:
#                         cve_details["severity_data"].append(sev)
#                     continue

#                 # ----------------------
#                 # Section headers
#                 # ----------------------
#                 if re.search(r"Affected Versions", text, re.IGNORECASE):
#                     capture_section = "affected_versions"
#                     affected_text = re.sub(r"Affected Versions:?\s*", "", text, flags=re.IGNORECASE)
#                     if affected_text:
#                         cve_details["affected_versions"].extend(
#                             [v.strip() for v in re.split(r",|\n", affected_text) if v.strip()]
#                         )
#                     continue

#                 if re.search(r"Affected Configurations", text, re.IGNORECASE):
#                     capture_section = "affected_configurations"
#                     continue

#                 if re.search(r"Solutions and Mitigations", text, re.IGNORECASE):
#                     capture_section = "solutions_and_mitigations"
#                     continue

#                 if "For Users that Cannot Upgrade" in text:
#                     cve_details["cannot_upgrade"].append(text)
#                     capture_section = None
#                     continue

#                 # ----------------------
#                 # Capture section text
#                 # ----------------------
#                 if capture_section == "affected_versions":
#                     cve_details["affected_versions"].extend(
#                         [v.strip() for v in re.split(r",|\n", text) if v.strip()]
#                     )
#                     continue
#                 if capture_section == "affected_configurations":
#                     cve_details["affected_configurations"].append(text)
#                     continue
#                 if capture_section == "solutions_and_mitigations":
#                     cve_details["solutions_and_mitigations"].append(text)
#                     continue

#                 # ----------------------
#                 # Description (trim extra CVE & start from 2nd paragraph)
#                 # ----------------------
#                 if capture_section is None:
#                     if skip_first_desc:
#                         skip_first_desc = False
#                         continue
#                     if block.find("strong") or block.name in ["table"]:
#                         continue
#                     # Remove CVE IDs already captured
#                     for cve in cve_details["cve_ids"]:
#                         text = re.sub(rf"\b{cve}\b", "", text, flags=re.IGNORECASE)
#                     buffer_desc.append(text.strip())

#             cve_details["description"] = " ".join([b for b in buffer_desc if b]).strip()

#             # Created / Updated date
#             time_elem = soup.select_one("span.relative-date")
#             if time_elem and time_elem.has_attr("data-time"):
#                 timestamp = int(time_elem["data-time"]) / 1000
#                 formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
#                 cve_details["created_date"] = formatted_time
#                 cve_details["updated_date"] = formatted_time

#             if cve_details["cve_ids"] or cve_details["severity"]:
#                 all_cves.append(cve_details)

#         return all_cves

#     except Exception as e:
#         log.warning(f"⚠️ Failed to fetch advisory {url}: {e}")
#         return []

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
# # Collect Elastic announcements
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
#             td = row.select_one("td.activity")
#             created_date, latest_date = None, None
#             if td and td.has_attr("title"):
#                 title_attr = td["title"]
#                 m1 = re.search(r"Created:\s*([^\n]+)", title_attr)
#                 m2 = re.search(r"Latest:\s*([^\n]+)", title_attr)
#                 if m1:
#                     created_date = m1.group(1).strip()
#                 if m2:
#                     latest_date = m2.group(1).strip()

#             topics.append({
#                 "title": title,
#                 "url": full_url,
#                 "created_date": created_date,
#                 "latest_date": latest_date
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
#                 "created_date": topic["created_date"],
#                 "latest_date": topic["latest_date"]
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
# # def parse_severity(text):
# #     m = re.search(r"(CVSSv\d\.\d:\s*[\d\.]+.*)", text, re.IGNORECASE)
# #     if not m:
# #         return {}
# #     full_line = m.group(1).strip()
# #     struct_pattern = r"CVSSv\d\.\d:\s*([\d\.]+)\s*\(?(\w+)?\)?\s*-?\s*(CVSS:[^\s]+.*)?"
# #     m2 = re.search(struct_pattern, full_line)
# #     if m2:
# #         score, level, vector = m2.groups()
# #         return {
# #             "cvss_score": float(score),
# #             "severity_level": level if level else "",
# #             "vector": vector if vector else ""
# #         }
# #     return {}



# def parse_severity(text):
#     # Match "CVSSvX.Y: score(level) vector"
#     m = re.search(r"(CVSSv\d\.\d:\s*[\d\.]+.*)", text, re.IGNORECASE)
#     if not m:
#         return {}

#     full_line = m.group(1).strip()

#     struct_pattern = (
#         r"CVSSv\d\.\d:\s*([\d\.]+)"      # Score (e.g., 4.1)
#         r"\s*\(?([A-Za-z]+)?\)?"         # Optional severity word in ()
#         r"\s*-?\s*"                      # Optional dash
#         r"(CVSS:[^\s]+.*|[A-Z]{2}:[A-Z]\/.*)?"  # Either CVSS:... or shorthand AV:L/AC:H/...
#     )

#     m2 = re.search(struct_pattern, full_line)
#     if m2:
#         score, level, vector = m2.groups()
#         return {
#             "cvss_score": float(score),
#             "severity_level": level if level else "",
#             "vector": vector if vector else ""
#         }
#     return {}

# # ---------------------------
# # Fetch advisory details with stop conditions
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
#             return []

#         sections = [s for s in cooked.decode_contents().split("<hr")]
#         all_cves = []

#         for section_html in sections:
#             section_soup = BeautifulSoup(section_html, "html.parser")
#             blocks = section_soup.find_all(["h1", "h3", "p", "li", "strong", "table"], recursive=True)

#             cve_details = {
#                 "title": "",
#                 "cve_ids": [],
#                 "severity": [],
#                 "severity_data": [],
#                 "affected_versions": [],
#                 "affected_configurations": [],
#                 "solutions_and_mitigations": [],
#                 "cannot_upgrade": [],
#                 "description": "",
#                 "created_date": None,
#                 "updated_date": None
#             }

#             buffer_desc = []
#             capture_section = None
#             skip_first_desc = True

#             for idx, block in enumerate(blocks):
#                 text = block.get_text(" ", strip=True)
#                 if not text:
#                     continue

#                 # ----------------------
#                 # Stop conditions
#                 # ----------------------
#                 if block.name in ["h1", "h2", "h3", "h4", "strong", "table"]:
#                     capture_section = None
#                     if block.name in ["h1", "h2", "h3", "h4", "table"]:
#                         continue
#                 if "<hr" in str(block):
#                     capture_section = None
#                     continue

#                 # ----------------------
#                 # Title
#                 # ----------------------
#                 if block.name == "h1":
#                     cve_details["title"] = text
#                     continue

#                 # ----------------------
#                 # CVE IDs
#                 # ----------------------
#                 for cve in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE):
#                     cve = cve.upper()
#                     if cve not in cve_details["cve_ids"]:
#                         cve_details["cve_ids"].append(cve)

#                 # ----------------------
#                 # Severity handling
#                 # ----------------------
#                 if block.name == "h3" and "severity" in text.lower():
#                     next_p = block.find_next_sibling("p")
#                     if next_p:
#                         sev_text = next_p.get_text(" ", strip=True)
#                         if sev_text and sev_text.lower() != "severity:":
#                             if sev_text not in cve_details["severity"]:
#                                 cve_details["severity"].append(sev_text)
#                             sev = parse_severity(sev_text)
#                             if sev and sev not in cve_details["severity_data"]:
#                                 cve_details["severity_data"].append(sev)
#                             # Remove CVE from description later
#                     continue

#                 if "Severity:" in text and text.strip() != "Severity:":
#                     if text not in cve_details["severity"]:
#                         cve_details["severity"].append(text)
#                     sev = parse_severity(text)
#                     if sev and sev not in cve_details["severity_data"]:
#                         cve_details["severity_data"].append(sev)
#                     continue

#                 # ----------------------
#                 # Section headers
#                 # ----------------------
#                 if re.search(r"Affected Versions", text, re.IGNORECASE):
#                     capture_section = "affected_versions"
#                     affected_text = re.sub(r"Affected Versions:?\s*", "", text, flags=re.IGNORECASE)
#                     if affected_text:
#                         cve_details["affected_versions"].extend(
#                             [v.strip() for v in re.split(r",|\n", affected_text) if v.strip()]
#                         )
#                     continue

#                 if re.search(r"Affected Configurations", text, re.IGNORECASE):
#                     capture_section = "affected_configurations"
#                     continue

#                 if re.search(r"Solutions and Mitigations", text, re.IGNORECASE):
#                     capture_section = "solutions_and_mitigations"
#                     continue

#                 if "For Users that Cannot Upgrade" in text:
#                     cve_details["cannot_upgrade"].append(text)
#                     capture_section = None
#                     continue

#                 # ----------------------
#                 # Capture section text
#                 # ----------------------
#                 if capture_section == "affected_versions":
#                     cve_details["affected_versions"].extend(
#                         [v.strip() for v in re.split(r",|\n", text) if v.strip()]
#                     )
#                     continue
#                 if capture_section == "affected_configurations":
#                     cve_details["affected_configurations"].append(text)
#                     continue
#                 if capture_section == "solutions_and_mitigations":
#                     cve_details["solutions_and_mitigations"].append(text)
#                     continue

#                 # ----------------------
#                 # Description (trim extra CVE & start from 2nd paragraph)
#                 # ----------------------
#                 if capture_section is None:
#                     if skip_first_desc:
#                         skip_first_desc = False
#                         continue
#                     if block.find("strong") or block.name in ["table"]:
#                         continue
#                     # Remove CVE IDs already captured
#                     for cve in cve_details["cve_ids"]:
#                         text = re.sub(rf"\b{cve}\b", "", text, flags=re.IGNORECASE)
#                     buffer_desc.append(text.strip())

#             cve_details["description"] = " ".join([b for b in buffer_desc if b]).strip()

#             # Created / Updated date
#             time_elem = soup.select_one("span.relative-date")
#             if time_elem and time_elem.has_attr("data-time"):
#                 timestamp = int(time_elem["data-time"]) / 1000
#                 formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
#                 cve_details["created_date"] = formatted_time
#                 cve_details["updated_date"] = formatted_time

#             if cve_details["cve_ids"] or cve_details["severity"]:
#                 all_cves.append(cve_details)

#         return all_cves

#     except Exception as e:
#         log.warning(f"⚠️ Failed to fetch advisory {url}: {e}")
#         return []

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
# # Collect Elastic announcements
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
#             td = row.select_one("td.activity")
#             created_date, latest_date = None, None
#             if td and td.has_attr("title"):
#                 title_attr = td["title"]
#                 m1 = re.search(r"Created:\s*([^\n]+)", title_attr)
#                 m2 = re.search(r"Latest:\s*([^\n]+)", title_attr)
#                 if m1:
#                     created_date = m1.group(1).strip()
#                 if m2:
#                     latest_date = m2.group(1).strip()

#             topics.append({
#                 "title": title,
#                 "url": full_url,
#                 "created_date": created_date,
#                 "latest_date": latest_date
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
#                 "created_date": topic["created_date"],
#                 "latest_date": topic["latest_date"]
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
#     m = re.search(r"(CVSSv\d\.\d:\s*[\d\.]+.*)", text, re.IGNORECASE)
#     if not m:
#         return {}
#     full_line = m.group(1).strip()
#     struct_pattern = (
#         r"CVSSv\d\.\d:\s*([\d\.]+)"      
#         r"\s*\(?([A-Za-z]+)?\)?"         
#         r"\s*-?\s*"                      
#         r"(CVSS:[^\s]+.*|[A-Z]{2}:[A-Z]\/.*)?"  
#     )
#     m2 = re.search(struct_pattern, full_line)
#     if m2:
#         score, level, vector = m2.groups()
#         return {
#             "cvss_score": float(score),
#             "severity_level": level if level else "",
#             "vector": vector if vector else ""
#         }
#     return {}

# # ---------------------------
# # Fetch advisory details with hr split
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
#             return []

#         # Split advisories by <hr>
#         sections = [s for s in cooked.decode_contents().split("<hr")]
#         all_cves = []

#         for section_html in sections:
#             section_soup = BeautifulSoup(section_html, "html.parser")
#             blocks = section_soup.find_all(["h1", "h2", "h3", "p", "li", "strong", "table"], recursive=True)

#             cve_details = {
#                 "title": "",
#                 "cve_ids": [],
#                 "severity": [],
#                 "severity_data": [],
#                 "affected_versions": [],
#                 "affected_configurations": [],
#                 "solutions_and_mitigations": [],
#                 "cannot_upgrade": [],
#                 "description": ""
#             }

#             buffer_desc = []
#             capture_section = None
#             skip_first_desc = True

#             for block in blocks:
#                 text = block.get_text(" ", strip=True)
#                 if not text:
#                     continue

#                 # ----------------------
#                 # Title (first h1/h2)
#                 # ----------------------
#                 if block.name in ["h1", "h2"] and not cve_details["title"]:
#                     cve_details["title"] = text
#                     continue

#                 # ----------------------
#                 # CVE IDs (unique only)
#                 # ----------------------
#                 for cve in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE):
#                     cve = cve.upper()
#                     if cve not in cve_details["cve_ids"]:
#                         cve_details["cve_ids"].append(cve)

#                 # ----------------------
#                 # Severity
#                 # ----------------------
#                 if block.name == "h3" and "severity" in text.lower():
#                     next_p = block.find_next_sibling("p")
#                     if next_p:
#                         sev_text = next_p.get_text(" ", strip=True)
#                         if sev_text and sev_text.lower() != "severity:":
#                             if sev_text not in cve_details["severity"]:
#                                 cve_details["severity"].append(sev_text)
#                             sev = parse_severity(sev_text)
#                             if sev and sev not in cve_details["severity_data"]:
#                                 cve_details["severity_data"].append(sev)
#                     continue

#                 if "Severity:" in text and text.strip() != "Severity:":
#                     if text not in cve_details["severity"]:
#                         cve_details["severity"].append(text)
#                     sev = parse_severity(text)
#                     if sev and sev not in cve_details["severity_data"]:
#                         cve_details["severity_data"].append(sev)
#                     continue

#                 # ----------------------
#                 # Section headers
#                 # ----------------------
#                 if re.search(r"Affected Versions", text, re.IGNORECASE):
#                     capture_section = "affected_versions"
#                     affected_text = re.sub(r"Affected Versions:?\s*", "", text, flags=re.IGNORECASE)
#                     if affected_text:
#                         cve_details["affected_versions"].extend(
#                             [v.strip() for v in re.split(r",|\n", affected_text) if v.strip()]
#                         )
#                     continue

#                 if re.search(r"Affected Configurations", text, re.IGNORECASE):
#                     capture_section = "affected_configurations"
#                     continue

#                 if re.search(r"Solutions and Mitigations", text, re.IGNORECASE):
#                     capture_section = "solutions_and_mitigations"
#                     continue

#                 if "For Users that Cannot Upgrade" in text:
#                     cve_details["cannot_upgrade"].append(text)
#                     capture_section = None
#                     continue

#                 # ----------------------
#                 # Capture sections
#                 # ----------------------
#                 if capture_section == "affected_versions":
#                     cve_details["affected_versions"].extend(
#                         [v.strip() for v in re.split(r",|\n", text) if v.strip()]
#                     )
#                     continue
#                 if capture_section == "affected_configurations":
#                     cve_details["affected_configurations"].append(text)
#                     continue
#                 if capture_section == "solutions_and_mitigations":
#                     cve_details["solutions_and_mitigations"].append(text)
#                     continue

#                 # ----------------------
#                 # Description
#                 # ----------------------
#                 if capture_section is None:
#                     if skip_first_desc:
#                         skip_first_desc = False
#                         continue
#                     if block.find("strong") or block.name == "table":
#                         continue
#                     buffer_desc.append(text.strip())

#             cve_details["description"] = " ".join([b for b in buffer_desc if b]).strip()

#             # Add only if useful
#             if cve_details["cve_ids"] or cve_details["severity"]:
#                 all_cves.append(cve_details)

#         return all_cves

#     except Exception as e:
#         log.warning(f"⚠️ Failed to fetch advisory {url}: {e}")
#         return []

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
# # Collect Elastic announcements
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
#             td = row.select_one("td.activity")
#             created_date, latest_date = None, None
#             if td and td.has_attr("title"):
#                 title_attr = td["title"]
#                 m1 = re.search(r"Created:\s*([^\n]+)", title_attr)
#                 m2 = re.search(r"Latest:\s*([^\n]+)", title_attr)
#                 if m1:
#                     created_date = m1.group(1).strip()
#                 if m2:
#                     latest_date = m2.group(1).strip()

#             topics.append({
#                 "title": title,
#                 "url": full_url,
#                 "created_date": created_date,
#                 "latest_date": latest_date
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
#                 "created_date": topic["created_date"],
#                 "latest_date": topic["latest_date"]
#             }
#             insert_advisory(topic["url"], raw_data, driver)
#             time.sleep(0.5)
#         log.info(f"✅ Finished. Stored {total}/{total} announcements.")
#     finally:
#         driver.quit()

# if __name__ == "__main__":
#     main()




# good version



#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# import os, re, time, warnings, logging
# import psycopg2
# from psycopg2.extras import Json
# from selenium import webdriver
# from selenium.webdriver.chrome.service import Service
# from selenium.webdriver.chrome.options import Options
# from selenium.webdriver.common.by import By
# from selenium.webdriver.support.ui import WebDriverWait
# from selenium.webdriver.support import expected_conditions as EC
# from webdriver_manager.chrome import ChromeDriverManager
# from bs4 import BeautifulSoup
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
# # DB helpers
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
# # Parse severity
# # ---------------------------
# def parse_severity(text):
#     m = re.search(r"(CVSSv\d\.\d:\s*[\d\.]+.*)", text, re.IGNORECASE)
#     if not m:
#         return {}
#     full_line = m.group(1).strip()
#     struct_pattern = (
#         r"CVSSv\d\.\d:\s*([\d\.]+)"      
#         r"\s*\(?([A-Za-z]+)?\)?"         
#         r"\s*-?\s*"                      
#         r"(CVSS:[^\s]+.*|[A-Z]{2}:[A-Z]\/.*)?"  
#     )
#     m2 = re.search(struct_pattern, full_line)
#     if m2:
#         score, level, vector = m2.groups()
#         return {
#             "cvss_score": float(score),
#             "severity_level": level if level else "",
#             "vector": vector if vector else ""
#         }
#     return {}

# # ---------------------------
# # Fetch advisory details with structured breaking
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
#             return []

#         sections = [s for s in cooked.decode_contents().split("<hr")]
#         all_cves = []

#         for section_html in sections:
#             section_soup = BeautifulSoup(section_html, "html.parser")
#             blocks = section_soup.find_all(["h1","h2","h3","h4","h5","p","li","strong","table"], recursive=True)

#             cve_details = {
#                 "title": "",
#                 "cve_ids": [],
#                 "severity": [],
#                 "severity_data": [],
#                 "affected_versions": [],
#                 "affected_configurations": [],
#                 "solutions_and_mitigations": [],
#                 "cannot_upgrade": [],
#                 "description": ""
#             }

#             buffer_desc = []
#             capture_section = None
#             got_title = False
#             collecting_description = False

#             for block in blocks:
#                 text = block.get_text(" ", strip=True)
#                 if not text:
#                     continue
#                 low = text.lower()

#                 # ---------------- Title ----------------
#                 if not got_title:
#                     if block.name in ["h1","h2","h3"] or (block.name == "p" and block.find("strong")):
#                         cve_details["title"] = text
#                         got_title = True
#                         collecting_description = True
#                         continue

#                 # ---------------- Stop description on patterns ----------------
#                 stop_markers = ["affected versions", "affected configurations", "solutions", "mitigations", "cve", "severity"]
#                 if collecting_description:
#                     if block.name in ["h1","h2","h3","h4","h5","table"] or block.find("strong") or any(sm in low for sm in stop_markers):
#                         collecting_description = False

#                 # ---------------- CVE IDs ----------------
#                 for cve in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE):
#                     cve = cve.upper()
#                     if cve not in cve_details["cve_ids"]:
#                         cve_details["cve_ids"].append(cve)

#                 # ---------------- Severity ----------------
#                 if "severity" in low:
#                     if text not in cve_details["severity"]:
#                         cve_details["severity"].append(text)
#                     sev = parse_severity(text)
#                     if sev and sev not in cve_details["severity_data"]:
#                         cve_details["severity_data"].append(sev)
#                     continue

#                 # ---------------- Section headers ----------------
#                 if "affected versions" in low:
#                     capture_section = "affected_versions"
#                     rest = re.sub(r"Affected Versions:?\s*", "", text, flags=re.I)
#                     if rest:
#                         cve_details["affected_versions"].extend([v.strip() for v in re.split(r",|\n", rest) if v.strip()])
#                     continue

#                 if "affected configurations" in low:
#                     capture_section = "affected_configurations"
#                     continue

#                 if "solutions" in low or "mitigations" in low:
#                     capture_section = "solutions_and_mitigations"
#                     continue

#                 if "for users that cannot upgrade" in low:
#                     cve_details["cannot_upgrade"].append(text)
#                     capture_section = None
#                     continue

#                 # ---------------- Capture section bodies ----------------
#                 if capture_section == "affected_versions":
#                     cve_details["affected_versions"].extend([v.strip() for v in re.split(r",|\n", text) if v.strip()])
#                     continue
#                 if capture_section == "affected_configurations":
#                     cve_details["affected_configurations"].append(text)
#                     continue
#                 if capture_section == "solutions_and_mitigations":
#                     cve_details["solutions_and_mitigations"].append(text)
#                     continue

#                 # ---------------- Description ----------------
#                 if collecting_description:
#                     buffer_desc.append(text.strip())

#             cve_details["description"] = " ".join(buffer_desc).strip()

#             if any([cve_details["title"], cve_details["cve_ids"], cve_details["description"]]):
#                 all_cves.append(cve_details)

#         return all_cves

#     except Exception as e:
#         log.warning(f"⚠️ Failed to fetch advisory {url}: {e}")
#         return []

# # ---------------------------
# # Insert into DB
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
# # Driver
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
# # Collect announcements
# # ---------------------------
# def collect_elastic_announcements(driver):
#     BASE = "https://discuss.elastic.co/c/announcements/security-announcements/31"
#     driver.get(BASE)

#     seen, topics = set(), []
#     last_count, attempts, max_attempts = -1, 0, 8

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
#             td = row.select_one("td.activity")
#             created_date, latest_date = None, None
#             if td and td.has_attr("title"):
#                 title_attr = td["title"]
#                 m1 = re.search(r"Created:\s*([^\n]+)", title_attr)
#                 m2 = re.search(r"Latest:\s*([^\n]+)", title_attr)
#                 if m1: created_date = m1.group(1).strip()
#                 if m2: latest_date = m2.group(1).strip()

#             topics.append({
#                 "title": title,
#                 "url": full_url,
#                 "created_date": created_date,
#                 "latest_date": latest_date
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
#                 "created_date": topic["created_date"],
#                 "latest_date": topic["latest_date"]
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

# import os, re, time, warnings, logging
# import psycopg2
# from psycopg2.extras import Json
# from selenium import webdriver
# from selenium.webdriver.chrome.service import Service
# from selenium.webdriver.chrome.options import Options
# from selenium.webdriver.common.by import By
# from selenium.webdriver.support.ui import WebDriverWait
# from selenium.webdriver.support import expected_conditions as EC
# from webdriver_manager.chrome import ChromeDriverManager
# from bs4 import BeautifulSoup
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
# # DB helpers
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
# # Convert empty fields to None
# # ---------------------------
# def nullify_empty(d):
#     """Recursively convert empty lists, dicts, or empty strings to None."""
#     if isinstance(d, dict):
#         return {k: nullify_empty(v) for k, v in d.items() if nullify_empty(v) is not None} or None
#     elif isinstance(d, list):
#         lst = [nullify_empty(x) for x in d if nullify_empty(x) is not None]
#         return lst if lst else None
#     elif isinstance(d, str):
#         return d.strip() if d.strip() else None
#     elif isinstance(d, (int, float, bool)):
#         return d
#     else:
#         return None

# # ---------------------------
# # Parse severity
# # ---------------------------
# def parse_severity(text):
#     m = re.search(r"(CVSSv\d\.\d:\s*[\d\.]+.*)", text, re.IGNORECASE)
#     if not m:
#         return None
#     full_line = m.group(1).strip()
#     struct_pattern = (
#         r"CVSSv\d\.\d:\s*([\d\.]+)"      
#         r"\s*\(?([A-Za-z]+)?\)?"         
#         r"\s*-?\s*"                       
#         r"(CVSS:[^\s]+.*|[A-Z]{2}:[A-Z]\/.*)?"  
#     )
#     m2 = re.search(struct_pattern, full_line)
#     if m2:
#         score, level, vector = m2.groups()
#         return nullify_empty({
#             "cvss_score": float(score),
#             "severity_level": level if level else None,
#             "vector": vector if vector else None
#         })
#     return None

# # ---------------------------
# # Fetch advisory details with structured breaking
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
#             return None

#         sections = [s for s in cooked.decode_contents().split("<hr")]
#         all_cves = []

#         for section_html in sections:
#             section_soup = BeautifulSoup(section_html, "html.parser")
#             blocks = section_soup.find_all(["h1","h2","h3","h4","h5","p","li","strong","table"], recursive=True)

#             cve_details = {
#                 "title": None,
#                 "cve_ids": None,
#                 "severity": None,
#                 "severity_data": None,
#                 "affected_versions": None,
#                 "affected_configurations": None,
#                 "solutions_and_mitigations": None,
#                 "cannot_upgrade": None,
#                 "description": None
#             }

#             buffer_desc = []
#             capture_section = None
#             got_title = False
#             collecting_description = False

#             for block in blocks:
#                 text = block.get_text(" ", strip=True)
#                 if not text:
#                     continue
#                 low = text.lower()

#                 # ---------------- Title ----------------
#                 if not got_title:
#                     if block.name in ["h1","h2","h3"] or (block.name == "p" and block.find("strong")):
#                         cve_details["title"] = text
#                         got_title = True
#                         collecting_description = True
#                         continue

#                 # ---------------- Stop description on patterns ----------------
#                 stop_markers = ["affected versions", "affected configurations", "solutions", "mitigations", "cve", "severity"]
#                 if collecting_description:
#                     if block.name in ["h1","h2","h3","h4","h5","table"] or block.find("strong") or any(sm in low for sm in stop_markers):
#                         collecting_description = False

#                 # ---------------- CVE IDs ----------------
#                 cve_list = re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
#                 if cve_list:
#                     if cve_details.get("cve_ids") is None:
#                         cve_details["cve_ids"] = []
#                     for cve in cve_list:
#                         cve = cve.upper()
#                         if cve not in cve_details["cve_ids"]:
#                             cve_details["cve_ids"].append(cve)

#                 # ---------------- Severity ----------------
#                 if "severity" in low:
#                     if cve_details.get("severity") is None:
#                         cve_details["severity"] = []
#                     if text not in cve_details["severity"]:
#                         cve_details["severity"].append(text)
#                     sev = parse_severity(text)
#                     if sev:
#                         if cve_details.get("severity_data") is None:
#                             cve_details["severity_data"] = []
#                         if sev not in cve_details["severity_data"]:
#                             cve_details["severity_data"].append(sev)
#                     continue

#                 # ---------------- Section headers ----------------
#                 if "affected versions" in low:
#                     capture_section = "affected_versions"
#                     rest = re.sub(r"Affected Versions:?\s*", "", text, flags=re.I)
#                     if rest:
#                         if cve_details.get("affected_versions") is None:
#                             cve_details["affected_versions"] = []
#                         cve_details["affected_versions"].extend([v.strip() for v in re.split(r",|\n", rest) if v.strip()])
#                     continue

#                 if "affected configurations" in low:
#                     capture_section = "affected_configurations"
#                     continue

#                 if "solutions" in low or "mitigations" in low:
#                     capture_section = "solutions_and_mitigations"
#                     continue

#                 if "for users that cannot upgrade" in low:
#                     if cve_details.get("cannot_upgrade") is None:
#                         cve_details["cannot_upgrade"] = []
#                     cve_details["cannot_upgrade"].append(text)
#                     capture_section = None
#                     continue

#                 # ---------------- Capture section bodies ----------------
#                 if capture_section == "affected_versions":
#                     if cve_details.get("affected_versions") is None:
#                         cve_details["affected_versions"] = []
#                     cve_details["affected_versions"].extend([v.strip() for v in re.split(r",|\n", text) if v.strip()])
#                     continue
#                 if capture_section == "affected_configurations":
#                     if cve_details.get("affected_configurations") is None:
#                         cve_details["affected_configurations"] = []
#                     cve_details["affected_configurations"].append(text)
#                     continue
#                 if capture_section == "solutions_and_mitigations":
#                     if cve_details.get("solutions_and_mitigations") is None:
#                         cve_details["solutions_and_mitigations"] = []
#                     cve_details["solutions_and_mitigations"].append(text)
#                     continue

#                 # ---------------- Description ----------------
#                 if collecting_description:
#                     buffer_desc.append(text.strip())

#             cve_details["description"] = " ".join(buffer_desc).strip() if buffer_desc else None
#             cve_details = nullify_empty(cve_details)
#             if cve_details:
#                 all_cves.append(cve_details)

#         return nullify_empty(all_cves) if all_cves else None

#     except Exception as e:
#         log.warning(f"⚠️ Failed to fetch advisory {url}: {e}")
#         return None

# # ---------------------------
# # Insert into DB
# # ---------------------------
# def insert_advisory(source_url, raw_data, driver):
#     if advisory_exists(source_url):
#         log.info(f"⏭ Skipping already existing advisory: {source_url}")
#         return

#     raw_data["cve_details"] = fetch_advisory_details(driver, source_url)
#     raw_data = nullify_empty(raw_data)

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
# # Driver
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
# # Collect announcements
# # ---------------------------
# def collect_elastic_announcements(driver):
#     BASE = "https://discuss.elastic.co/c/announcements/security-announcements/31"
#     driver.get(BASE)

#     seen, topics = set(), []
#     last_count, attempts, max_attempts = -1, 0, 8

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
#             td = row.select_one("td.activity")
#             created_date, latest_date = None, None
#             if td and td.has_attr("title"):
#                 title_attr = td["title"]
#                 m1 = re.search(r"Created:\s*([^\n]+)", title_attr)
#                 m2 = re.search(r"Latest:\s*([^\n]+)", title_attr)
#                 if m1: created_date = m1.group(1).strip()
#                 if m2: latest_date = m2.group(1).strip()

#             topics.append({
#                 "title": title,
#                 "url": full_url,
#                 "created_date": created_date,
#                 "latest_date": latest_date
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
#                 "created_date": topic["created_date"],
#                 "latest_date": topic["latest_date"]
#             }
#             insert_advisory(topic["url"], raw_data, driver)
#             time.sleep(0.5)
#         log.info(f"✅ Finished. Stored {total}/{total} announcements.")
#     finally:
#         driver.quit()

# if __name__ == "__main__":
#     main()






# Above is finest version 


# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-

# import os, re, time, warnings, logging
# from bs4 import BeautifulSoup
# from selenium import webdriver
# from selenium.webdriver.chrome.service import Service
# from selenium.webdriver.chrome.options import Options
# from selenium.webdriver.common.by import By
# from selenium.webdriver.support.ui import WebDriverWait
# from selenium.webdriver.support import expected_conditions as EC
# from webdriver_manager.chrome import ChromeDriverManager
# import psycopg2
# from psycopg2.extras import Json
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
# # DB Helpers
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
# # Helper: convert empty strings/lists to None
# # ---------------------------
# def nullify_empty(value):
#     if isinstance(value, dict):
#         return {k: nullify_empty(v) for k, v in value.items()}
#     elif isinstance(value, list):
#         return [nullify_empty(v) for v in value] if value else None
#     elif isinstance(value, str):
#         return value.strip() if value.strip() else None
#     return value

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
#             return []

#         blocks = cooked.find_all(["h1", "h2", "h3", "p", "strong", "li","h4"], recursive=True)

#         cve_details = {
#             "title": None,
#             "cve_ids": [],
#             "affected_versions": None,
#             "affected_configurations": None,
#             "solutions_and_mitigations": None,
#             "cannot_upgrade": None,
#             "description": None
#         }

#         section = None
#         description_buffer = []
#         title_set = False

#         for block in blocks:
#             text = block.get_text(" ", strip=True)
#             if not text:
#                 continue

#             low_text = text.lower()

#             # -------------------
#             # First heading or p as Title
#             # -------------------
#             if not title_set and block.name in ["h1", "h2", "p","h4","h3"]:
#                 cve_details["title"] = text
#                 title_set = True
#                 continue

#             # -------------------
#             # CVE IDs
#             # -------------------
#             for cve in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE):
#                 cve = cve.upper()
#                 if cve not in cve_details["cve_ids"]:
#                     cve_details["cve_ids"].append(cve)

#             # -------------------
#             # Section start detection
#             # -------------------
#             if re.search(r"affected versions", low_text):
#                 section = "affected_versions"
#                 content = re.sub(r"affected versions:?\s*", "", text, flags=re.I)
#                 if content:
#                     cve_details[section] = [v.strip() for v in re.split(r",|\n", content) if v.strip()]
#                 continue
#             elif re.search(r"affected configurations", low_text):
#                 section = "affected_configurations"
#                 continue
#             elif re.search(r"solutions and mitigations", low_text):
#                 section = "solutions_and_mitigations"
#                 continue
#             elif re.search(r"cannot upgrade", low_text):
#                 section = "cannot_upgrade"
#                 cve_details[section] = [text]
#                 section = None
#                 continue
#             # -------------------
#             # Stop capturing if a new heading or strong tag appears
#             # -------------------
#             elif block.name in ["h1", "h2", "h3", "strong","h4"]:
#                 section = None

#             # -------------------
#             # Capture section content
#             # -------------------
#             if section:
#                 if cve_details.get(section) is None:
#                     cve_details[section] = []
#                 cve_details[section].append(text)
#                 continue

#             # -------------------
#             # Capture description if not in a section
#             # -------------------
#             if not section and block.name not in ["strong"]:
#                 description_buffer.append(text)

#         # -------------------
#         # Set description
#         # -------------------
#         cve_details["description"] = " ".join(description_buffer).strip() if description_buffer else None

#         # -------------------
#         # Nullify empty lists
#         # -------------------
#         for key in ["cve_ids", "affected_versions", "affected_configurations",
#                     "solutions_and_mitigations", "cannot_upgrade"]:
#             if not cve_details[key]:
#                 cve_details[key] = None

#         return [cve_details]

#     except Exception as e:
#         log.warning(f"⚠️ Failed to fetch advisory {url}: {e}")
#         return []

# # ---------------------------
# # Insert advisory
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
# # Collect Elastic announcements
# # ---------------------------
# def collect_elastic_announcements(driver):
#     BASE = "https://discuss.elastic.co/c/announcements/security-announcements/31"
#     driver.get(BASE)
#     seen, topics = set(), []
#     last_count, max_attempts, attempts = -1, 8, 0
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
#             td = row.select_one("td.activity")
#             created_date, latest_date = None, None
#             if td and td.has_attr("title"):
#                 title_attr = td["title"]
#                 m1 = re.search(r"Created:\s*([^\n]+)", title_attr)
#                 m2 = re.search(r"Latest:\s*([^\n]+)", title_attr)
#                 if m1: created_date = m1.group(1).strip()
#                 if m2: latest_date = m2.group(1).strip()
#             topics.append({
#                 "title": title,
#                 "url": full_url,
#                 "created_date": created_date,
#                 "latest_date": latest_date
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
#                 "created_date": topic["created_date"],
#                 "latest_date": topic["latest_date"]
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

# import os, re, time, warnings, logging
# from bs4 import BeautifulSoup
# from selenium import webdriver
# from selenium.webdriver.chrome.service import Service
# from selenium.webdriver.chrome.options import Options
# from selenium.webdriver.common.by import By
# from selenium.webdriver.support.ui import WebDriverWait
# from selenium.webdriver.support import expected_conditions as EC
# from webdriver_manager.chrome import ChromeDriverManager
# import psycopg2
# from psycopg2.extras import Json
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
# # DB Helpers
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
# # Helper: convert empty strings/lists to None
# # ---------------------------
# def nullify_empty(value):
#     if isinstance(value, dict):
#         return {k: nullify_empty(v) for k, v in value.items()}
#     elif isinstance(value, list):
#         return [nullify_empty(v) for v in value] if value else None
#     elif isinstance(value, str):
#         return value.strip() if value.strip() else None
#     return value

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
#             return []

#         blocks = cooked.find_all(["h1", "h2", "h3", "h4", "p", "strong", "li"], recursive=True)

#         cve_details = {
#             "title": None,
#             "cve_ids": [],
#             "affected_versions": None,
#             "affected_configurations": None,
#             "solutions_and_mitigations": None,
#             "cannot_upgrade": None,
#             "severity": None,
#             "description": None
#         }

#         section = None
#         description_buffer = []
#         title_set = False

#         for block in blocks:
#             text = block.get_text(" ", strip=True)
#             if not text:
#                 continue
#             low_text = text.lower()

#             # -------------------
#             # First heading or p as Title
#             # -------------------
#             if not title_set and block.name in ["h1", "h2", "h3", "h4", "p"]:
#                 cve_details["title"] = text
#                 title_set = True
#                 continue

#             # -------------------
#             # CVE IDs
#             # -------------------
#             for cve in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE):
#                 cve = cve.upper()
#                 if cve not in cve_details["cve_ids"]:
#                     cve_details["cve_ids"].append(cve)

#             # -------------------
#             # Severity
#             # -------------------
#             if re.search(r"^severity", low_text) or re.search(r"^severity:", low_text):
#                 cve_details["severity"] = re.sub(r"^severity[:\s]*", "", text, flags=re.I)
#                 section = None
#                 continue

#             # -------------------
#             # Section start detection
#             # -------------------
#             if re.search(r"affected versions", low_text):
#                 section = "affected_versions"
#                 content = re.sub(r"affected versions:?\s*", "", text, flags=re.I)
#                 if content:
#                     cve_details[section] = [v.strip() for v in re.split(r",|\n", content) if v.strip()]
#                 continue
#             elif re.search(r"affected configurations", low_text):
#                 section = "affected_configurations"
#                 continue
#             elif re.search(r"solutions and mitigations", low_text):
#                 section = "solutions_and_mitigations"
#                 continue
#             elif re.search(r"cannot upgrade", low_text):
#                 section = "cannot_upgrade"
#                 cve_details[section] = [text]
#                 section = None
#                 continue
#             elif block.name in ["h1", "h2", "h3", "h4", "strong"]:
#                 section = None

#             # -------------------
#             # Capture section content
#             # -------------------
#             if section:
#                 if cve_details.get(section) is None:
#                     cve_details[section] = []
#                 cve_details[section].append(text)
#                 continue

#             # -------------------
#             # Description (only free text, not structured)
#             # -------------------
#             if not section and block.name not in ["strong"]:
#                 if not re.match(r"^(severity|affected versions|affected configurations|solutions and mitigations|cannot upgrade)", low_text):
#                     description_buffer.append(text)

#         # -------------------
#         # Finalize description
#         # -------------------
#         cve_details["description"] = " ".join(description_buffer).strip() if description_buffer else None

#         # -------------------
#         # Nullify empty lists
#         # -------------------
#         for key in ["cve_ids", "affected_versions", "affected_configurations",
#                     "solutions_and_mitigations", "cannot_upgrade"]:
#             if not cve_details[key]:
#                 cve_details[key] = None

#         return [cve_details]

#     except Exception as e:
#         log.warning(f"⚠️ Failed to fetch advisory {url}: {e}")
#         return []

# # ---------------------------
# # Insert advisory
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
# # Collect Elastic announcements
# # ---------------------------
# def collect_elastic_announcements(driver):
#     BASE = "https://discuss.elastic.co/c/announcements/security-announcements/31"
#     driver.get(BASE)
#     seen, topics = set(), []
#     last_count, max_attempts, attempts = -1, 8, 0
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
#             td = row.select_one("td.activity")
#             created_date, latest_date = None, None
#             if td and td.has_attr("title"):
#                 title_attr = td["title"]
#                 m1 = re.search(r"Created:\s*([^\n]+)", title_attr)
#                 m2 = re.search(r"Latest:\s*([^\n]+)", title_attr)
#                 if m1: created_date = m1.group(1).strip()
#                 if m2: latest_date = m2.group(1).strip()
#             topics.append({
#                 "title": title,
#                 "url": full_url,
#                 "created_date": created_date,
#                 "latest_date": latest_date
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
#                 "created_date": topic["created_date"],
#                 "latest_date": topic["latest_date"]
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

# import os, re, time, warnings, logging
# import psycopg2
# from psycopg2.extras import Json
# from selenium import webdriver
# from selenium.webdriver.chrome.service import Service
# from selenium.webdriver.chrome.options import Options
# from selenium.webdriver.common.by import By
# from selenium.webdriver.support.ui import WebDriverWait
# from selenium.webdriver.support import expected_conditions as EC
# from webdriver_manager.chrome import ChromeDriverManager
# from bs4 import BeautifulSoup
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
# # DB helpers
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
# # Convert empty fields to None
# # ---------------------------
# def nullify_empty(d):
#     """Recursively convert empty lists, dicts, or empty strings to None."""
#     if isinstance(d, dict):
#         return {k: nullify_empty(v) for k, v in d.items() if nullify_empty(v) is not None} or None
#     elif isinstance(d, list):
#         lst = [nullify_empty(x) for x in d if nullify_empty(x) is not None]
#         return lst if lst else None
#     elif isinstance(d, str):
#         return d.strip() if d.strip() else None
#     elif isinstance(d, (int, float, bool)):
#         return d
#     else:
#         return None

# # ---------------------------
# # Parse severity
# # ---------------------------
# def parse_severity(text):
#     m = re.search(r"(CVSSv\d\.\d:\s*[\d\.]+.*)", text, re.IGNORECASE)
#     if not m:
#         return None
#     full_line = m.group(1).strip()
#     struct_pattern = (
#         r"CVSSv\d\.\d:\s*([\d\.]+)"      
#         r"\s*\(?([A-Za-z]+)?\)?"         
#         r"\s*-?\s*"                       
#         r"(CVSS:[^\s]+.*|[A-Z]{2}:[A-Z]\/.*)?"  
#     )
#     m2 = re.search(struct_pattern, full_line)
#     if m2:
#         score, level, vector = m2.groups()
#         return nullify_empty({
#             "cvss_score": float(score),
#             "severity_level": level if level else None,
#             "vector": vector if vector else None
#         })
#     return None

# # ---------------------------
# # Fetch advisory details with structured breaking
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
#             return None

#         sections = [s for s in cooked.decode_contents().split("<hr")]
#         all_cves = []

#         for section_html in sections:
#             section_soup = BeautifulSoup(section_html, "html.parser")
#             blocks = section_soup.find_all(["h1","h2","h3","h4","h5","p","li","strong","table"], recursive=True)

#             cve_details = {
#                 "title": None,
#                 "cve_ids": None,
#                 "severity": None,
#                 "severity_data": None,
#                 "affected_versions": None,
#                 "affected_configurations": None,
#                 "solutions_and_mitigations": None,
#                 "cannot_upgrade": None,
#                 "description": None
#             }

#             buffer_desc = []
#             capture_section = None
#             got_title = False
#             collecting_description = False

#             for block in blocks:
#                 text = block.get_text(" ", strip=True)
#                 if not text:
#                     continue
#                 low = text.lower()

#                 # ---------------- Title ----------------
#                 if not got_title:
#                     if block.name in ["h1","h2","h3"] or (block.name == "p" and block.find("strong")):
#                         cve_details["title"] = text
#                         got_title = True
#                         collecting_description = True
#                         continue

#                 # ---------------- Stop description on patterns ----------------
#                 stop_markers = ["affected versions", "affected configurations", "solutions", "mitigations", "cve", "severity"]
#                 if collecting_description:
#                     if block.name in ["h1","h2","h3","h4","h5","table"] or block.find("strong") or any(sm in low for sm in stop_markers):
#                         collecting_description = False

#                 # ---------------- CVE IDs ----------------
#                 cve_list = re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
#                 if cve_list:
#                     if cve_details.get("cve_ids") is None:
#                         cve_details["cve_ids"] = []
#                     for cve in cve_list:
#                         cve = cve.upper()
#                         if cve not in cve_details["cve_ids"]:
#                             cve_details["cve_ids"].append(cve)

#                 # ---------------- Severity ----------------
#                 if "severity" in low:
#                     if cve_details.get("severity") is None:
#                         cve_details["severity"] = []
#                     if text not in cve_details["severity"]:
#                         cve_details["severity"].append(text)
#                     sev = parse_severity(text)
#                     if sev:
#                         if cve_details.get("severity_data") is None:
#                             cve_details["severity_data"] = []
#                         if sev not in cve_details["severity_data"]:
#                             cve_details["severity_data"].append(sev)
#                     continue

#                 # ---------------- Section headers ----------------
#                 if "affected versions" in low:
#                     capture_section = "affected_versions"
#                     rest = re.sub(r"Affected Versions:?\s*", "", text, flags=re.I)
#                     if rest:
#                         if cve_details.get("affected_versions") is None:
#                             cve_details["affected_versions"] = []
#                         cve_details["affected_versions"].extend([v.strip() for v in re.split(r",|\n", rest) if v.strip()])
#                     continue

#                 if "affected configurations" in low:
#                     capture_section = "affected_configurations"
#                     continue

#                 if "solutions" in low or "mitigations" in low:
#                     capture_section = "solutions_and_mitigations"
#                     continue

#                 if "for users that cannot upgrade" in low:
#                     if cve_details.get("cannot_upgrade") is None:
#                         cve_details["cannot_upgrade"] = []
#                     cve_details["cannot_upgrade"].append(text)
#                     capture_section = None
#                     continue

#                 # ---------------- Capture section bodies ----------------
#                 if capture_section == "affected_versions":
#                     if cve_details.get("affected_versions") is None:
#                         cve_details["affected_versions"] = []
#                     cve_details["affected_versions"].extend([v.strip() for v in re.split(r",|\n", text) if v.strip()])
#                     continue
#                 if capture_section == "affected_configurations":
#                     if cve_details.get("affected_configurations") is None:
#                         cve_details["affected_configurations"] = []
#                     cve_details["affected_configurations"].append(text)
#                     continue
#                 if capture_section == "solutions_and_mitigations":
#                     if cve_details.get("solutions_and_mitigations") is None:
#                         cve_details["solutions_and_mitigations"] = []
#                     cve_details["solutions_and_mitigations"].append(text)
#                     continue

#                 # ---------------- Description ----------------
#                 if collecting_description:
#                     buffer_desc.append(text.strip())

#             cve_details["description"] = " ".join(buffer_desc).strip() if buffer_desc else None
#             cve_details = nullify_empty(cve_details)
#             if cve_details:
#                 all_cves.append(cve_details)

#         return nullify_empty(all_cves) if all_cves else None

#     except Exception as e:
#         log.warning(f"⚠️ Failed to fetch advisory {url}: {e}")
#         return None
# def fetch_advisory_details(driver, url):
#     try:
#         driver.get(url)
#         WebDriverWait(driver, 10).until(
#             EC.presence_of_element_located((By.CSS_SELECTOR, "div.cooked"))
#         )
#         soup = BeautifulSoup(driver.page_source, "html.parser")
#         cooked = soup.select_one("div.cooked")
#         if not cooked:
#             return None

#         # Split sections by <hr> if present
#         sections = [s for s in cooked.decode_contents().split("<hr")]

#         all_cves = []

#         for section_html in sections:
#             section_soup = BeautifulSoup(section_html, "html.parser")
#             blocks = section_soup.find_all(["h1","h2","h3","h4","h5","p","li","strong"], recursive=True)

#             cve_details = {
#                 "title": None,
#                 "cve_ids": None,
#                 "severity": None,
#                 "severity_data": None,
#                 "affected_versions": None,
#                 "affected_configurations": None,
#                 "solutions_and_mitigations": None,
#                 "cannot_upgrade": None,
#                 "description": None
#             }

#             buffer_desc = []
#             capture_section = None
#             got_title = False
#             collecting_description = False

#             def extract_severity(block):
#                 """Extract Severity text, stop at next <strong> or <br>."""
#                 contents = block.contents
#                 severity_text = ""
#                 capture = False

#                 for item in contents:
#                     if getattr(item, "name", None) == "strong":
#                         if "severity" in item.get_text(strip=True).lower() or "cvssv" in item.get_text(strip=True).lower():
#                             capture = True
#                         else:
#                             if capture:
#                                 break
#                     elif getattr(item, "name", None) == "br":
#                         if capture:
#                             break
#                     if capture:
#                         if hasattr(item, "get_text"):
#                             severity_text += item.get_text(" ", strip=True) + " "
#                         else:
#                             severity_text += str(item).strip() + " "
#                 return severity_text.strip() if severity_text else None

#             for block in blocks:
#                 text = block.get_text(" ", strip=True)
#                 if not text:
#                     continue
#                 low = text.lower()

#                 # ---------------- Title ----------------
#                 if not got_title:
#                     if block.name in ["h1","h2","h3","h4","h5"] or (block.name == "p" and block.find("strong")):
#                         cve_details["title"] = text
#                         got_title = True
#                         collecting_description = True
#                         continue

#                 # ---------------- CVE IDs ----------------
#                 cve_list = re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
#                 if cve_list:
#                     if cve_details.get("cve_ids") is None:
#                         cve_details["cve_ids"] = []
#                     for cve in cve_list:
#                         cve = cve.upper()
#                         if cve not in cve_details["cve_ids"]:
#                             cve_details["cve_ids"].append(cve)

#                 # ---------------- Severity ----------------
#                 if "severity" in low or "cvssv" in low:
#                     sev = extract_severity(block)
#                     if sev:
#                         if cve_details.get("severity") is None:
#                             cve_details["severity"] = []
#                         if sev not in cve_details["severity"]:
#                             cve_details["severity"].append(sev)

#                         # Extract structured CVSS score & vector
#                         m = re.search(r"(CVSSv\d\.\d:.*?)(?:$|<|$)", sev, re.IGNORECASE)
#                         if m:
#                             if cve_details.get("severity_data") is None:
#                                 cve_details["severity_data"] = []
#                             cve_details["severity_data"].append(m.group(1).strip())
#                     continue

#                 # ---------------- Section Detection ----------------
#                 if re.search(r"affected versions\s*:", low):
#                     capture_section = "affected_versions"
#                     continue
#                 elif re.search(r"affected configurations\s*:", low):
#                     capture_section = "affected_configurations"
#                     continue
#                 elif re.search(r"solutions\s*and\s*mitigations\s*:", low):
#                     capture_section = "solutions_and_mitigations"
#                     continue
#                 elif re.search(r"for users that cannot upgrade", low):
#                     if cve_details.get("cannot_upgrade") is None:
#                         cve_details["cannot_upgrade"] = []
#                     cve_details["cannot_upgrade"].append(text)
#                     capture_section = None
#                     continue

#                 # ---------------- Capture Section Content ----------------
#                 if capture_section == "affected_versions":
#                     if cve_details.get("affected_versions") is None:
#                         cve_details["affected_versions"] = []
#                     # split by comma or newline
#                     cve_details["affected_versions"].extend([v.strip() for v in re.split(r",|\n", text) if v.strip()])
#                     continue

#                 if capture_section == "affected_configurations":
#                     if cve_details.get("affected_configurations") is None:
#                         cve_details["affected_configurations"] = []
#                     cve_details["affected_configurations"].append(text)
#                     continue

#                 if capture_section == "solutions_and_mitigations":
#                     if cve_details.get("solutions_and_mitigations") is None:
#                         cve_details["solutions_and_mitigations"] = []
#                     cve_details["solutions_and_mitigations"].append(text)
#                     continue

#                 # ---------------- Description ----------------
#                 if collecting_description:
#                     if block.name in ["h1","h2","h3","h4","h5"] or block.find("strong"):
#                         collecting_description = False
#                     else:
#                         buffer_desc.append(text.strip())

#             cve_details["description"] = " ".join(buffer_desc).strip() if buffer_desc else None
#             cve_details = nullify_empty(cve_details)
#             if cve_details:
#                 all_cves.append(cve_details)

#         return nullify_empty(all_cves) if all_cves else None

#     except Exception as e:
#         log.warning(f"⚠️ Failed to fetch advisory {url}: {e}")
#         return None



# def fetch_advisory_details(driver, url):
#     try:
#         driver.get(url)
#         WebDriverWait(driver, 10).until(
#             EC.presence_of_element_located((By.CSS_SELECTOR, "div.cooked"))
#         )
#         soup = BeautifulSoup(driver.page_source, "html.parser")
#         cooked = soup.select_one("div.cooked")
#         if not cooked:
#             return None

#         # Split sections by <hr> if present
#         sections = [s for s in cooked.decode_contents().split("<hr")]

#         all_cves = []

#         for section_html in sections:
#             section_soup = BeautifulSoup(section_html, "html.parser")
#             blocks = section_soup.find_all(["h1","h2","h3","h4","h5","p","li","strong"], recursive=True)

#             cve_details = {
#                 "title": None,
#                 "cve_ids": None,
#                 "severity": None,
#                 "severity_data": None,
#                 "affected_versions": None,
#                 "affected_configurations": None,
#                 "solutions_and_mitigations": None,
#                 "cannot_upgrade": None,
#                 "description": None
#             }

#             buffer_desc = []
#             capture_section = None
#             got_title = False
#             collecting_description = False
#             skip_next_header_for_upgrade = False  # New flag to skip the header line

#             def extract_severity(block):
#                 """Extract Severity text, stop at next <strong> or <br>."""
#                 contents = block.contents
#                 severity_text = ""
#                 capture = False

#                 for item in contents:
#                     if getattr(item, "name", None) == "strong":
#                         if "severity" in item.get_text(strip=True).lower() or "cvssv" in item.get_text(strip=True).lower():
#                             capture = True
#                         else:
#                             if capture:
#                                 break
#                     elif getattr(item, "name", None) == "br":
#                         if capture:
#                             break
#                     if capture:
#                         if hasattr(item, "get_text"):
#                             severity_text += item.get_text(" ", strip=True) + " "
#                         else:
#                             severity_text += str(item).strip() + " "
#                 return severity_text.strip() if severity_text else None

#             for block in blocks:
#                 text = block.get_text(" ", strip=True)
#                 if not text:
#                     continue
#                 low = text.lower()

#                 # ---------------- Title ----------------
#                 if not got_title:
#                     if block.name in ["h1","h2","h3","h4","h5"] or (block.name == "p" and block.find("strong")):
#                         cve_details["title"] = text
#                         got_title = True
#                         collecting_description = True
#                         continue

#                 # ---------------- CVE IDs ----------------
#                 cve_list = re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
#                 if cve_list:
#                     if cve_details.get("cve_ids") is None:
#                         cve_details["cve_ids"] = []
#                     for cve in cve_list:
#                         cve = cve.upper()
#                         if cve not in cve_details["cve_ids"]:
#                             cve_details["cve_ids"].append(cve)

#                 # ---------------- Severity ----------------
#                 if "severity" in low or "cvssv" in low:
#                     sev = extract_severity(block)
#                     if sev:
#                         if cve_details.get("severity") is None:
#                             cve_details["severity"] = []
#                         if sev not in cve_details["severity"]:
#                             cve_details["severity"].append(sev)

#                         # Extract structured CVSS score & vector
#                         m = re.search(r"(CVSSv\d\.\d:.*?)(?:$|<|$)", sev, re.IGNORECASE)
#                         if m:
#                             if cve_details.get("severity_data") is None:
#                                 cve_details["severity_data"] = []
#                             cve_details["severity_data"].append(m.group(1).strip())
#                     continue

#                 # ---------------- Section Detection ----------------
#                 if re.search(r"affected versions\s*:", low):
#                     capture_section = "affected_versions"
#                     continue
#                 elif re.search(r"affected configurations\s*:", low):
#                     capture_section = "affected_configurations"
#                     continue
#                 elif re.search(r"solutions\s*and\s*mitigations\s*:", low):
#                     capture_section = "solutions_and_mitigations"
#                     continue
#                 elif re.search(r"for users that cannot upgrade", low):
#                     capture_section = "cannot_upgrade"
#                     skip_next_header_for_upgrade = True  # Skip the header line itself
#                     continue

#                 # ---------------- Capture Section Content ----------------
#                 if capture_section == "affected_versions":
#                     if cve_details.get("affected_versions") is None:
#                         cve_details["affected_versions"] = []
#                     cve_details["affected_versions"].extend([v.strip() for v in re.split(r",|\n", text) if v.strip()])
#                     continue

#                 if capture_section == "affected_configurations":
#                     if cve_details.get("affected_configurations") is None:
#                         cve_details["affected_configurations"] = []
#                     cve_details["affected_configurations"].append(text)
#                     continue

#                 if capture_section == "solutions_and_mitigations":
#                     if cve_details.get("solutions_and_mitigations") is None:
#                         cve_details["solutions_and_mitigations"] = []
#                     cve_details["solutions_and_mitigations"].append(text)
#                     continue

#                 if capture_section == "cannot_upgrade":
#                     if skip_next_header_for_upgrade:
#                         skip_next_header_for_upgrade = False
#                         continue  # skip the "For Users that Cannot Upgrade:" line itself
#                     if cve_details.get("cannot_upgrade") is None:
#                         cve_details["cannot_upgrade"] = []
#                     cve_details["cannot_upgrade"].append(text)
#                     # Stop capturing on new heading or strong
#                     if block.name in ["h1","h2","h3","h4","h5"] or block.find("strong"):
#                         capture_section = None
#                     continue

#                 # ---------------- Description ----------------
#                 if collecting_description:
#                     if block.name in ["h1","h2","h3","h4","h5"] or block.find("strong"):
#                         collecting_description = False
#                     else:
#                         buffer_desc.append(text.strip())

#             cve_details["description"] = " ".join(buffer_desc).strip() if buffer_desc else None
#             cve_details = nullify_empty(cve_details)
#             if cve_details:
#                 all_cves.append(cve_details)

#         return nullify_empty(all_cves) if all_cves else None

#     except Exception as e:
#         log.warning(f"⚠️ Failed to fetch advisory {url}: {e}")
#         return None


# def fetch_advisory_details(driver, url):
#     try:
#         driver.get(url)
#         WebDriverWait(driver, 10).until(
#             EC.presence_of_element_located((By.CSS_SELECTOR, "div.cooked"))
#         )
#         soup = BeautifulSoup(driver.page_source, "html.parser")
#         cooked = soup.select_one("div.cooked")
#         if not cooked:
#             return None

#         # Split sections by <hr> if present
#         sections = [s for s in cooked.decode_contents().split("<hr")]

#         all_cves = []

#         for section_html in sections:
#             section_soup = BeautifulSoup(section_html, "html.parser")
#             blocks = section_soup.find_all(["h1", "h2", "h3", "h4", "h5", "p", "li", "strong"], recursive=True)

#             cve_details = {
#                 "title": None,
#                 "cve_ids": None,
#                 "severity": None,
#                 "severity_data": None,
#                 "affected_versions": None,
#                 "affected_configurations": None,
#                 "solutions_and_mitigations": None,
#                 "cannot_upgrade": None,
#                 "description": None
#             }

#             buffer_desc = []
#             capture_section = None
#             got_title = False
#             collecting_description = False
#             skip_next_header_for_upgrade = False  # Flag to skip the header line

#             def extract_block_after_strong(block):
#                 """Extracts text from a <p> block that starts with <strong>LABEL:</strong><br> content..."""
#                 lines = []
#                 capture = False
#                 for item in block.contents:
#                     if getattr(item, "name", None) == "strong":
#                         # only the label, actual content is after <br>
#                         continue
#                     elif getattr(item, "name", None) == "br":
#                         capture = True
#                         continue
#                     elif getattr(item, "name", None) in ["h1", "h2", "h3", "h4", "h5"]:
#                         break
#                     elif getattr(item, "name", None) == "strong" and capture:
#                         break
#                     elif capture:
#                         if isinstance(item, str):
#                             lines.append(item.strip())
#                         else:
#                             lines.append(item.get_text(" ", strip=True))
#                 return "\n".join([l for l in lines if l]).strip() if lines else None

#             def extract_severity(block):
#                 """Extract Severity text (supports both inline and <br>-after patterns)."""
#                 # Case 1: regular inline pattern
#                 contents = block.contents
#                 severity_text = ""
#                 capture = False

#                 for item in contents:
#                     if getattr(item, "name", None) == "strong":
#                         if "severity" in item.get_text(strip=True).lower() or "cvssv" in item.get_text(strip=True).lower():
#                             capture = True
#                         else:
#                             if capture:
#                                 break
#                     elif getattr(item, "name", None) == "br":
#                         # switch to new pattern (after <br>)
#                         return extract_block_after_strong(block)
#                     if capture:
#                         if hasattr(item, "get_text"):
#                             severity_text += item.get_text(" ", strip=True) + " "
#                         else:
#                             severity_text += str(item).strip() + " "
#                 return severity_text.strip() if severity_text else None

#             for block in blocks:
#                 text = block.get_text(" ", strip=True)
#                 if not text:
#                     continue
#                 low = text.lower()

#                 # ---------------- Title ----------------
#                 if not got_title:
#                     if block.name in ["h1", "h2", "h3", "h4", "h5"] or (block.name == "p" and block.find("strong")):
#                         cve_details["title"] = text
#                         got_title = True
#                         collecting_description = True
#                         continue

#                 # ---------------- CVE IDs ----------------
#                 cve_list = re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
#                 if cve_list:
#                     if cve_details.get("cve_ids") is None:
#                         cve_details["cve_ids"] = []
#                     for cve in cve_list:
#                         cve = cve.upper()
#                         if cve not in cve_details["cve_ids"]:
#                             cve_details["cve_ids"].append(cve)

#                 # ---------------- Severity ----------------
#                 if "severity" in low or "cvssv" in low:
#                     sev = extract_severity(block)
#                     if sev:
#                         if cve_details.get("severity") is None:
#                             cve_details["severity"] = []
#                         if sev not in cve_details["severity"]:
#                             cve_details["severity"].append(sev)

#                         # Extract structured CVSS score & vector
#                         m = re.search(r"(CVSSv\d\.\d:.*?)(?:$|<|$)", sev, re.IGNORECASE)
#                         if m:
#                             if cve_details.get("severity_data") is None:
#                                 cve_details["severity_data"] = []
#                             cve_details["severity_data"].append(m.group(1).strip())
#                     continue

#                 # ---------------- Section Detection ----------------
#                 if re.search(r"affected versions\s*:", low):
#                     capture_section = "affected_versions"
#                     continue
#                 elif re.search(r"affected configurations\s*:", low):
#                     capture_section = "affected_configurations"
#                     continue
#                 elif re.search(r"solutions\s*and\s*mitigations\s*:", low):
#                     capture_section = "solutions_and_mitigations"
#                     # handle new <br>-after pattern
#                     content = extract_block_after_strong(block)
#                     if content:
#                         if cve_details.get("solutions_and_mitigations") is None:
#                             cve_details["solutions_and_mitigations"] = []
#                         cve_details["solutions_and_mitigations"].append(content)
#                     continue
#                 elif re.search(r"for users that cannot upgrade", low):
#                     capture_section = "cannot_upgrade"
#                     skip_next_header_for_upgrade = True
#                     continue

#                 # ---------------- Capture Section Content (handles <br>) ----------------
#                 if capture_section:
#                     lines = []
#                     for item in block.contents:
#                         if isinstance(item, str):
#                             lines.append(item.strip())
#                         elif getattr(item, "name", None) == "br":
#                             lines.append("\n")
#                         else:
#                             lines.append(item.get_text(" ", strip=True))

#                     for line in "\n".join(lines).split("\n"):
#                         line = line.strip()
#                         if not line:
#                             continue
#                         if capture_section == "affected_versions":
#                             if cve_details.get("affected_versions") is None:
#                                 cve_details["affected_versions"] = []
#                             cve_details["affected_versions"].extend([v.strip() for v in re.split(r",", line) if v.strip()])
#                         elif capture_section == "affected_configurations":
#                             if cve_details.get("affected_configurations") is None:
#                                 cve_details["affected_configurations"] = []
#                             cve_details["affected_configurations"].append(line)
#                         elif capture_section == "solutions_and_mitigations":
#                             if cve_details.get("solutions_and_mitigations") is None:
#                                 cve_details["solutions_and_mitigations"] = []
#                             cve_details["solutions_and_mitigations"].append(line)
#                         elif capture_section == "cannot_upgrade":
#                             if skip_next_header_for_upgrade:
#                                 skip_next_header_for_upgrade = False
#                                 continue
#                             if cve_details.get("cannot_upgrade") is None:
#                                 cve_details["cannot_upgrade"] = []
#                             cve_details["cannot_upgrade"].append(line)

#                     if block.name in ["h1", "h2", "h3", "h4", "h5"] or block.find("strong"):
#                         capture_section = None
#                     continue

#                 # ---------------- Description ----------------
#                 if collecting_description:
#                     if block.name in ["h1", "h2", "h3", "h4", "h5"] or block.find("strong"):
#                         collecting_description = False
#                     else:
#                         buffer_desc.append(text.strip())

#             cve_details["description"] = " ".join(buffer_desc).strip() if buffer_desc else None
#             cve_details = nullify_empty(cve_details)
#             if cve_details:
#                 all_cves.append(cve_details)

#         return nullify_empty(all_cves) if all_cves else None

#     except Exception as e:
#         log.warning(f"⚠️ Failed to fetch advisory {url}: {e}")
#         return None

# def fetch_advisory_details(driver, url):
#     try:
#         driver.get(url)
#         WebDriverWait(driver, 10).until(
#             EC.presence_of_element_located((By.CSS_SELECTOR, "div.cooked"))
#         )
#         soup = BeautifulSoup(driver.page_source, "html.parser")
#         cooked = soup.select_one("div.cooked")
#         if not cooked:
#             return None

#         sections = [s for s in cooked.decode_contents().split("<hr")]
#         all_cves = []

#         for section_html in sections:
#             section_soup = BeautifulSoup(section_html, "html.parser")
#             blocks = section_soup.find_all(
#                 ["h1", "h2", "h3", "h4", "h5", "p", "li", "strong"], recursive=True
#             )

#             # Always pre-fill with None
#             cve_details = {
#                 "title": None,
#                 "cve_ids": None,
#                 "severity": None,
#                 "severity_data": None,
#                 "affected_versions": None,
#                 "affected_configurations": None,
#                 "solutions_and_mitigations": None,
#                 "cannot_upgrade": None,
#                 "description": None,
#             }

#             buffer_desc = []
#             capture_section = None
#             got_title = False
#             collecting_description = False
#             skip_next_header_for_upgrade = False

#             def extract_block_after_strong(block):
#                 lines, capture = [], False
#                 for item in block.contents:
#                     if getattr(item, "name", None) == "strong":
#                         continue
#                     elif getattr(item, "name", None) == "br":
#                         capture = True
#                         continue
#                     elif getattr(item, "name", None) in ["h1", "h2", "h3", "h4", "h5"]:
#                         break
#                     elif capture:
#                         if isinstance(item, str):
#                             lines.append(item.strip())
#                         else:
#                             lines.append(item.get_text(" ", strip=True))
#                 return "\n".join([l for l in lines if l]).strip() if lines else None

#             def extract_severity(block):
#                 contents = block.contents
#                 severity_text, capture = "", False
#                 for item in contents:
#                     if getattr(item, "name", None) == "strong":
#                         if "severity" in item.get_text(strip=True).lower() or "cvssv" in item.get_text(strip=True).lower():
#                             capture = True
#                         else:
#                             if capture:
#                                 break
#                     elif getattr(item, "name", None) == "br":
#                         return extract_block_after_strong(block)
#                     if capture:
#                         if hasattr(item, "get_text"):
#                             severity_text += item.get_text(" ", strip=True) + " "
#                         else:
#                             severity_text += str(item).strip() + " "
#                 return severity_text.strip() if severity_text else None

#             for block in blocks:
#                 text = block.get_text(" ", strip=True)
#                 if not text:
#                     continue
#                 low = text.lower()

#                 # --- Title ---
#                 if not got_title:
#                     if block.name in ["h1", "h2", "h3", "h4", "h5"] or (
#                         block.name == "p" and block.find("strong")
#                     ):
#                         cve_details["title"] = text
#                         got_title = True
#                         collecting_description = True
#                         continue

#                 # --- CVE IDs ---
#                 cve_list = re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
#                 if cve_list:
#                     if cve_details["cve_ids"] is None:
#                         cve_details["cve_ids"] = []
#                     for cve in cve_list:
#                         cve = cve.upper()
#                         if cve not in cve_details["cve_ids"]:
#                             cve_details["cve_ids"].append(cve)

#                 # --- Severity ---
#                 if "severity" in low or "cvssv" in low:
#                     sev = extract_severity(block)
#                     if sev:
#                         if cve_details["severity"] is None:
#                             cve_details["severity"] = []
#                         if sev not in cve_details["severity"]:
#                             cve_details["severity"].append(sev)

#                         m = re.search(r"(CVSSv\d\.\d:.*?)(?:$|<|$)", sev, re.IGNORECASE)
#                         if m:
#                             if cve_details["severity_data"] is None:
#                                 cve_details["severity_data"] = []
#                             cve_details["severity_data"].append(m.group(1).strip())
#                     continue

#                 # --- Section Detection ---
#                 if re.search(r"affected versions\s*:", low):
#                     capture_section = "affected_versions"
#                     continue
#                 elif re.search(r"affected configurations\s*:", low):
#                     capture_section = "affected_configurations"
#                     continue
#                 elif re.search(r"solutions\s*and\s*mitigations\s*:", low):
#                     capture_section = "solutions_and_mitigations"
#                     content = extract_block_after_strong(block)
#                     if content:
#                         if cve_details["solutions_and_mitigations"] is None:
#                             cve_details["solutions_and_mitigations"] = []
#                         cve_details["solutions_and_mitigations"].append(content)
#                     continue
#                 elif re.search(r"for users that cannot upgrade", low):
#                     capture_section = "cannot_upgrade"
#                     skip_next_header_for_upgrade = True
#                     continue

#                 # --- Capture Section Content ---
#                 if capture_section:
#                     lines = []
#                     for item in block.contents:
#                         if isinstance(item, str):
#                             lines.append(item.strip())
#                         elif getattr(item, "name", None) == "br":
#                             lines.append("\n")
#                         else:
#                             lines.append(item.get_text(" ", strip=True))

#                     for line in "\n".join(lines).split("\n"):
#                         line = line.strip()
#                         if not line:
#                             continue
#                         if capture_section == "affected_versions":
#                             if cve_details["affected_versions"] is None:
#                                 cve_details["affected_versions"] = []
#                             cve_details["affected_versions"].extend(
#                                 [v.strip() for v in re.split(r",", line) if v.strip()]
#                             )
#                         elif capture_section == "affected_configurations":
#                             if cve_details["affected_configurations"] is None:
#                                 cve_details["affected_configurations"] = []
#                             cve_details["affected_configurations"].append(line)
#                         elif capture_section == "solutions_and_mitigations":
#                             if cve_details["solutions_and_mitigations"] is None:
#                                 cve_details["solutions_and_mitigations"] = []
#                             cve_details["solutions_and_mitigations"].append(line)
#                         elif capture_section == "cannot_upgrade":
#                             if skip_next_header_for_upgrade:
#                                 skip_next_header_for_upgrade = False
#                                 continue
#                             if cve_details["cannot_upgrade"] is None:
#                                 cve_details["cannot_upgrade"] = []
#                             cve_details["cannot_upgrade"].append(line)

#                     if block.name in ["h1", "h2", "h3", "h4", "h5"] or block.find("strong"):
#                         capture_section = None
#                     continue

#                 # --- Description ---
#                 if collecting_description:
#                     if block.name in ["h1", "h2", "h3", "h4", "h5"] or block.find("strong"):
#                         collecting_description = False
#                     else:
#                         buffer_desc.append(text.strip())

#             cve_details["description"] = " ".join(buffer_desc).strip() if buffer_desc else None

#             # ✅ No nullify_empty → always keep all keys
#             all_cves.append(cve_details)

#         return all_cves if all_cves else None

#     except Exception as e:
#         log.warning(f"⚠️ Failed to fetch advisory {url}: {e}")
#         return None


# # ---------------------------
# # Insert into DB
# # ---------------------------
# def insert_advisory(source_url, raw_data, driver):
#     if advisory_exists(source_url):
#         log.info(f"⏭ Skipping already existing advisory: {source_url}")
#         return

#     raw_data["cve_details"] = fetch_advisory_details(driver, source_url)
#     raw_data = nullify_empty(raw_data)

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
# # Driver
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
# # Collect announcements
# # ---------------------------
# def collect_elastic_announcements(driver):
#     BASE = "https://discuss.elastic.co/c/announcements/security-announcements/31"
#     driver.get(BASE)

#     seen, topics = set(), []
#     last_count, attempts, max_attempts = -1, 0, 8

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
#             td = row.select_one("td.activity")
#             created_date, latest_date = None, None
#             if td and td.has_attr("title"):
#                 title_attr = td["title"]
#                 m1 = re.search(r"Created:\s*([^\n]+)", title_attr)
#                 m2 = re.search(r"Latest:\s*([^\n]+)", title_attr)
#                 if m1: created_date = m1.group(1).strip()
#                 if m2: latest_date = m2.group(1).strip()

#             topics.append({
#                 "title": title,
#                 "url": full_url,
#                 "created_date": created_date,
#                 "latest_date": latest_date
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
#                 "created_date": topic["created_date"],
#                 "latest_date": topic["latest_date"]
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

import os, re, time, warnings, logging
import psycopg2
from psycopg2.extras import Json
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
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
# DB helpers
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
# Convert empty fields to None
# ---------------------------
def nullify_empty(d):
    """Recursively convert empty lists, dicts, or empty strings to None."""
    if isinstance(d, dict):
        return {k: nullify_empty(v) for k, v in d.items() if nullify_empty(v) is not None} or None
    elif isinstance(d, list):
        lst = [nullify_empty(x) for x in d if nullify_empty(x) is not None]
        return lst if lst else None
    elif isinstance(d, str):
        return d.strip() if d.strip() else None
    elif isinstance(d, (int, float, bool)):
        return d
    else:
        return None

# --# -------------------------
# Parse severity
# ---------------------------
def parse_severity(text):
    m = re.search(r"(CVSSv\d\.\d:\s*[\d\.]+.*)", text, re.IGNORECASE)
    if not m:
        return None
    full_line = m.group(1).strip()
    struct_pattern = (
        r"CVSSv\d\.\d:\s*([\d\.]+)"      
        r"\s*\(?([A-Za-z]+)?\)?"         
        r"\s*-?\s*"                       
        r"(CVSS:[^\s]+.*|[A-Z]{2}:[A-Z]\/.*)?"  
    )
    m2 = re.search(struct_pattern, full_line)
    if m2:
        score, level, vector = m2.groups()
        return nullify_empty({
            "cvss_score": float(score),
            "severity_level": level if level else None,
            "vector": vector if vector else None
        })
    return None

def fetch_advisory_details(driver, url, created_date=None, latest_date=None):
    try:
        driver.get(url)
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "div.cooked"))
        )
        soup = BeautifulSoup(driver.page_source, "html.parser")
        cooked = soup.select_one("div.cooked")
        if not cooked:
            return None

        sections = [s for s in cooked.decode_contents().split("<hr")]
        all_cves = []

        for section_html in sections:
            section_soup = BeautifulSoup(section_html, "html.parser")
            blocks = section_soup.find_all(
                ["h1", "h2", "h3", "h4", "h5", "p", "li", "strong"], recursive=True
            )

            # Always pre-fill with None + dates
            cve_details = {
                "title": None,
                "cve_ids": None,
                "severity": None,
                "severity_data": None,
                "affected_versions": None,
                "affected_configurations": None,
                "solutions_and_mitigations": None,
                "cannot_upgrade": None,
                "description": None,
                "created_date": created_date if created_date else None,
                "latest_date": latest_date if latest_date else None,
            }

            buffer_desc = []
            capture_section = None
            got_title = False
            collecting_description = False
            skip_next_header_for_upgrade = False

            def extract_block_after_strong(block):
                lines, capture = [], False
                for item in block.contents:
                    if getattr(item, "name", None) == "strong":
                        continue
                    elif getattr(item, "name", None) == "br":
                        capture = True
                        continue
                    elif getattr(item, "name", None) in ["h1", "h2", "h3", "h4", "h5"]:
                        break
                    elif capture:
                        if isinstance(item, str):
                            lines.append(item.strip())
                        else:
                            lines.append(item.get_text(" ", strip=True))
                return "\n".join([l for l in lines if l]).strip() if lines else None

            # -----------------------------
            # Updated Severity Extraction
            # -----------------------------
            def extract_severity(block):
                """
                Extract severity text immediately after a <strong> containing 'severity' or 'CVSS'
                and stop at the next <strong>, heading (h1-h5), or <hr>.
                """
                severity_text = []
                capture = False

                for item in block.contents:
                    # Start capturing after <strong> with 'severity' or 'CVSS'
                    if getattr(item, "name", None) == "strong":
                        strong_text = item.get_text(strip=True).lower()
                        if "severity" in strong_text or "cvssv" in strong_text:
                            capture = True
                        else:
                            if capture:  # Stop if we hit another strong
                                break
                        continue

                    # Stop capturing if we hit another strong, heading, or hr
                    if capture and getattr(item, "name", None) in ["strong", "h1", "h2", "h3", "h4", "h5", "hr"]:
                        break

                    # Capture text
                    if capture:
                        if isinstance(item, str):
                            severity_text.append(item.strip())
                        elif hasattr(item, "get_text"):
                            severity_text.append(item.get_text(" ", strip=True))

                result = " ".join([s for s in severity_text if s]).strip()
                return result if result else None

            for block in blocks:
                text = block.get_text(" ", strip=True)
                if not text:
                    continue
                low = text.lower()

                # --- Title ---
                if not got_title:
                    if block.name in ["h1", "h2", "h3", "h4", "h5"] or (
                        block.name == "p" and block.find("strong")
                    ):
                        cve_details["title"] = text
                        got_title = True
                        collecting_description = True
                        continue

                # --- CVE IDs ---
                cve_list = re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
                if cve_list:
                    if cve_details["cve_ids"] is None:
                        cve_details["cve_ids"] = []
                    for cve in cve_list:
                        cve = cve.upper()
                        if cve not in cve_details["cve_ids"]:
                            cve_details["cve_ids"].append(cve)

                # --- Severity ---
                if "severity" in low or "cvssv" in low:
                    sev = extract_severity(block)
                    if sev:
                        if cve_details["severity"] is None:
                            cve_details["severity"] = []
                        if sev not in cve_details["severity"]:
                            cve_details["severity"].append(sev)

                        m = re.search(r"(CVSSv\d\.\d:.*?)(?:$|<|$)", sev, re.IGNORECASE)
                        if m:
                            if cve_details["severity_data"] is None:
                                cve_details["severity_data"] = []
                            cve_details["severity_data"].append(m.group(1).strip())
                    continue

                # --- Section Detection ---
                if re.search(r"affected versions\s*:", low):
                    capture_section = "affected_versions"
                    continue
                elif re.search(r"affected configurations\s*:", low):
                    capture_section = "affected_configurations"
                    continue
                elif re.search(r"solutions\s*and\s*mitigations\s*:", low):
                    capture_section = "solutions_and_mitigations"
                    content = extract_block_after_strong(block)
                    if content:
                        if cve_details["solutions_and_mitigations"] is None:
                            cve_details["solutions_and_mitigations"] = []
                        cve_details["solutions_and_mitigations"].append(content)
                    continue
                elif re.search(r"for users that cannot upgrade", low):
                    capture_section = "cannot_upgrade"
                    skip_next_header_for_upgrade = True
                    continue

                # --- Capture Section Content ---
                if capture_section:
                    lines = []
                    for item in block.contents:
                        if isinstance(item, str):
                            lines.append(item.strip())
                        elif getattr(item, "name", None) == "br":
                            lines.append("\n")
                        else:
                            lines.append(item.get_text(" ", strip=True))

                    for line in "\n".join(lines).split("\n"):
                        line = line.strip()
                        if not line:
                            continue
                        if capture_section == "affected_versions":
                            if cve_details["affected_versions"] is None:
                                cve_details["affected_versions"] = []
                            cve_details["affected_versions"].extend(
                                [v.strip() for v in re.split(r",", line) if v.strip()]
                            )
                        elif capture_section == "affected_configurations":
                            if cve_details["affected_configurations"] is None:
                                cve_details["affected_configurations"] = []
                            cve_details["affected_configurations"].append(line)
                        elif capture_section == "solutions_and_mitigations":
                            if cve_details["solutions_and_mitigations"] is None:
                                cve_details["solutions_and_mitigations"] = []
                            cve_details["solutions_and_mitigations"].append(line)
                        elif capture_section == "cannot_upgrade":
                            if skip_next_header_for_upgrade:
                                skip_next_header_for_upgrade = False
                                continue
                            if cve_details["cannot_upgrade"] is None:
                                cve_details["cannot_upgrade"] = []
                            cve_details["cannot_upgrade"].append(line)

                    if block.name in ["h1", "h2", "h3", "h4", "h5"] or block.find("strong"):
                        capture_section = None
                    continue

                # --- Description ---
                if collecting_description:
                    if block.name in ["h1", "h2", "h3", "h4", "h5"] or block.find("strong"):
                        collecting_description = False
                    else:
                        buffer_desc.append(text.strip())

            cve_details["description"] = " ".join(buffer_desc).strip() if buffer_desc else None

            all_cves.append(cve_details)

        return all_cves if all_cves else None

    except Exception as e:
        log.warning(f"⚠️ Failed to fetch advisory {url}: {e}")
        return None

# ---------------------------
# Inside insert_advisory
def insert_advisory(source_url, raw_data, driver):
    # Ensure both dates are present
    if "created_date" not in raw_data:
        raw_data["created_date"] = None
    if "latest_date" not in raw_data:
        raw_data["latest_date"] = None

    if advisory_exists(source_url):
        log.info(f"⏭ Skipping already existing advisory: {source_url}")
        return

    raw_data["cve_details"] = fetch_advisory_details(
        driver,
        source_url,
        raw_data.get("created_date"),
        raw_data.get("latest_date")
    )
    raw_data = nullify_empty(raw_data)

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
# Driver
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
# Collect announcements
# ---------------------------
def collect_elastic_announcements(driver):
    BASE = "https://discuss.elastic.co/c/announcements/security-announcements/31"
    driver.get(BASE)

    seen, topics = set(), []
    last_count, attempts, max_attempts = -1, 0, 8

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
            td = row.select_one("td.activity")
            created_date, latest_date = None, None
            if td and td.has_attr("title"):
                title_attr = td["title"]
                m1 = re.search(r"Created:\s*([^\n]+)", title_attr)
                m2 = re.search(r"Latest:\s*([^\n]+)", title_attr)
                if m1: created_date = m1.group(1).strip()
                if m2: latest_date = m2.group(1).strip()

            topics.append({
                "title": title,
                "url": full_url,
                "created_date": created_date,
                "latest_date": latest_date
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
                "created_date": topic["created_date"],
                "latest_date": topic["latest_date"]
            }
            insert_advisory(topic["url"], raw_data, driver)
            time.sleep(0.5)
        log.info(f"✅ Finished. Stored {total}/{total} announcements.")
    finally:
        driver.quit()

if __name__ == "__main__":
    main()
