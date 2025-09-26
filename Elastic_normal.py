# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-

# import os
# import re
# import logging
# import psycopg2
# from datetime import datetime
# from dotenv import load_dotenv
# from urllib.parse import urlparse

# # -------------------------
# # Config
# # -------------------------
# load_dotenv()
# DB_CONFIG = {
#     "host": os.getenv("DB_HOST", "localhost"),
#     "dbname": os.getenv("DB_NAME", "Elastic"),
#     "user": os.getenv("DB_USER", "postgres"),
#     "password": os.getenv("DB_PASS", "623809"),
#     "port": int(os.getenv("DB_PORT", 5432)),
# }

# # Control whether to mark staging rows as processed
# MARK_PROCESSED = False

# # -------------------------
# # Logging
# # -------------------------
# logging.basicConfig(level=logging.INFO, format="%(message)s")
# logger = logging.getLogger("elastic_normalizer")

# # -------------------------
# # Table Names
# # -------------------------
# TABLE_STAGING = "staging_table"
# TABLE_VENDORS = "vendors"
# TABLE_ADVISORIES = "advisories"
# TABLE_CVES = "cves"
# TABLE_ADV_CVE_MAP = "advisory_cves_map"
# TABLE_CVE_PRODUCT_MAP = "cve_product_map"

# # -------------------------
# # Helpers
# # -------------------------
# def safe_date(s):
#     if not s:
#         return None
#     for fmt in (
#         "%Y-%m-%d",
#         "%b %d, %Y",
#         "%B %d, %Y",
#         "%b %d %Y %I:%M %p",
#         "%b %d, %Y %I:%M %p",
#         "%B %d, %Y %I:%M %p",
#     ):
#         try:
#             return datetime.strptime(s.strip(), fmt).date()
#         except Exception:
#             continue
#     return None

# def extract_advisory_id(url):
#     """Take last path segment and prepend 'Elastic-'"""
#     try:
#         last = urlparse(url).path.strip("/").split("/")[-1]
#         return f"Elastic-{last}"
#     except Exception:
#         return None

# def generate_cve_url(cve_id, extra_text):
#     urls = []
#     if extra_text:
#         matches = re.findall(r"(https?://\S+)", str(extra_text))
#         urls.extend(matches)
#     if cve_id:
#         urls.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
#         urls.append(f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}")
#     return " | ".join(urls) if urls else None

# def clean_text(val):
#     if not val:
#         return None
#     val = re.sub(r"[\r\n\t]+", " ", str(val))
#     val = re.sub(r"\s{2,}", " ", val)
#     return val.strip()

# def parse_severity_block(block_list):
#     """Extract severity, score, and vector from severity text"""
#     sev, score, vector = None, None, None
#     if not block_list:
#         return sev, score, vector
#     text = " ".join(block_list)
#     m1 = re.search(r"\((Low|Medium|High|Critical)\)", text, re.IGNORECASE)
#     if m1:
#         sev = m1.group(1).capitalize()
#     m2 = re.search(r"CVSSv\d\.\d*:\s*([\d\.]+)", text)
#     if m2:
#         try:
#             score = float(m2.group(1))
#         except Exception:
#             pass
#     m3 = re.search(r"(CVSS:[\d\.]+/[A-Z:\/]+)", text)
#     if m3:
#         vector = m3.group(1)
#     return sev, score, vector

# # -------------------------
# # Ensure Tables
# # -------------------------
# def ensure_tables(conn):
#     cur = conn.cursor()
#     cur.execute(f"""
#         CREATE TABLE IF NOT EXISTS {TABLE_VENDORS} (
#             vendor_id SERIAL PRIMARY KEY,
#             vendor_name TEXT NOT NULL UNIQUE
#         );
#     """)
#     cur.execute(f"""
#         CREATE TABLE IF NOT EXISTS {TABLE_ADVISORIES} (
#             advisory_id TEXT PRIMARY KEY,
#             vendor_id INTEGER REFERENCES {TABLE_VENDORS}(vendor_id),
#             title TEXT,
#             severity TEXT,
#             initial_release_date DATE,
#             latest_update_date DATE,
#             advisory_url TEXT
#         );
#     """)
#     cur.execute(f"""
#         CREATE TABLE IF NOT EXISTS {TABLE_CVES} (
#             cve_id TEXT PRIMARY KEY,
#             description TEXT,
#             severity TEXT,
#             cvss_score NUMERIC(3,1),
#             cvss_vector TEXT,
#             initial_release_date DATE,
#             latest_update_date DATE,
#             reference_url TEXT
#         );
#     """)
#     cur.execute(f"""
#         CREATE TABLE IF NOT EXISTS {TABLE_ADV_CVE_MAP} (
#             advisory_id TEXT REFERENCES {TABLE_ADVISORIES}(advisory_id) ON DELETE CASCADE,
#             cve_id TEXT REFERENCES {TABLE_CVES}(cve_id) ON DELETE CASCADE,
#             PRIMARY KEY (advisory_id, cve_id)
#         );
#     """)
#     cur.execute(f"""
#         CREATE TABLE IF NOT EXISTS {TABLE_CVE_PRODUCT_MAP} (
#             qs_id SERIAL NOT NULL UNIQUE,
#             cve_id TEXT PRIMARY KEY REFERENCES {TABLE_CVES}(cve_id) ON DELETE CASCADE,
#             affected_products_cpe JSONB,
#             recommendations TEXT
#         );
#     """)
#     cur.execute(f"CREATE INDEX IF NOT EXISTS idx_cpe_gin ON {TABLE_CVE_PRODUCT_MAP} USING GIN (affected_products_cpe);")
#     conn.commit()
#     cur.close()

# # -------------------------
# # Vendor / Advisory / CVE Normalization
# # -------------------------
# def ensure_vendor(conn, vendor_name):
#     cur = conn.cursor()
#     cur.execute(f"SELECT vendor_id FROM {TABLE_VENDORS} WHERE vendor_name=%s", (vendor_name,))
#     row = cur.fetchone()
#     if row:
#         cur.close()
#         return row[0]
#     cur.execute(f"INSERT INTO {TABLE_VENDORS} (vendor_name) VALUES (%s) RETURNING vendor_id", (vendor_name,))
#     vendor_id = cur.fetchone()[0]
#     conn.commit()
#     cur.close()
#     return vendor_id

# def normalize_advisory(conn, raw, vendor_id):
#     cur = conn.cursor()

#     advisory_url = raw.get("advisory_url")
#     advisory_id = extract_advisory_id(advisory_url)
#     title = raw.get("advisory_title")
#     severity = None  # always null for advisory
#     initial_date = safe_date(raw.get("created_date"))
#     latest_date = safe_date(raw.get("latest_date"))

#     # Insert Advisory
#     cur.execute(f"""
#         INSERT INTO {TABLE_ADVISORIES}
#         (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url)
#         VALUES (%s,%s,%s,%s,%s,%s,%s)
#         ON CONFLICT (advisory_id) DO UPDATE SET
#             title=EXCLUDED.title,
#             severity=EXCLUDED.severity,
#             initial_release_date=EXCLUDED.initial_release_date,
#             latest_update_date=EXCLUDED.latest_update_date,
#             advisory_url=EXCLUDED.advisory_url
#     """, (advisory_id, vendor_id, title, severity, initial_date, latest_date, advisory_url))

#     # Process CVEs
#     for cve in raw.get("cve_details", []):
#         description = clean_text(cve.get("description"))
#         recommendations = " | ".join(cve.get("solutions_and_mitigations", []) or [])

#         sev, cvss_score, cvss_vector = parse_severity_block(cve.get("solutions_and_mitigations"))

#         for cve_id in cve.get("cve_ids", []):
#             ref_url = generate_cve_url(cve_id, recommendations)

#             # Insert CVE
#             cur.execute(f"""
#                 INSERT INTO {TABLE_CVES}
#                 (cve_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url)
#                 VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
#                 ON CONFLICT (cve_id) DO UPDATE SET
#                     description=EXCLUDED.description,
#                     severity=EXCLUDED.severity,
#                     cvss_score=EXCLUDED.cvss_score,
#                     cvss_vector=EXCLUDED.cvss_vector,
#                     initial_release_date=EXCLUDED.initial_release_date,
#                     latest_update_date=EXCLUDED.latest_update_date,
#                     reference_url=EXCLUDED.reference_url
#             """, (
#                 cve_id,
#                 description,
#                 sev,
#                 cvss_score,
#                 cvss_vector,
#                 None,  # CVE dates always NULL
#                 None,
#                 ref_url
#             ))

#             # Advisory ↔ CVE mapping
#             cur.execute(f"""
#                 INSERT INTO {TABLE_ADV_CVE_MAP} (advisory_id, cve_id)
#                 VALUES (%s,%s) ON CONFLICT DO NOTHING
#             """, (advisory_id, cve_id))

#             # CVE → Products mapping (always NULL for affected_products_cpe)
#             cur.execute(f"""
#                 INSERT INTO {TABLE_CVE_PRODUCT_MAP} (cve_id, affected_products_cpe, recommendations)
#                 VALUES (%s,%s,%s)
#                 ON CONFLICT (cve_id) DO UPDATE SET
#                     affected_products_cpe=EXCLUDED.affected_products_cpe,
#                     recommendations=EXCLUDED.recommendations
#             """, (
#                 cve_id,
#                 None,
#                 clean_text(recommendations)
#             ))

#     conn.commit()
#     cur.close()

# # -------------------------
# # Main
# # -------------------------
# def main():
#     conn = psycopg2.connect(**DB_CONFIG)
#     ensure_tables(conn)

#     vendor_name = "Elastic"
#     vendor_id = ensure_vendor(conn, vendor_name)

#     cur = conn.cursor()
#     cur.execute(f"SELECT staging_id, raw_data FROM {TABLE_STAGING} WHERE vendor_name=%s AND processed=false", (vendor_name,))
#     rows = cur.fetchall()

#     logger.info(f"Found {len(rows)} advisories to process for {vendor_name}")

#     for staging_id, raw_data in rows:
#         try:
#             normalize_advisory(conn, raw_data, vendor_id)
#             if MARK_PROCESSED:
#                 cur.execute(f"UPDATE {TABLE_STAGING} SET processed=true WHERE staging_id=%s", (staging_id,))
#             logger.info(f"[OK] Processed staging_id={staging_id}")
#         except Exception as e:
#             logger.error(f"[ERROR] Failed staging_id={staging_id}: {e}")

#     conn.commit()
#     cur.close()
#     conn.close()
#     logger.info("Normalization complete.")

# if __name__ == "__main__":
#     main()






# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-

# import os
# import re
# import logging
# import psycopg2
# from psycopg2.extras import Json
# from datetime import datetime
# from dotenv import load_dotenv
# from urllib.parse import urlparse

# # -------------------------
# # Config
# # -------------------------
# load_dotenv()
# DB_CONFIG = {
#     "host": os.getenv("DB_HOST", "localhost"),
#     "dbname": os.getenv("DB_NAME", "Elastic"),
#     "user": os.getenv("DB_USER", "postgres"),
#     "password": os.getenv("DB_PASS", ""),
#     "port": int(os.getenv("DB_PORT", 5432)),
# }

# # Control whether to mark staging rows as processed
# MARK_PROCESSED = True

# # -------------------------
# # Logging
# # -------------------------
# logging.basicConfig(level=logging.INFO, format="%(message)s")
# logger = logging.getLogger("elastic_normalizer")

# # -------------------------
# # Table Names
# # -------------------------
# TABLE_STAGING = "staging_table"
# TABLE_VENDORS = "vendors"
# TABLE_ADVISORIES = "advisories"
# TABLE_CVES = "cves"
# TABLE_ADV_CVE_MAP = "advisory_cves_map"
# TABLE_CVE_PRODUCT_MAP = "cve_product_map"

# # -------------------------
# # Helpers
# # -------------------------
# def safe_date(s):
#     if not s:
#         return None
#     for fmt in (
#         "%Y-%m-%d",
#         "%b %d, %Y",
#         "%B %d, %Y",
#         "%b %d %Y %I:%M %p",
#         "%b %d, %Y %I:%M %p",
#         "%B %d, %Y %I:%M %p",
#     ):
#         try:
#             return datetime.strptime(s.strip(), fmt).date()
#         except Exception:
#             continue
#     return None

# def extract_advisory_id(url):
#     try:
#         last = urlparse(url).path.strip("/").split("/")[-1]
#         return f"Elastic-{last}"
#     except Exception:
#         return None

# def generate_cve_url(cve_id, extra_text):
#     urls = []
#     if extra_text:
#         matches = re.findall(r"(https?://\S+)", str(extra_text))
#         urls.extend(matches)
#     if cve_id:
#         urls.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
#         urls.append(f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}")
#     return " | ".join(urls) if urls else None

# def clean_text(val):
#     if not val:
#         return None
#     val = re.sub(r"[\r\n\t]+", " ", str(val))
#     val = re.sub(r"\s{2,}", " ", val)
#     return val.strip()

# def parse_severity_block(block_list):
#     """Extract severity, score, and vector from severity text"""
#     sev, score, vector = None, None, None
#     if not block_list:
#         return sev, score, vector
#     text = " ".join(block_list)
#     m1 = re.search(r"\((Low|Medium|High|Critical)\)", text, re.IGNORECASE)
#     if m1:
#         sev = m1.group(1).capitalize()
#     m2 = re.search(r"CVSSv\d\.\d*:\s*([\d\.]+)", text)
#     if m2:
#         try:
#             score = float(m2.group(1))
#         except Exception:
#             pass
#     m3 = re.search(r"(CVSS:[\d\.]+/[A-Z:\/]+)", text)
#     if m3:
#         vector = m3.group(1)
#     return sev, score, vector

# # -------------------------
# # Ensure Tables
# # -------------------------
# def ensure_tables(conn):
#     cur = conn.cursor()
#     cur.execute(f"""
#         CREATE TABLE IF NOT EXISTS {TABLE_VENDORS} (
#             vendor_id SERIAL PRIMARY KEY,
#             vendor_name TEXT NOT NULL UNIQUE
#         );
#     """)
#     cur.execute(f"""
#         CREATE TABLE IF NOT EXISTS {TABLE_ADVISORIES} (
#             advisory_id TEXT PRIMARY KEY,
#             vendor_id INTEGER REFERENCES {TABLE_VENDORS}(vendor_id),
#             title TEXT,
#             severity TEXT,
#             initial_release_date DATE,
#             latest_update_date DATE,
#             advisory_url TEXT
#         );
#     """)
#     cur.execute(f"""
#         CREATE TABLE IF NOT EXISTS {TABLE_CVES} (
#             cve_id TEXT PRIMARY KEY,
#             description TEXT,
#             severity TEXT,
#             cvss_score NUMERIC(3,1),
#             cvss_vector TEXT,
#             initial_release_date DATE,
#             latest_update_date DATE,
#             reference_url TEXT
#         );
#     """)
#     cur.execute(f"""
#         CREATE TABLE IF NOT EXISTS {TABLE_ADV_CVE_MAP} (
#             advisory_id TEXT REFERENCES {TABLE_ADVISORIES}(advisory_id) ON DELETE CASCADE,
#             cve_id TEXT REFERENCES {TABLE_CVES}(cve_id) ON DELETE CASCADE,
#             PRIMARY KEY (advisory_id, cve_id)
#         );
#     """)
#     cur.execute(f"""
#         CREATE TABLE IF NOT EXISTS {TABLE_CVE_PRODUCT_MAP} (
#             qs_id SERIAL NOT NULL UNIQUE,
#             cve_id TEXT PRIMARY KEY REFERENCES {TABLE_CVES}(cve_id) ON DELETE CASCADE,
#             affected_products_cpe JSONB,
#             recommendations TEXT
#         );
#     """)
#     cur.execute(f"CREATE INDEX IF NOT EXISTS idx_cpe_gin ON {TABLE_CVE_PRODUCT_MAP} USING GIN (affected_products_cpe);")
#     conn.commit()
#     cur.close()

# # -------------------------
# # Vendor / Advisory / CVE Normalization
# # -------------------------
# def ensure_vendor(conn, vendor_name):
#     cur = conn.cursor()
#     cur.execute(f"SELECT vendor_id FROM {TABLE_VENDORS} WHERE vendor_name=%s", (vendor_name,))
#     row = cur.fetchone()
#     if row:
#         cur.close()
#         return row[0]
#     cur.execute(f"INSERT INTO {TABLE_VENDORS} (vendor_name) VALUES (%s) RETURNING vendor_id", (vendor_name,))
#     vendor_id = cur.fetchone()[0]
#     conn.commit()
#     cur.close()
#     return vendor_id

# def normalize_advisory(conn, raw, vendor_id):
#     cur = conn.cursor()
#     advisory_url = raw.get("advisory_url")
#     advisory_id = extract_advisory_id(advisory_url)
#     title = raw.get("advisory_title")
#     severity = None
#     initial_date = safe_date(raw.get("created_date"))
#     latest_date = safe_date(raw.get("latest_date"))

#     # Insert Advisory
#     cur.execute(f"""
#         INSERT INTO {TABLE_ADVISORIES}
#         (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url)
#         VALUES (%s,%s,%s,%s,%s,%s,%s)
#         ON CONFLICT (advisory_id) DO UPDATE SET
#             title=EXCLUDED.title,
#             severity=EXCLUDED.severity,
#             initial_release_date=EXCLUDED.initial_release_date,
#             latest_update_date=EXCLUDED.latest_update_date,
#             advisory_url=EXCLUDED.advisory_url
#     """, (advisory_id, vendor_id, title, severity, initial_date, latest_date, advisory_url))

#     # Process each CVE
#     for cve in raw.get("cve_details", []):
#         description = clean_text(cve.get("description"))
#         recommendations = " | ".join(cve.get("solutions_and_mitigations", []) or [])
#         sev, cvss_score, cvss_vector = parse_severity_block(cve.get("solutions_and_mitigations"))

#         for cve_id in cve.get("cve_ids", []):
#             ref_url = generate_cve_url(cve_id, recommendations)

#             # Insert CVE
#             cur.execute(f"""
#                 INSERT INTO {TABLE_CVES}
#                 (cve_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url)
#                 VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
#                 ON CONFLICT (cve_id) DO UPDATE SET
#                     description=EXCLUDED.description,
#                     severity=EXCLUDED.severity,
#                     cvss_score=EXCLUDED.cvss_score,
#                     cvss_vector=EXCLUDED.cvss_vector,
#                     initial_release_date=EXCLUDED.initial_release_date,
#                     latest_update_date=EXCLUDED.latest_update_date,
#                     reference_url=EXCLUDED.reference_url
#             """, (
#                 cve_id, description, sev, cvss_score, cvss_vector,
#                 None, None, ref_url
#             ))

#             # Advisory ↔ CVE mapping
#             cur.execute(f"""
#                 INSERT INTO {TABLE_ADV_CVE_MAP} (advisory_id, cve_id)
#                 VALUES (%s,%s) ON CONFLICT DO NOTHING
#             """, (advisory_id, cve_id))

#             # CVE → Products mapping
#             cur.execute(f"""
#                 INSERT INTO {TABLE_CVE_PRODUCT_MAP} (cve_id, affected_products_cpe, recommendations)
#                 VALUES (%s,%s,%s)
#                 ON CONFLICT (cve_id) DO UPDATE SET
#                     affected_products_cpe=EXCLUDED.affected_products_cpe,
#                     recommendations=EXCLUDED.recommendations
#             """, (cve_id, None, clean_text(recommendations)))

#     conn.commit()
#     cur.close()

# # -------------------------
# # Main
# # -------------------------
# def main():
#     conn = psycopg2.connect(**DB_CONFIG)
#     ensure_tables(conn)

#     vendor_name = "Elastic"
#     vendor_id = ensure_vendor(conn, vendor_name)

#     cur = conn.cursor()
#     cur.execute(f"SELECT staging_id, raw_data FROM {TABLE_STAGING} WHERE vendor_name=%s AND processed=false", (vendor_name,))
#     rows = cur.fetchall()

#     logger.info(f"Found {len(rows)} advisories to process for {vendor_name}")

#     for staging_id, raw_data in rows:
#         try:
#             normalize_advisory(conn, raw_data, vendor_id)
#             if MARK_PROCESSED:
#                 cur.execute(f"UPDATE {TABLE_STAGING} SET processed=true WHERE staging_id=%s", (staging_id,))
#             logger.info(f"[OK] Processed staging_id={staging_id}")
#         except Exception as e:
#             logger.error(f"[ERROR] Failed staging_id={staging_id}: {e}")

#     conn.commit()
#     cur.close()
#     conn.close()
#     logger.info("Normalization complete.")

# if __name__ == "__main__":
#     main()


# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-

# import os
# import re
# import logging
# import psycopg2
# from psycopg2.extras import Json
# from datetime import datetime
# from dotenv import load_dotenv
# from urllib.parse import urlparse

# # -------------------------
# # Config
# # -------------------------
# load_dotenv()
# DB_CONFIG = {
#     "host": os.getenv("DB_HOST", "localhost"),
#     "dbname": os.getenv("DB_NAME", "Elastic"),
#     "user": os.getenv("DB_USER", "postgres"),
#     "password": os.getenv("DB_PASS", ""),
#     "port": int(os.getenv("DB_PORT", 5432)),
# }

# # Control whether to mark staging rows as processed
# MARK_PROCESSED = True

# # -------------------------
# # Logging
# # -------------------------
# logging.basicConfig(level=logging.INFO, format="%(message)s")
# logger = logging.getLogger("elastic_normalizer")

# # -------------------------
# # Table Names
# # -------------------------
# TABLE_STAGING = "staging_table"
# TABLE_VENDORS = "vendors"
# TABLE_ADVISORIES = "advisories"
# TABLE_CVES = "cves"
# TABLE_ADV_CVE_MAP = "advisory_cves_map"
# TABLE_CVE_PRODUCT_MAP = "cve_product_map"

# # -------------------------
# # Helpers
# # -------------------------
# def safe_date(s):
#     if not s:
#         return None
#     for fmt in (
#         "%Y-%m-%d",
#         "%b %d, %Y",
#         "%B %d, %Y",
#         "%b %d %Y %I:%M %p",
#         "%b %d, %Y %I:%M %p",
#         "%B %d, %Y %I:%M %p",
#     ):
#         try:
#             return datetime.strptime(s.strip(), fmt).date()
#         except Exception:
#             continue
#     return None

# def extract_advisory_id(url):
#     try:
#         last = urlparse(url).path.strip("/").split("/")[-1]
#         return f"Elastic-{last}"
#     except Exception:
#         return None

# def generate_cve_url(cve_id, extra_text):
#     urls = []
#     if extra_text:
#         matches = re.findall(r"(https?://\S+)", str(extra_text))
#         urls.extend(matches)
#     if cve_id:
#         urls.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
#         urls.append(f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}")
#     return " | ".join(urls) if urls else None

# def clean_text(val):
#     if not val:
#         return None
#     val = re.sub(r"[\r\n\t]+", " ", str(val))
#     val = re.sub(r"\s{2,}", " ", val)
#     return val.strip()

# def parse_severity_block(block_list):
#     """Extract severity, CVSS score, and vector string from severity text robustly."""
#     sev, score, vector = None, None, None
#     if not block_list:
#         return sev, score, vector

#     text = " ".join(block_list).strip()

#     # --- Severity inside parentheses ---
#     m_sev = re.search(r"\((Low|Medium|High|Critical)\)", text, re.IGNORECASE)
#     if m_sev:
#         sev = m_sev.group(1).capitalize()

#     # --- CVSS score: try multiple patterns ---
#     # 1. CVSSv3: 8.8
#     m_score1 = re.search(r"CVSSv\d+(\.\d+)?:\s*([\d\.]+)", text)
#     # 2. Just ": 5.3" (after "Severity:" or standalone)
#     m_score2 = re.search(r":\s*([\d\.]+)", text)
#     # 3. Sometimes written without space e.g., 5.3(Medium)
#     m_score3 = re.search(r"(\d\.\d+)\s*\(", text)

#     if m_score1:
#         score = float(m_score1.group(2))
#     elif m_score2:
#         score = float(m_score2.group(1))
#     elif m_score3:
#         score = float(m_score3.group(1))

#     # --- CVSS vector ---
#     # Vector may start with "CVSS:" or directly after "-"
#     m_vector = re.search(r"-\s*(CVSS:[\d\.]+/[A-Z:\/]+|[A-Z:\/]+)", text)
#     if m_vector:
#         vector = m_vector.group(1).strip()

#     return sev, score, vector
# # -------------------------
# # Ensure Tables
# # -------------------------
# def ensure_tables(conn):
#     cur = conn.cursor()
#     cur.execute(f"""
#         CREATE TABLE IF NOT EXISTS {TABLE_VENDORS} (
#             vendor_id SERIAL PRIMARY KEY,
#             vendor_name TEXT NOT NULL UNIQUE
#         );
#     """)
#     cur.execute(f"""
#         CREATE TABLE IF NOT EXISTS {TABLE_ADVISORIES} (
#             advisory_id TEXT PRIMARY KEY,
#             vendor_id INTEGER REFERENCES {TABLE_VENDORS}(vendor_id),
#             title TEXT,
#             severity TEXT,
#             initial_release_date DATE,
#             latest_update_date DATE,
#             advisory_url TEXT
#         );
#     """)
#     cur.execute(f"""
#         CREATE TABLE IF NOT EXISTS {TABLE_CVES} (
#             cve_id TEXT PRIMARY KEY,
#             description TEXT,
#             severity TEXT,
#             cvss_score NUMERIC(3,1),
#             cvss_vector TEXT,
#             initial_release_date DATE,
#             latest_update_date DATE,
#             reference_url TEXT
#         );
#     """)
#     cur.execute(f"""
#         CREATE TABLE IF NOT EXISTS {TABLE_ADV_CVE_MAP} (
#             advisory_id TEXT REFERENCES {TABLE_ADVISORIES}(advisory_id) ON DELETE CASCADE,
#             cve_id TEXT REFERENCES {TABLE_CVES}(cve_id) ON DELETE CASCADE,
#             PRIMARY KEY (advisory_id, cve_id)
#         );
#     """)
#     cur.execute(f"""
#         CREATE TABLE IF NOT EXISTS {TABLE_CVE_PRODUCT_MAP} (
#             qs_id SERIAL NOT NULL UNIQUE,
#             cve_id TEXT PRIMARY KEY REFERENCES {TABLE_CVES}(cve_id) ON DELETE CASCADE,
#             affected_products_cpe JSONB,
#             recommendations TEXT
#         );
#     """)
#     cur.execute(f"CREATE INDEX IF NOT EXISTS idx_cpe_gin ON {TABLE_CVE_PRODUCT_MAP} USING GIN (affected_products_cpe);")
#     conn.commit()
#     cur.close()

# # -------------------------
# # Vendor / Advisory / CVE Normalization
# # -------------------------
# def ensure_vendor(conn, vendor_name):
#     cur = conn.cursor()
#     cur.execute(f"SELECT vendor_id FROM {TABLE_VENDORS} WHERE vendor_name=%s", (vendor_name,))
#     row = cur.fetchone()
#     if row:
#         cur.close()
#         return row[0]
#     cur.execute(f"INSERT INTO {TABLE_VENDORS} (vendor_name) VALUES (%s) RETURNING vendor_id", (vendor_name,))
#     vendor_id = cur.fetchone()[0]
#     conn.commit()
#     cur.close()
#     return vendor_id

# def normalize_advisory(conn, raw, vendor_id):
#     cur = conn.cursor()
#     advisory_url = raw.get("advisory_url")
#     advisory_id = extract_advisory_id(advisory_url)
#     title = raw.get("advisory_title")
#     severity = None
#     initial_date = safe_date(raw.get("created_date"))
#     latest_date = safe_date(raw.get("latest_date"))

#     # Insert Advisory
#     cur.execute(f"""
#         INSERT INTO {TABLE_ADVISORIES}
#         (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url)
#         VALUES (%s,%s,%s,%s,%s,%s,%s)
#         ON CONFLICT (advisory_id) DO UPDATE SET
#             title=EXCLUDED.title,
#             severity=EXCLUDED.severity,
#             initial_release_date=EXCLUDED.initial_release_date,
#             latest_update_date=EXCLUDED.latest_update_date,
#             advisory_url=EXCLUDED.advisory_url
#     """, (advisory_id, vendor_id, title, severity, initial_date, latest_date, advisory_url))

#     # Process each CVE
#     for cve in raw.get("cve_details", []):
#         description = clean_text(cve.get("description"))
#         recommendations = " | ".join(cve.get("solutions_and_mitigations", []) or [])
#         sev, cvss_score, cvss_vector = parse_severity_block(cve.get("severity") or cve.get("solutions_and_mitigations"))

#         for cve_id in cve.get("cve_ids", []):
#             ref_url = generate_cve_url(cve_id, recommendations)

#             # Insert CVE
#             cur.execute(f"""
#                 INSERT INTO {TABLE_CVES}
#                 (cve_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url)
#                 VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
#                 ON CONFLICT (cve_id) DO UPDATE SET
#                     description=EXCLUDED.description,
#                     severity=EXCLUDED.severity,
#                     cvss_score=EXCLUDED.cvss_score,
#                     cvss_vector=EXCLUDED.cvss_vector,
#                     initial_release_date=EXCLUDED.initial_release_date,
#                     latest_update_date=EXCLUDED.latest_update_date,
#                     reference_url=EXCLUDED.reference_url
#             """, (
#                 cve_id, description, sev, cvss_score, cvss_vector,
#                 None, None, ref_url
#             ))

#             # Advisory ↔ CVE mapping
#             cur.execute(f"""
#                 INSERT INTO {TABLE_ADV_CVE_MAP} (advisory_id, cve_id)
#                 VALUES (%s,%s) ON CONFLICT DO NOTHING
#             """, (advisory_id, cve_id))

#             # CVE → Products mapping
#             cur.execute(f"""
#                 INSERT INTO {TABLE_CVE_PRODUCT_MAP} (cve_id, affected_products_cpe, recommendations)
#                 VALUES (%s,%s,%s)
#                 ON CONFLICT (cve_id) DO UPDATE SET
#                     affected_products_cpe=EXCLUDED.affected_products_cpe,
#                     recommendations=EXCLUDED.recommendations
#             """, (cve_id, None, clean_text(recommendations)))

#     conn.commit()
#     cur.close()

# # -------------------------
# # Main
# # -------------------------
# def main():
#     conn = psycopg2.connect(**DB_CONFIG)
#     ensure_tables(conn)

#     vendor_name = "Elastic"
#     vendor_id = ensure_vendor(conn, vendor_name)

#     cur = conn.cursor()
#     cur.execute(f"SELECT staging_id, raw_data FROM {TABLE_STAGING} WHERE vendor_name=%s AND processed=false", (vendor_name,))
#     rows = cur.fetchall()

#     logger.info(f"Found {len(rows)} advisories to process for {vendor_name}")

#     for staging_id, raw_data in rows:
#         try:
#             normalize_advisory(conn, raw_data, vendor_id)
#             if MARK_PROCESSED:
#                 cur.execute(f"UPDATE {TABLE_STAGING} SET processed=true WHERE staging_id=%s", (staging_id,))
#             logger.info(f"[OK] Processed staging_id={staging_id}")
#         except Exception as e:
#             logger.error(f"[ERROR] Failed staging_id={staging_id}: {e}")

#     conn.commit()
#     cur.close()
#     conn.close()
#     logger.info("Normalization complete.")

# if __name__ == "__main__":
#     main()



# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-

# import os
# import re
# import logging
# import psycopg2
# from psycopg2.extras import Json
# from datetime import datetime
# from dotenv import load_dotenv
# from urllib.parse import urlparse

# # -------------------------
# # Config
# # -------------------------
# load_dotenv()
# DB_CONFIG = {
#     "host": os.getenv("DB_HOST", "localhost"),
#     "dbname": os.getenv("DB_NAME", "Elastic"),
#     "user": os.getenv("DB_USER", "postgres"),
#     "password": os.getenv("DB_PASS", ""),
#     "port": int(os.getenv("DB_PORT", 5432)),
# }

# # Control whether to mark staging rows as processed
# MARK_PROCESSED = True

# # -------------------------
# # Logging
# # -------------------------
# logging.basicConfig(level=logging.INFO, format="%(message)s")
# logger = logging.getLogger("elastic_normalizer")

# # -------------------------
# # Table Names
# # -------------------------
# TABLE_STAGING = "staging_table"
# TABLE_VENDORS = "vendors"
# TABLE_ADVISORIES = "advisories"
# TABLE_CVES = "cves"
# TABLE_ADV_CVE_MAP = "advisory_cves_map"
# TABLE_CVE_PRODUCT_MAP = "cve_product_map"

# # -------------------------
# # Helpers
# # -------------------------
# def safe_date(s):
#     if not s:
#         return None
#     for fmt in (
#         "%Y-%m-%d",
#         "%b %d, %Y",
#         "%B %d, %Y",
#         "%b %d %Y %I:%M %p",
#         "%b %d, %Y %I:%M %p",
#         "%B %d, %Y %I:%M %p",
#     ):
#         try:
#             return datetime.strptime(s.strip(), fmt).date()
#         except Exception:
#             continue
#     return None

# def extract_advisory_id(url):
#     try:
#         last = urlparse(url).path.strip("/").split("/")[-1]
#         return f"Elastic-{last}"
#     except Exception:
#         return None

# def generate_cve_url(cve_id, extra_text):
#     urls = []
#     if extra_text:
#         matches = re.findall(r"(https?://\S+)", str(extra_text))
#         urls.extend(matches)
#     if cve_id:
#         urls.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
#         urls.append(f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}")
#     return " | ".join(urls) if urls else None

# def clean_text(val):
#     if not val:
#         return None
#     val = re.sub(r"[\r\n\t]+", " ", str(val))
#     val = re.sub(r"\s{2,}", " ", val)
#     return val.strip()

# def parse_severity_block(block_list):
#     """Extract severity, CVSS score, and vector string from severity text robustly."""
#     sev, score, vector = None, None, None
#     if not block_list:
#         return sev, score, vector

#     text = " ".join(block_list).strip()

#     # --- Severity inside parentheses ---
#     m_sev = re.search(r"\((Low|Medium|High|Critical)\)", text, re.IGNORECASE)
#     if m_sev:
#         sev = m_sev.group(1).capitalize()

#     # --- CVSS score: try multiple patterns ---
#     m_score1 = re.search(r"CVSSv\d+(\.\d+)?:\s*([\d\.]+)", text)  # CVSSv3: 8.8
#     m_score2 = re.search(r":\s*([\d\.]+)", text)                  # : 5.3
#     m_score3 = re.search(r"(\d\.\d+)\s*\(", text)                 # 4.3(Medium)

#     if m_score1:
#         score = float(m_score1.group(2))
#     elif m_score2:
#         score = float(m_score2.group(1))
#     elif m_score3:
#         score = float(m_score3.group(1))

#     # --- CVSS vector ---
#     m_vector = re.search(r"-\s*(CVSS:[\d\.]+/[A-Z:\/]+|[A-Z:\/]+)", text)
#     if m_vector:
#         vector = m_vector.group(1).strip()

#     return sev, score, vector

# # -------------------------
# # Ensure Tables
# # -------------------------
# def ensure_tables(conn):
#     cur = conn.cursor()
#     cur.execute(f"""
#         CREATE TABLE IF NOT EXISTS {TABLE_VENDORS} (
#             vendor_id SERIAL PRIMARY KEY,
#             vendor_name TEXT NOT NULL UNIQUE
#         );
#     """)
#     cur.execute(f"""
#         CREATE TABLE IF NOT EXISTS {TABLE_ADVISORIES} (
#             advisory_id TEXT PRIMARY KEY,
#             vendor_id INTEGER REFERENCES {TABLE_VENDORS}(vendor_id),
#             title TEXT,
#             severity TEXT,
#             initial_release_date DATE,
#             latest_update_date DATE,
#             advisory_url TEXT
#         );
#     """)
#     cur.execute(f"""
#         CREATE TABLE IF NOT EXISTS {TABLE_CVES} (
#             cve_id TEXT PRIMARY KEY,
#             description TEXT,
#             severity TEXT,
#             cvss_score NUMERIC(3,1),
#             cvss_vector TEXT,
#             initial_release_date DATE,
#             latest_update_date DATE,
#             reference_url TEXT
#         );
#     """)
#     cur.execute(f"""
#         CREATE TABLE IF NOT EXISTS {TABLE_ADV_CVE_MAP} (
#             advisory_id TEXT REFERENCES {TABLE_ADVISORIES}(advisory_id) ON DELETE CASCADE,
#             cve_id TEXT REFERENCES {TABLE_CVES}(cve_id) ON DELETE CASCADE,
#             PRIMARY KEY (advisory_id, cve_id)
#         );
#     """)
#     cur.execute(f"""
#         CREATE TABLE IF NOT EXISTS {TABLE_CVE_PRODUCT_MAP} (
#             qs_id SERIAL NOT NULL UNIQUE,
#             cve_id TEXT PRIMARY KEY REFERENCES {TABLE_CVES}(cve_id) ON DELETE CASCADE,
#             affected_products_cpe JSONB,
#             recommendations TEXT
#         );
#     """)
#     cur.execute(f"CREATE INDEX IF NOT EXISTS idx_cpe_gin ON {TABLE_CVE_PRODUCT_MAP} USING GIN (affected_products_cpe);")
#     conn.commit()
#     cur.close()

# # -------------------------
# # Vendor / Advisory / CVE Normalization
# # -------------------------
# def ensure_vendor(conn, vendor_name):
#     cur = conn.cursor()
#     cur.execute(f"SELECT vendor_id FROM {TABLE_VENDORS} WHERE vendor_name=%s", (vendor_name,))
#     row = cur.fetchone()
#     if row:
#         cur.close()
#         return row[0]
#     cur.execute(f"INSERT INTO {TABLE_VENDORS} (vendor_name) VALUES (%s) RETURNING vendor_id", (vendor_name,))
#     vendor_id = cur.fetchone()[0]
#     conn.commit()
#     cur.close()
#     return vendor_id

# def normalize_advisory(conn, raw, vendor_id):
#     cur = conn.cursor()
#     advisory_url = raw.get("advisory_url")
#     advisory_id = extract_advisory_id(advisory_url)
#     title = raw.get("advisory_title")
#     severity = None
#     initial_date = safe_date(raw.get("created_date"))
#     latest_date = safe_date(raw.get("latest_date"))

#     # Insert Advisory
#     cur.execute(f"""
#         INSERT INTO {TABLE_ADVISORIES}
#         (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url)
#         VALUES (%s,%s,%s,%s,%s,%s,%s)
#         ON CONFLICT (advisory_id) DO UPDATE SET
#             title=EXCLUDED.title,
#             severity=EXCLUDED.severity,
#             initial_release_date=EXCLUDED.initial_release_date,
#             latest_update_date=EXCLUDED.latest_update_date,
#             advisory_url=EXCLUDED.advisory_url
#     """, (advisory_id, vendor_id, title, severity, initial_date, latest_date, advisory_url))

#     # Process each CVE
#     for cve in raw.get("cve_details", []):
#         description = clean_text(cve.get("description"))
#         # Use title if description is null or short
#         if not description or len(description) < 50:
#             description = clean_text(cve.get("title"))

#         recommendations = " | ".join(cve.get("solutions_and_mitigations", []) or [])

#         sev, cvss_score, cvss_vector = parse_severity_block(
#             cve.get("severity") or cve.get("severity_data") or cve.get("solutions_and_mitigations")
#         )

#         for cve_id in cve.get("cve_ids", []):
#             ref_url = generate_cve_url(cve_id, recommendations)

#             # Insert CVE
#             cur.execute(f"""
#                 INSERT INTO {TABLE_CVES}
#                 (cve_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url)
#                 VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
#                 ON CONFLICT (cve_id) DO UPDATE SET
#                     description=EXCLUDED.description,
#                     severity=EXCLUDED.severity,
#                     cvss_score=EXCLUDED.cvss_score,
#                     cvss_vector=EXCLUDED.cvss_vector,
#                     initial_release_date=EXCLUDED.initial_release_date,
#                     latest_update_date=EXCLUDED.latest_update_date,
#                     reference_url=EXCLUDED.reference_url
#             """, (
#                 cve_id, description, sev, cvss_score, cvss_vector,
#                 None, None, ref_url
#             ))

#             # Advisory ↔ CVE mapping
#             cur.execute(f"""
#                 INSERT INTO {TABLE_ADV_CVE_MAP} (advisory_id, cve_id)
#                 VALUES (%s,%s) ON CONFLICT DO NOTHING
#             """, (advisory_id, cve_id))

#             # CVE → Products mapping
#             cur.execute(f"""
#                 INSERT INTO {TABLE_CVE_PRODUCT_MAP} (cve_id, affected_products_cpe, recommendations)
#                 VALUES (%s,%s,%s)
#                 ON CONFLICT (cve_id) DO UPDATE SET
#                     affected_products_cpe=EXCLUDED.affected_products_cpe,
#                     recommendations=EXCLUDED.recommendations
#             """, (cve_id, None, clean_text(recommendations)))

#     conn.commit()
#     cur.close()

# # -------------------------
# # Main
# # -------------------------
# def main():
#     conn = psycopg2.connect(**DB_CONFIG)
#     ensure_tables(conn)

#     vendor_name = "Elastic"
#     vendor_id = ensure_vendor(conn, vendor_name)

#     cur = conn.cursor()
#     cur.execute(f"SELECT staging_id, raw_data FROM {TABLE_STAGING} WHERE vendor_name=%s AND processed=false", (vendor_name,))
#     rows = cur.fetchall()

#     logger.info(f"Found {len(rows)} advisories to process for {vendor_name}")

#     for staging_id, raw_data in rows:
#         try:
#             normalize_advisory(conn, raw_data, vendor_id)
#             if MARK_PROCESSED:
#                 cur.execute(f"UPDATE {TABLE_STAGING} SET processed=true WHERE staging_id=%s", (staging_id,))
#             logger.info(f"[OK] Processed staging_id={staging_id}")
#         except Exception as e:
#             logger.error(f"[ERROR] Failed staging_id={staging_id}: {e}")

#     conn.commit()
#     cur.close()
#     conn.close()
#     logger.info("Normalization complete.")

# if __name__ == "__main__":
#     main()





# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-

# import os
# import re
# import logging
# import psycopg2
# from psycopg2.extras import Json
# from datetime import datetime
# from dotenv import load_dotenv
# from urllib.parse import urlparse

# # -------------------------
# # Config
# # -------------------------
# load_dotenv()
# DB_CONFIG = {
#     "host": os.getenv("DB_HOST", "localhost"),
#     "dbname": os.getenv("DB_NAME", "Elastic"),
#     "user": os.getenv("DB_USER", "postgres"),
#     "password": os.getenv("DB_PASS", ""),
#     "port": int(os.getenv("DB_PORT", 5432)),
# }

# MARK_PROCESSED = True

# # -------------------------
# # Logging
# # -------------------------
# logging.basicConfig(level=logging.INFO, format="%(message)s")
# logger = logging.getLogger("elastic_normalizer")

# # -------------------------
# # Table Names
# # -------------------------
# TABLE_STAGING = "staging_table"
# TABLE_VENDORS = "vendors"
# TABLE_ADVISORIES = "advisories"
# TABLE_CVES = "cves"
# TABLE_ADV_CVE_MAP = "advisory_cves_map"
# TABLE_CVE_PRODUCT_MAP = "cve_product_map"

# # -------------------------
# # Helpers
# # -------------------------
# def safe_date(s):
#     if not s:
#         return None
#     for fmt in (
#         "%Y-%m-%d",
#         "%b %d, %Y",
#         "%B %d, %Y",
#         "%b %d %Y %I:%M %p",
#         "%b %d, %Y %I:%M %p",
#         "%B %d, %Y %I:%M %p",
#     ):
#         try:
#             return datetime.strptime(s.strip(), fmt).date()
#         except Exception:
#             continue
#     return None

# def extract_advisory_id(url):
#     try:
#         last = urlparse(url).path.strip("/").split("/")[-1]
#         return f"Elastic-{last}"
#     except Exception:
#         return None

# def generate_cve_url(cve_id, extra_text):
#     urls = []
#     if extra_text:
#         matches = re.findall(r"(https?://\S+)", str(extra_text))
#         urls.extend(matches)
#     if cve_id:
#         urls.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
#         urls.append(f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}")
#     return " | ".join(urls) if urls else None

# def clean_text(val):
#     if not val:
#         return None
#     val = re.sub(r"[\r\n\t]+", " ", str(val))
#     val = re.sub(r"\s{2,}", " ", val)
#     return val.strip()
# def parse_severity_block(block_list):
#     """Extract severity, CVSS score, and vector string robustly using multiple patterns."""
#     if not block_list:
#         return None, None, None

#     text = " ".join(block_list).strip()

#     # --- Severity ---
#     sev_candidates = []
#     m_paren = re.findall(r"\((Low|Medium|High|Critical)\)", text, re.IGNORECASE)
#     sev_candidates.extend([x.capitalize() for x in m_paren])
#     for keyword in ["Critical", "High", "Medium", "Low"]:
#         if re.search(rf"\b{keyword}\b", text, re.IGNORECASE):
#             sev_candidates.append(keyword)
#     sev = sev_candidates[0] if sev_candidates else None

#     # --- CVSS Scores ---
#     score_candidates = []
#     patterns = [
#         r"CVSSv\d+(\.\d+)?:\s*([\d\.]+)",          # CVSSv3: 8.8
#         r"CVSS Score[:\s]+([\d\.]+)",              # CVSS Score: 7.2
#         r"Score[:\s]+([\d\.]+)",                   # Score 7.2
#         r":\s*([\d\.]+)\s*\(?",                    # : 5.3 (Medium)
#         r"(\d\.\d+)\s*\(",                          # 5.3(Medium)
#         r"^(\d\.\d+)\s*$",                         # bare number
#     ]
#     for pat in patterns:
#         for m in re.findall(pat, text):
#             try:
#                 score_candidates.append(float(m))
#             except:
#                 continue
#     cvss_score = max(score_candidates) if score_candidates else None

#     # --- CVSS Vector ---
#     vector_candidates = []
#     vec_patterns = [
#         r"CVSS:[\d\.]+/[A-Z:\/]+",                     # CVSS:3.1/AV:N/AC:L/...
#         r"AV:[A-Z]/AC:[A-Z]/PR:[A-Z]/UI:[A-Z]/S:[A-Z]/C:[A-Z]/I:[A-Z]/A:[A-Z]"  # direct vector
#     ]
#     for pat in vec_patterns:
#         vector_candidates.extend(re.findall(pat, text))
#     cvss_vector = vector_candidates[0] if vector_candidates else None

#     return sev, cvss_score, cvss_vector

# # -------------------------
# # Ensure Tables
# # -------------------------
# def ensure_tables(conn):
#     cur = conn.cursor()
#     cur.execute(f"""
#         CREATE TABLE IF NOT EXISTS {TABLE_VENDORS} (
#             vendor_id SERIAL PRIMARY KEY,
#             vendor_name TEXT NOT NULL UNIQUE
#         );
#     """)
#     cur.execute(f"""
#         CREATE TABLE IF NOT EXISTS {TABLE_ADVISORIES} (
#             advisory_id TEXT PRIMARY KEY,
#             vendor_id INTEGER REFERENCES {TABLE_VENDORS}(vendor_id),
#             title TEXT,
#             severity TEXT,
#             initial_release_date DATE,
#             latest_update_date DATE,
#             advisory_url TEXT
#         );
#     """)
#     cur.execute(f"""
#         CREATE TABLE IF NOT EXISTS {TABLE_CVES} (
#             cve_id TEXT PRIMARY KEY,
#             description TEXT,
#             severity TEXT,
#             cvss_score NUMERIC(3,1),
#             cvss_vector TEXT,
#             initial_release_date DATE,
#             latest_update_date DATE,
#             reference_url TEXT
#         );
#     """)
#     cur.execute(f"""
#         CREATE TABLE IF NOT EXISTS {TABLE_ADV_CVE_MAP} (
#             advisory_id TEXT REFERENCES {TABLE_ADVISORIES}(advisory_id) ON DELETE CASCADE,
#             cve_id TEXT REFERENCES {TABLE_CVES}(cve_id) ON DELETE CASCADE,
#             PRIMARY KEY (advisory_id, cve_id)
#         );
#     """)
#     cur.execute(f"""
#         CREATE TABLE IF NOT EXISTS {TABLE_CVE_PRODUCT_MAP} (
#             qs_id SERIAL NOT NULL UNIQUE,
#             cve_id TEXT PRIMARY KEY REFERENCES {TABLE_CVES}(cve_id) ON DELETE CASCADE,
#             affected_products_cpe JSONB,
#             recommendations TEXT
#         );
#     """)
#     cur.execute(f"CREATE INDEX IF NOT EXISTS idx_cpe_gin ON {TABLE_CVE_PRODUCT_MAP} USING GIN (affected_products_cpe);")
#     conn.commit()
#     cur.close()

# # -------------------------
# # Vendor / Advisory / CVE Normalization
# # -------------------------
# def ensure_vendor(conn, vendor_name):
#     cur = conn.cursor()
#     cur.execute(f"SELECT vendor_id FROM {TABLE_VENDORS} WHERE vendor_name=%s", (vendor_name,))
#     row = cur.fetchone()
#     if row:
#         cur.close()
#         return row[0]
#     cur.execute(f"INSERT INTO {TABLE_VENDORS} (vendor_name) VALUES (%s) RETURNING vendor_id", (vendor_name,))
#     vendor_id = cur.fetchone()[0]
#     conn.commit()
#     cur.close()
#     return vendor_id

# def normalize_advisory(conn, raw, vendor_id):
#     cur = conn.cursor()
#     advisory_url = raw.get("advisory_url")
#     advisory_id = extract_advisory_id(advisory_url)
#     title = raw.get("advisory_title")
#     severity = None
#     initial_date = safe_date(raw.get("created_date"))
#     latest_date = safe_date(raw.get("latest_date"))

#     # Insert Advisory
#     cur.execute(f"""
#         INSERT INTO {TABLE_ADVISORIES}
#         (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url)
#         VALUES (%s,%s,%s,%s,%s,%s,%s)
#         ON CONFLICT (advisory_id) DO UPDATE SET
#             title=EXCLUDED.title,
#             severity=EXCLUDED.severity,
#             initial_release_date=EXCLUDED.initial_release_date,
#             latest_update_date=EXCLUDED.latest_update_date,
#             advisory_url=EXCLUDED.advisory_url
#     """, (advisory_id, vendor_id, title, severity, initial_date, latest_date, advisory_url))

#     # Process each CVE
#     for cve in raw.get("cve_details", []):
#         description = clean_text(cve.get("description"))
#         if not description or len(description) < 50:
#             description = clean_text(cve.get("title"))

#         recommendations = " | ".join(cve.get("solutions_and_mitigations", []) or [])

#         sev, cvss_score, cvss_vector = parse_severity_block(
#             cve.get("severity") or cve.get("severity_data") or cve.get("solutions_and_mitigations")
#         )

#         for cve_id in cve.get("cve_ids", []):
#             ref_url = generate_cve_url(cve_id, recommendations)

#             # Insert CVE
#             cur.execute(f"""
#                 INSERT INTO {TABLE_CVES}
#                 (cve_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url)
#                 VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
#                 ON CONFLICT (cve_id) DO UPDATE SET
#                     description=EXCLUDED.description,
#                     severity=EXCLUDED.severity,
#                     cvss_score=EXCLUDED.cvss_score,
#                     cvss_vector=EXCLUDED.cvss_vector,
#                     initial_release_date=EXCLUDED.initial_release_date,
#                     latest_update_date=EXCLUDED.latest_update_date,
#                     reference_url=EXCLUDED.reference_url
#             """, (
#                 cve_id, description, sev, cvss_score, cvss_vector,
#                 None, None, ref_url
#             ))

#             # Advisory ↔ CVE mapping
#             cur.execute(f"""
#                 INSERT INTO {TABLE_ADV_CVE_MAP} (advisory_id, cve_id)
#                 VALUES (%s,%s) ON CONFLICT DO NOTHING
#             """, (advisory_id, cve_id))

#             # CVE → Products mapping
#             cur.execute(f"""
#                 INSERT INTO {TABLE_CVE_PRODUCT_MAP} (cve_id, affected_products_cpe, recommendations)
#                 VALUES (%s,%s,%s)
#                 ON CONFLICT (cve_id) DO UPDATE SET
#                     affected_products_cpe=EXCLUDED.affected_products_cpe,
#                     recommendations=EXCLUDED.recommendations
#             """, (cve_id, None, clean_text(recommendations)))

#     conn.commit()
#     cur.close()

# # -------------------------
# # Main
# # -------------------------
# def main():
#     conn = psycopg2.connect(**DB_CONFIG)
#     ensure_tables(conn)

#     vendor_name = "Elastic"
#     vendor_id = ensure_vendor(conn, vendor_name)

#     cur = conn.cursor()
#     cur.execute(f"SELECT staging_id, raw_data FROM {TABLE_STAGING} WHERE vendor_name=%s AND processed=false", (vendor_name,))
#     rows = cur.fetchall()

#     logger.info(f"Found {len(rows)} advisories to process for {vendor_name}")

#     for staging_id, raw_data in rows:
#         try:
#             normalize_advisory(conn, raw_data, vendor_id)
#             if MARK_PROCESSED:
#                 cur.execute(f"UPDATE {TABLE_STAGING} SET processed=true WHERE staging_id=%s", (staging_id,))
#             logger.info(f"[OK] Processed staging_id={staging_id}")
#         except Exception as e:
#             logger.error(f"[ERROR] Failed staging_id={staging_id}: {e}")

#     conn.commit()
#     cur.close()
#     conn.close()
#     logger.info("Normalization complete.")

# if __name__ == "__main__":
#     main()


#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import logging
import psycopg2
from psycopg2.extras import Json
from datetime import datetime
from dotenv import load_dotenv
from urllib.parse import urlparse

# -------------------------
# Config
# -------------------------
load_dotenv()
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "dbname": os.getenv("DB_NAME", "Elastic"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASS", ""),
    "port": int(os.getenv("DB_PORT", 5432)),
}

MARK_PROCESSED = True

# -------------------------
# Logging
# -------------------------
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("elastic_normalizer")

# -------------------------
# Table Names
# -------------------------
TABLE_STAGING = "staging_table"
TABLE_VENDORS = "vendors"
TABLE_ADVISORIES = "advisories"
TABLE_CVES = "cves"
TABLE_ADV_CVE_MAP = "advisory_cves_map"
TABLE_CVE_PRODUCT_MAP = "cve_product_map"

# -------------------------
# Helpers
# -------------------------
def safe_date(s):
    if not s:
        return None
    for fmt in (
        "%Y-%m-%d", "%b %d, %Y", "%B %d, %Y",
        "%b %d %Y %I:%M %p", "%b %d, %Y %I:%M %p", "%B %d, %Y %I:%M %p",
    ):
        try:
            return datetime.strptime(s.strip(), fmt).date()
        except:
            continue
    return None

def extract_advisory_id(url):
    try:
        last = urlparse(url).path.strip("/").split("/")[-1]
        return f"Elastic-{last}"
    except:
        return None

def generate_cve_url(cve_id, extra_text):
    urls = []
    if extra_text:
        matches = re.findall(r"(https?://\S+)", str(extra_text))
        urls.extend(matches)
    if cve_id:
        urls.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
        urls.append(f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}")
    return " | ".join(urls) if urls else None

def clean_text(val):
    if not val:
        return None
    val = re.sub(r"[\r\n\t]+", " ", str(val))
    val = re.sub(r"\s{2,}", " ", val)
    return val.strip()

# # -------------------------
# # Severity / CVSS parser
# # -------------------------
# SEVERITY_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Moderate": 3, "Low": 2, "Informational": 1}

# def parse_severity_block(block):
#     """Extract severity, CVSS score, and vector string robustly."""
#     if not block:
#         return None, None, None

#     # If block is a list, join into string; else, keep string
#     if isinstance(block, list):
#         text = " ".join(str(b) for b in block).strip()
#     else:
#         text = str(block).strip()

#     # --- Severity ---
#     sev_candidates = []
#     m_paren = re.findall(r"\((Low|Medium|High|Critical|Moderate|Informational)\)", text, re.IGNORECASE)
#     sev_candidates.extend([x.capitalize() for x in m_paren])
#     # Also check for keywords in plain text
#     for keyword in ["Critical", "High", "Medium", "Low", "Moderate", "Informational"]:
#         if re.search(rf"\b{keyword}\b", text, re.IGNORECASE):
#             sev_candidates.append(keyword)
#     sev = sev_candidates[0] if sev_candidates else None

#     # --- CVSS score ---
#     score_candidates = []
#     patterns = [
#         r"CVSSv\d+(\.\d+)?:\s*([\d\.]+)",          # CVSSv3: 8.8
#         r"CVSS Score[:\s]+([\d\.]+)",              # CVSS Score: 7.2
#         r"Score[:\s]+([\d\.]+)",                   # Score 7.2
#         r":\s*([\d\.]+)\s*\(?",                    # : 5.3 (Medium)
#         r"(\d\.\d+)\s*\(",                          # 5.3(Medium)
#         r"^(\d\.\d+)\s*$",                         # bare number
#     ]
#     for pat in patterns:
#         for m in re.findall(pat, text):
#             try:
#                 score_candidates.append(float(m))
#             except:
#                 continue
#     cvss_score = max(score_candidates) if score_candidates else None

#     # --- CVSS vector ---
#     vector_candidates = []
#     vec_patterns = [
#         r"CVSS:[\d\.]+/[A-Z:\/]+",  
#         r"-?\s*(AV:[A-Z]/AC:[A-Z]/PR:[A-Z]/UI:[A-Z]/S:[A-Z]/C:[A-Z]/I:[A-Z]/A:[A-Z])",
#     ]
#     for pat in vec_patterns:
#         vector_candidates.extend(re.findall(pat, text))
#     cvss_vector = vector_candidates[0] if vector_candidates else None

#     return sev, cvss_score, cvss_vector


# # -------------------------
# # Severity / CVSS parser
# # -------------------------
# SEVERITY_RANK = {
#     "Critical": 5, "High": 4, "Medium": 3, "Moderate": 3, "Low": 2, "Informational": 1
# }

# def parse_severity_block(block):
#     """Extract severity, CVSS score, and vector string robustly."""
#     if not block:
#         return None, None, None

#     # If block is a list, join into string; else, keep string
#     if isinstance(block, list):
#         text = " ".join(str(b) for b in block).strip()
#     else:
#         text = str(block).strip()

#     # --- Severity ---
#     sev_candidates = []
#     m_paren = re.findall(r"\((Low|Medium|High|Critical|Moderate|Informational)\)", text, re.IGNORECASE)
#     sev_candidates.extend([x.capitalize() for x in m_paren])
#     # Also check for keywords in plain text
#     for keyword in ["Critical", "High", "Medium", "Low", "Moderate", "Informational"]:
#         if re.search(rf"\b{keyword}\b", text, re.IGNORECASE):
#             sev_candidates.append(keyword)
#     sev = sev_candidates[0] if sev_candidates else None

#     # --- CVSS Score ---
#     score_candidates = []
#     patterns = [
#         r"CVSSv\d+(\.\d+)?:\s*([\d\.]+)",          # CVSSv3: 8.8
#         r"CVSS Score[:\s]+([\d\.]+)",              # CVSS Score: 7.2
#         r"Score[:\s]+([\d\.]+)",                   # Score 7.2
#         r":\s*([\d\.]+)\s*\(?",                    # : 5.3 (Medium)
#         r"(\d\.\d+)\s*\(",                          # 5.3(Medium)
#         r"^(\d\.\d+)\s*$",                         # bare number
#     ]
#     for pat in patterns:
#         for m in re.findall(pat, text):
#             try:
#                 score_candidates.append(float(m))
#             except:
#                 continue
#     cvss_score = max(score_candidates) if score_candidates else None

#     # --- CVSS Vector ---
#     vector_candidates = []
#     vec_patterns = [
#         r"CVSS:[\d\.]+/[A-Z:\/]+",  
#         r"-?\s*(AV:[A-Z]/AC:[A-Z]/PR:[A-Z]/UI:[A-Z]/S:[A-Z]/C:[A-Z]/I:[A-Z]/A:[A-Z])",
#     ]
#     for pat in vec_patterns:
#         vector_candidates.extend(re.findall(pat, text))
#     cvss_vector = vector_candidates[0] if vector_candidates else None

#     return sev, cvss_score, cvss_vector


# -------------------------
# Severity / CVSS parser
# -------------------------
SEVERITY_RANK = {
    "Critical": 5, "High": 4, "Medium": 3, "Moderate": 3, "Low": 2, "Informational": 1
}

def parse_severity_block(block):
    """Extract severity, CVSS score, and vector string robustly (no inference, just extraction)."""
    if not block:
        return None, None, None

    # If block is a list, join into string; else, keep string
    if isinstance(block, list):
        text = " ".join(str(b) for b in block).strip()
    else:
        text = str(block).strip()

    # --- Severity ---
    sev_candidates = []
    # Check severity in parentheses
    m_paren = re.findall(r"\((Low|Medium|High|Critical|Moderate|Informational)\)", text, re.IGNORECASE)
    sev_candidates.extend([x.capitalize() for x in m_paren])

    # Check keywords in plain text
    for keyword in SEVERITY_RANK.keys():
        if re.search(rf"\b{keyword}\b", text, re.IGNORECASE):
            sev_candidates.append(keyword.capitalize())

    sev = sev_candidates[0] if sev_candidates else None

    # --- CVSS Score ---
    score_candidates = []
    patterns = [
        r"CVSSv\d+(\.\d+)?:\s*([\d\.]+)",   # CVSSv3: 8.8
        r"CVSS Score[:\s]+([\d\.]+)",       # CVSS Score: 7.2
        r"Score[:\s]+([\d\.]+)",            # Score 7.2
        r":\s*([\d\.]+)\s*\(?",             # : 5.3 (Medium)
        r"(\d\.\d+)\s*\(",                  # 5.3(Medium)
        r"^(\d\.\d+)\s*$",                  # bare number
        r"^\s*([\d\.]+)\s*-\s*AV:",         # 6.6 - AV:N/... (extra case)
    ]
    for pat in patterns:
        matches = re.findall(pat, text)
        for m in matches:
            if isinstance(m, tuple):
                m = m[-1]  # take last group if tuple
            try:
                score_candidates.append(float(m))
            except:
                continue
    cvss_score = max(score_candidates) if score_candidates else None

    # --- CVSS Vector ---
    vector_candidates = []
    vec_patterns = [
        r"(CVSS:[\d\.]+/[A-Z:\/]+)",  
        r"(AV:[A-Z]/AC:[A-Z]/PR:[A-Z]/UI:[A-Z]/S:[A-Z]/C:[A-Z]/I:[A-Z]/A:[A-Z])",
    ]
    for pat in vec_patterns:
        vector_candidates.extend(re.findall(pat, text))
    cvss_vector = vector_candidates[0] if vector_candidates else None

    return sev, cvss_score, cvss_vector


# # -------------------------
# Ensure Tables
# -------------------------
def ensure_tables(conn):
    cur = conn.cursor()
    cur.execute(f"""
        CREATE TABLE IF NOT EXISTS {TABLE_VENDORS} (
            vendor_id SERIAL PRIMARY KEY,
            vendor_name TEXT NOT NULL UNIQUE
        );
    """)
    cur.execute(f"""
        CREATE TABLE IF NOT EXISTS {TABLE_ADVISORIES} (
            advisory_id TEXT PRIMARY KEY,
            vendor_id INTEGER REFERENCES {TABLE_VENDORS}(vendor_id),
            title TEXT,
            severity TEXT,
            initial_release_date DATE,
            latest_update_date DATE,
            advisory_url TEXT
        );
    """)
    cur.execute(f"""
        CREATE TABLE IF NOT EXISTS {TABLE_CVES} (
            cve_id TEXT PRIMARY KEY,
            description TEXT,
            severity TEXT,
            cvss_score NUMERIC(3,1),
            cvss_vector TEXT,
            initial_release_date DATE,
            latest_update_date DATE,
            reference_url TEXT
        );
    """)
    cur.execute(f"""
        CREATE TABLE IF NOT EXISTS {TABLE_ADV_CVE_MAP} (
            advisory_id TEXT REFERENCES {TABLE_ADVISORIES}(advisory_id) ON DELETE CASCADE,
            cve_id TEXT REFERENCES {TABLE_CVES}(cve_id) ON DELETE CASCADE,
            PRIMARY KEY (advisory_id, cve_id)
        );
    """)
    cur.execute(f"""
        CREATE TABLE IF NOT EXISTS {TABLE_CVE_PRODUCT_MAP} (
            qs_id SERIAL NOT NULL UNIQUE,
            cve_id TEXT PRIMARY KEY REFERENCES {TABLE_CVES}(cve_id) ON DELETE CASCADE,
            affected_products_cpe JSONB,
            recommendations TEXT
        );
    """)
    cur.execute(f"CREATE INDEX IF NOT EXISTS idx_cpe_gin ON {TABLE_CVE_PRODUCT_MAP} USING GIN (affected_products_cpe);")
    conn.commit()
    cur.close()

# -------------------------
# Vendor / Advisory / CVE Normalization
# -------------------------
def ensure_vendor(conn, vendor_name):
    cur = conn.cursor()
    cur.execute(f"SELECT vendor_id FROM {TABLE_VENDORS} WHERE vendor_name=%s", (vendor_name,))
    row = cur.fetchone()
    if row:
        cur.close()
        return row[0]
    cur.execute(f"INSERT INTO {TABLE_VENDORS} (vendor_name) VALUES (%s) RETURNING vendor_id", (vendor_name,))
    vendor_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    return vendor_id

# -------------------------
# Ensure Tables
# -------------------------
def ensure_tables(conn):
    cur = conn.cursor()
    cur.execute(f"""
        CREATE TABLE IF NOT EXISTS {TABLE_VENDORS} (
            vendor_id SERIAL PRIMARY KEY,
            vendor_name TEXT NOT NULL UNIQUE
        );
    """)
    cur.execute(f"""
        CREATE TABLE IF NOT EXISTS {TABLE_ADVISORIES} (
            advisory_id TEXT PRIMARY KEY,
            vendor_id INTEGER REFERENCES {TABLE_VENDORS}(vendor_id),
            title TEXT,
            severity TEXT,
            initial_release_date DATE,
            latest_update_date DATE,
            advisory_url TEXT
        );
    """)
    cur.execute(f"""
        CREATE TABLE IF NOT EXISTS {TABLE_CVES} (
            cve_id TEXT PRIMARY KEY,
            description TEXT,
            severity TEXT,
            cvss_score NUMERIC(3,1),
            cvss_vector TEXT,
            initial_release_date DATE,
            latest_update_date DATE,
            reference_url TEXT
        );
    """)
    cur.execute(f"""
        CREATE TABLE IF NOT EXISTS {TABLE_ADV_CVE_MAP} (
            advisory_id TEXT REFERENCES {TABLE_ADVISORIES}(advisory_id) ON DELETE CASCADE,
            cve_id TEXT REFERENCES {TABLE_CVES}(cve_id) ON DELETE CASCADE,
            PRIMARY KEY (advisory_id, cve_id)
        );
    """)
    cur.execute(f"""
        CREATE TABLE IF NOT EXISTS {TABLE_CVE_PRODUCT_MAP} (
            qs_id SERIAL NOT NULL UNIQUE,
            cve_id TEXT PRIMARY KEY REFERENCES {TABLE_CVES}(cve_id) ON DELETE CASCADE,
            affected_products_cpe JSONB,
            recommendations TEXT
        );
    """)
    cur.execute(f"CREATE INDEX IF NOT EXISTS idx_cpe_gin ON {TABLE_CVE_PRODUCT_MAP} USING GIN (affected_products_cpe);")
    conn.commit()
    cur.close()

# -------------------------
# Vendor / Advisory / CVE Normalization
# -------------------------
def ensure_vendor(conn, vendor_name):
    cur = conn.cursor()
    cur.execute(f"SELECT vendor_id FROM {TABLE_VENDORS} WHERE vendor_name=%s", (vendor_name,))
    row = cur.fetchone()
    if row:
        cur.close()
        return row[0]
    cur.execute(f"INSERT INTO {TABLE_VENDORS} (vendor_name) VALUES (%s) RETURNING vendor_id", (vendor_name,))
    vendor_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    return vendor_id

def normalize_advisory(conn, raw, vendor_id):
    cur = conn.cursor()
    advisory_url = raw.get("advisory_url")
    advisory_id = extract_advisory_id(advisory_url)
    title = raw.get("advisory_title")
    initial_date = safe_date(raw.get("created_date"))
    latest_date = safe_date(raw.get("latest_date"))

    # Insert Advisory
    cur.execute(f"""
        INSERT INTO {TABLE_ADVISORIES}
        (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url)
        VALUES (%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (advisory_id) DO UPDATE SET
            title=EXCLUDED.title,
            severity=EXCLUDED.severity,
            initial_release_date=EXCLUDED.initial_release_date,
            latest_update_date=EXCLUDED.latest_update_date,
            advisory_url=EXCLUDED.advisory_url
    """, (advisory_id, vendor_id, title, None, initial_date, latest_date, advisory_url))

    # Process each CVE
    for cve in raw.get("cve_details", []):
        description = clean_text(cve.get("description"))
        cve_title = clean_text(cve.get("title"))
        if not description or len(description) < 100:
            description = cve_title if cve_title and len(cve_title) >= 50 else title

        recommendations = " | ".join(cve.get("solutions_and_mitigations", []) or [])
        sev, cvss_score, cvss_vector = parse_severity_block(
            cve.get("severity") or cve.get("severity_data") or cve.get("solutions_and_mitigations") or []
        )

        for cve_id in cve.get("cve_ids", []):
            ref_url = generate_cve_url(cve_id, recommendations)

            cur.execute(f"""
                INSERT INTO {TABLE_CVES}
                (cve_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (cve_id) DO UPDATE SET
                    description=EXCLUDED.description,
                    severity=EXCLUDED.severity,
                    cvss_score=EXCLUDED.cvss_score,
                    cvss_vector=EXCLUDED.cvss_vector,
                    initial_release_date=EXCLUDED.initial_release_date,
                    latest_update_date=EXCLUDED.latest_update_date,
                    reference_url=EXCLUDED.reference_url
            """, (cve_id, description, sev, cvss_score, cvss_vector, None, None, ref_url))

            cur.execute(f"""
                INSERT INTO {TABLE_ADV_CVE_MAP} (advisory_id, cve_id)
                VALUES (%s,%s) ON CONFLICT DO NOTHING
            """, (advisory_id, cve_id))

            cur.execute(f"""
                INSERT INTO {TABLE_CVE_PRODUCT_MAP} (cve_id, affected_products_cpe, recommendations)
                VALUES (%s,%s,%s)
                ON CONFLICT (cve_id) DO UPDATE SET
                    affected_products_cpe=EXCLUDED.affected_products_cpe,
                    recommendations=EXCLUDED.recommendations
            """, (cve_id, None, clean_text(recommendations)))

    conn.commit()
    cur.close()

# -------------------------
# Main
# -------------------------
def main():
    conn = psycopg2.connect(**DB_CONFIG)
    ensure_tables(conn)

    vendor_name = "Elastic"
    vendor_id = ensure_vendor(conn, vendor_name)

    cur = conn.cursor()
    cur.execute(f"SELECT staging_id, raw_data FROM {TABLE_STAGING} WHERE vendor_name=%s AND processed=false", (vendor_name,))
    rows = cur.fetchall()
    logger.info(f"Found {len(rows)} advisories to process for {vendor_name}")

    for staging_id, raw_data in rows:
        try:
            normalize_advisory(conn, raw_data, vendor_id)
            if MARK_PROCESSED:
                cur.execute(f"UPDATE {TABLE_STAGING} SET processed=true WHERE staging_id=%s", (staging_id,))
            logger.info(f"[OK] Processed staging_id={staging_id}")
        except Exception as e:
            logger.error(f"[ERROR] Failed staging_id={staging_id}: {e}")

    conn.commit()
    cur.close()
    conn.close()
    logger.info("Normalization complete.")

if __name__ == "__main__":
    main()
