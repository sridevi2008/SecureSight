
import csv
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CSV_FILE = ROOT / "Dataset" / "phishing_emails.csv"
BACKUP_FILE = ROOT / "Dataset" / "phishing_emails_backup.csv"

phishing_templates = [
    ("Account security verification",
     "Your account requires verification. Review this sample notice at https://example.test/verify",
     "security@bank.test", "https://example.test/verify"),

    ("Urgent account notification",
     "An unusual login was detected. Review this simulated alert at https://example.test/alert",
     "alert@account.test", "https://example.test/alert"),

    ("Password expiration notice",
     "Your password is scheduled to expire. Visit https://example.test/password",
     "support@service.test", "https://example.test/password"),

    ("Payment verification required",
     "A payment verification is pending. Review this sample at https://example.test/payment",
     "billing@payment.test", "https://example.test/payment"),

    ("Account access warning",
     "This sample message asks you to confirm account access at https://example.test/access",
     "admin@account.test", "https://example.test/access")
]

legitimate_templates = [
    ("Weekly team meeting",
     "Our weekly project meeting is scheduled for Monday. Please review your tasks.",
     "team@company.test", ""),

    ("Order confirmation",
     "Thank you for your purchase. Your sample order has been received.",
     "orders@shop.test", ""),

    ("Monthly newsletter",
     "Welcome to our monthly newsletter. Here are the latest updates and events.",
     "newsletter@library.test", ""),

    ("Office holiday schedule",
     "The updated office holiday schedule is available on the staff portal.",
     "hr@company.test", ""),

    ("Project progress update",
     "Please find the latest project progress summary. Thank you for your teamwork.",
     "manager@company.test", "")
]

if not CSV_FILE.exists():
    raise FileNotFoundError("phishing_emails.csv file not found!")

with open(CSV_FILE, "r", newline="", encoding="utf-8-sig") as file:
    reader = csv.DictReader(file)
    columns = reader.fieldnames
    records = list(reader)

expected = ["email_id", "sender", "subject", "body", "label", "urls"]

if columns != expected:
    raise ValueError(f"CSV columns do not match: {columns}")

if len(records) >= 500:
    print("Dataset already contains 500 or more records.")
    raise SystemExit

if not BACKUP_FILE.exists():
    shutil.copy2(CSV_FILE, BACKUP_FILE)
    print("Original CSV backup created.")

existing_ids = {row["email_id"] for row in records}
next_id = 1

while len(records) < 500:

    email_id = f"E{next_id:03d}"

    if email_id in existing_ids:
        next_id += 1
        continue

    if len(records) % 2 == 0:
        subject, body, sender, urls = phishing_templates[
            (next_id - 1) % len(phishing_templates)
        ]
        label = "Phishing"
    else:
        subject, body, sender, urls = legitimate_templates[
            (next_id - 1) % len(legitimate_templates)
        ]
        label = "Legitimate"

    records.append({
        "email_id": email_id,
        "sender": sender,
        "subject": f"{subject} - Sample {next_id}",
        "body": body,
        "label": label,
        "urls": urls
    })

    existing_ids.add(email_id)
    next_id += 1

with open(CSV_FILE, "w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(file, fieldnames=expected)
    writer.writeheader()
    writer.writerows(records)

phishing = sum(r["label"].lower() == "phishing" for r in records)
legitimate = sum(r["label"].lower() == "legitimate" for r in records)

print("\nDataset generation completed!")
print("Total records:", len(records))
print("Phishing emails:", phishing)
print("Legitimate emails:", legitimate)
print("Backup:", BACKUP_FILE)
