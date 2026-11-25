"""
PHISHING EMAIL DETECTION AND ANALYSIS USING PYTHON
Run: python main.py
Input: Dataset/phishing_emails.csv
Outputs: cleaned data, CSV reports, text report, and charts in Graphs/
"""
from pathlib import Path
import re
import ipaddress
from collections import Counter
from urllib.parse import urlparse
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

ROOT = Path(__file__).resolve().parent
DATA_DIR, GRAPH_DIR, REPORT_DIR = ROOT/"Dataset", ROOT/"Graphs", ROOT/"Reports"
INPUT_FILE = DATA_DIR/"phishing_emails.csv"
for folder in (DATA_DIR, GRAPH_DIR, REPORT_DIR):
    folder.mkdir(exist_ok=True)

SUSPICIOUS_WORDS = [
    "urgent", "verify", "password", "account", "login", "security",
    "bank", "suspended", "click here", "confirm", "update", "payment",
    "immediately", "limited time", "validate", "unlock"
]
URL_RE = re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', re.I)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
              "buff.ly", "cutt.ly", "rb.gy", "shorturl.at"}

def first_existing(df, names):
    lookup = {str(c).strip().lower(): c for c in df.columns}
    for name in names:
        if name in lookup:
            return lookup[name]
    return None

def normalise_label(value):
    s = str(value).strip().lower()
    if s in {"1", "phishing", "phish", "spam", "malicious", "fraud"} or "phish" in s:
        return "Phishing"
    if s in {"0", "legitimate", "legit", "ham", "safe", "benign", "non-phishing"} or "legit" in s:
        return "Legitimate"
    return "Unknown"

def extract_urls(text):
    return [u.rstrip(".,);]}>") for u in URL_RE.findall(str(text or ""))]

def sender_parts(sender):
    sender = str(sender or "").strip()
    match = re.search(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}', sender)
    address = match.group(0) if match else ""
    if not address:
        return "", "", ""
    username, domain = address.rsplit("@", 1)
    return address, username, domain.lower()

def url_flags(url):
    candidate = url if "://" in url else "http://" + url
    host = (urlparse(candidate).hostname or "").lower()
    ip_flag = False
    try:
        ipaddress.ip_address(host)
        ip_flag = True
    except ValueError:
        pass
    short_flag = host in SHORTENERS
    return host, ip_flag, short_flag

def save_bar(series, title, xlabel, filename, top=None):
    data = series.head(top) if top else series
    plt.figure(figsize=(10, 6))
    data.sort_values().plot(kind="barh")
    plt.title(title); plt.xlabel(xlabel); plt.ylabel("")
    plt.tight_layout(); plt.savefig(GRAPH_DIR/filename, dpi=160); plt.close()

def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Dataset not found: {INPUT_FILE}\n"
            "Place your CSV file at Dataset/phishing_emails.csv. "
            "See README.md for required columns and supported alternatives."
        )

    df = pd.read_csv(INPUT_FILE)
    print("\n=== STEP 1: DATASET COLLECTION AND DATA LOADING ===")
    print("First five records:\n", df.head().to_string(index=False))
    print("\nShape (rows, columns):", df.shape)
    print("Columns:", list(df.columns))
    print("\nData types:\n", df.dtypes)
    print("\nDataset information:")
    df.info()

    sender_col = first_existing(df, ["sender", "from", "sender_email", "email_address"])
    subject_col = first_existing(df, ["subject", "email_subject", "title"])
    body_col = first_existing(df, ["body", "message", "email_body", "text", "content", "email"])
    label_col = first_existing(df, ["label", "category", "class", "type", "target", "email_type"])
    id_col = first_existing(df, ["email_id", "id", "message_id"])
    urls_col = first_existing(df, ["urls", "url", "links", "email_urls"])

    if body_col is None:
        raise ValueError("Could not identify email body column. Rename it to 'body' or update the aliases in main.py.")
    if label_col is None:
        raise ValueError("Could not identify label column. A phishing/legitimate label column is required.")

    work = pd.DataFrame()
    work["email_id"] = df[id_col] if id_col else range(1, len(df)+1)
    work["sender"] = df[sender_col].fillna("").astype(str) if sender_col else ""
    work["subject"] = df[subject_col].fillna("").astype(str) if subject_col else ""
    work["body"] = df[body_col].fillna("").astype(str)
    work["label_original"] = df[label_col].astype(str)
    work["label"] = work["label_original"].map(normalise_label)
    work["provided_urls"] = df[urls_col].fillna("").astype(str) if urls_col else ""

    print("\n=== STEP 2: DATA UNDERSTANDING AND CLEANING ===")
    missing_before = work[["sender", "subject", "body", "label_original"]].isna().sum()
    duplicate_count = int(work.duplicated(subset=["sender", "subject", "body", "label"], keep="first").sum())
    empty_subject = int(work["subject"].str.strip().eq("").sum())
    empty_body = int(work["body"].str.strip().eq("").sum())
    work = work.drop_duplicates(subset=["sender", "subject", "body", "label"], keep="first").copy()
    work["sender"] = work["sender"].str.strip()
    work["subject"] = work["subject"].str.replace(r"\s+", " ", regex=True).str.strip()
    work["body"] = work["body"].str.replace(r"\s+", " ", regex=True).str.strip()
    work["label"] = work["label"].fillna("Unknown")
    work["full_text"] = (work["subject"] + " " + work["body"]).str.strip()
    work["email_length"] = work["full_text"].str.len()
    work["word_count"] = work["full_text"].str.findall(r"\b[\w'-]+\b").str.len()
    work["urls_extracted"] = work["full_text"].apply(extract_urls)
    work["url_count"] = work["urls_extracted"].str.len()
    work["urls_from_csv"] = work["provided_urls"].apply(extract_urls)
    work["all_urls"] = work.apply(lambda r: list(dict.fromkeys(r["urls_extracted"] + r["urls_from_csv"])), axis=1)
    work["url_count"] = work["all_urls"].str.len()
    work["sender_address"] = work["sender"].apply(lambda x: sender_parts(x)[0])
    work["sender_username"] = work["sender"].apply(lambda x: sender_parts(x)[1])
    work["sender_domain"] = work["sender"].apply(lambda x: sender_parts(x)[2])
    work["suspicious_keyword_count"] = work["full_text"].str.lower().apply(
        lambda t: sum(t.count(word) for word in SUSPICIOUS_WORDS)
    )
    work["contains_urgent_language"] = work["full_text"].str.contains(
        r"\b(urgent|immediately|act now|limited time|suspended)\b", case=False, regex=True
    )
    work["requests_sensitive_info"] = work["full_text"].str.contains(
        r"\b(password|bank details|credit card|personal information|login details|account number)\b",
        case=False, regex=True
    )
    work["contains_suspicious_url"] = work["all_urls"].apply(lambda arr: any(
        url_flags(u)[1] or url_flags(u)[2] for u in arr
    ))

    missing_summary = pd.DataFrame({"missing_values_before_cleaning": missing_before})
    quality = {
        "rows_loaded": len(df), "duplicate_records_removed": duplicate_count,
        "empty_subject_records": empty_subject, "empty_body_records": empty_body,
        "rows_after_duplicate_removal": len(work),
        "unknown_labels": int((work["label"] == "Unknown").sum())
    }
    missing_summary.to_csv(REPORT_DIR/"missing_value_summary.csv")
    pd.DataFrame([quality]).to_csv(REPORT_DIR/"data_quality_summary.csv", index=False)
    work.drop(columns=["urls_extracted", "urls_from_csv", "all_urls"]).to_csv(
        REPORT_DIR/"cleaned_email_dataset.csv", index=False
    )

    print("\n=== STEP 3: EMAIL CONTENT ANALYSIS ===")
    word_counter = Counter()
    for text in work["full_text"].str.lower():
        word_counter.update(re.findall(r"\b[a-zA-Z]{3,}\b", text))
    common_words = pd.DataFrame(word_counter.most_common(30), columns=["word", "frequency"])
    common_words.to_csv(REPORT_DIR/"frequently_used_words.csv", index=False)

    keyword_rows = []
    for word in SUSPICIOUS_WORDS:
        for category in ["Phishing", "Legitimate"]:
            subset = work[work["label"] == category]
            count = int(subset["full_text"].str.lower().str.count(re.escape(word)).sum())
            keyword_rows.append({"keyword": word, "category": category, "count": count})
    keyword_df = pd.DataFrame(keyword_rows)
    keyword_df.to_csv(REPORT_DIR/"suspicious_keyword_comparison.csv", index=False)

    print("\n=== STEP 4: SENDER AND URL ANALYSIS ===")
    sender_domains = work[work["sender_domain"] != ""].groupby(["sender_domain", "label"]).size().unstack(fill_value=0)
    sender_domains["total"] = sender_domains.sum(axis=1)
    sender_domains.sort_values("total", ascending=False).to_csv(REPORT_DIR/"sender_domain_analysis.csv")

    url_rows = []
    for _, row in work.iterrows():
        for url in row["all_urls"]:
            host, ip_flag, short_flag = url_flags(url)
            url_rows.append({
                "email_id": row["email_id"], "label": row["label"], "url": url,
                "host": host, "uses_ip_address": ip_flag, "is_known_shortener": short_flag
            })
    url_df = pd.DataFrame(url_rows, columns=[
        "email_id", "label", "url", "host", "uses_ip_address", "is_known_shortener"
    ])
    url_df.to_csv(REPORT_DIR/"extracted_urls.csv", index=False)
    url_summary = pd.DataFrame([{
        "emails_with_urls": int((work["url_count"] > 0).sum()),
        "emails_with_multiple_urls": int((work["url_count"] > 1).sum()),
        "total_extracted_urls": len(url_df),
        "urls_using_ip_addresses": int(url_df["uses_ip_address"].sum()) if len(url_df) else 0,
        "known_shortened_urls": int(url_df["is_known_shortener"].sum()) if len(url_df) else 0
    }])
    url_summary.to_csv(REPORT_DIR/"url_count_summary.csv", index=False)

    print("\n=== STEP 5: PHISHING PATTERN ANALYSIS ===")
    counts = work["label"].value_counts()
    total_known = int(work["label"].isin(["Phishing", "Legitimate"]).sum())
    pattern_summary = pd.DataFrame([
        {"category": cat, "email_count": int(counts.get(cat, 0)),
         "percentage": round(counts.get(cat, 0) / total_known * 100, 2) if total_known else 0}
        for cat in ["Phishing", "Legitimate", "Unknown"]
    ])
    pattern_summary.to_csv(REPORT_DIR/"phishing_legitimate_summary.csv", index=False)

    observations = []
    for cat in ["Phishing", "Legitimate"]:
        sub = work[work["label"] == cat]
        observations.append({
            "category": cat,
            "emails": len(sub),
            "avg_email_length": round(sub["email_length"].mean(), 2) if len(sub) else 0,
            "avg_url_count": round(sub["url_count"].mean(), 2) if len(sub) else 0,
            "emails_with_urgent_language": int(sub["contains_urgent_language"].sum()),
            "emails_requesting_sensitive_info": int(sub["requests_sensitive_info"].sum()),
            "emails_with_suspicious_url_indicators": int(sub["contains_suspicious_url"].sum())
        })
    pd.DataFrame(observations).to_csv(REPORT_DIR/"category_characteristics.csv", index=False)

    print("\n=== STEP 6: DATA VISUALISATION ===")
    sns.set_theme(style="whitegrid")
    # 1. Phishing vs legitimate bar chart
    plt.figure(figsize=(8, 5))
    order = ["Phishing", "Legitimate", "Unknown"]
    sns.countplot(data=work, x="label", order=order, color="#7565e5")
    plt.title("Phishing vs Legitimate Emails"); plt.xlabel("Email Category"); plt.ylabel("Number of Emails")
    plt.tight_layout(); plt.savefig(GRAPH_DIR/"01_phishing_vs_legitimate.png", dpi=160); plt.close()

    # 2. Category distribution pie chart
    pie_counts = work["label"].value_counts()
    plt.figure(figsize=(7, 7))
    plt.pie(pie_counts.values, labels=pie_counts.index, autopct="%1.1f%%", startangle=90)
    plt.title("Email Category Distribution")
    plt.tight_layout(); plt.savefig(GRAPH_DIR/"02_email_category_pie.png", dpi=160); plt.close()

    # 3. Top 10 suspicious keywords
    total_kw = keyword_df.groupby("keyword")["count"].sum().sort_values(ascending=False).head(10)
    save_bar(total_kw, "Top 10 Suspicious Keywords", "Occurrences", "03_top10_suspicious_keywords.png")

    # 4. Email length histogram
    plt.figure(figsize=(9, 5))
    sns.histplot(data=work, x="email_length", hue="label", bins=25, kde=True, element="step")
    plt.title("Email Length Distribution"); plt.xlabel("Email length (characters)"); plt.ylabel("Email count")
    plt.tight_layout(); plt.savefig(GRAPH_DIR/"04_email_length_distribution.png", dpi=160); plt.close()

    # 5. Sender domain frequency
    domain_freq = work[work["sender_domain"] != ""]["sender_domain"].value_counts().head(15)
    save_bar(domain_freq, "Sender Domain Frequency (Top 15)", "Email count", "05_sender_domain_frequency.png")

    # 6. URL count histogram
    plt.figure(figsize=(9, 5))
    sns.histplot(data=work, x="url_count", hue="label", discrete=True, multiple="dodge")
    plt.title("URL Count per Email"); plt.xlabel("Number of URLs"); plt.ylabel("Email count")
    plt.tight_layout(); plt.savefig(GRAPH_DIR/"06_url_count_per_email.png", dpi=160); plt.close()

    # 7. Phishing keyword comparison
    pivot = keyword_df.pivot(index="keyword", columns="category", values="count").fillna(0)
    ax = pivot.plot(kind="bar", figsize=(12, 6))
    ax.set_title("Suspicious Keyword Comparison"); ax.set_xlabel("Keyword"); ax.set_ylabel("Occurrences")
    plt.xticks(rotation=45, ha="right"); plt.tight_layout()
    plt.savefig(GRAPH_DIR/"07_phishing_keyword_comparison.png", dpi=160); plt.close()

    # 8. Phishing pattern heatmap
    heat = work.groupby("label")[[
        "email_length", "word_count", "url_count", "suspicious_keyword_count",
        "contains_urgent_language", "requests_sensitive_info", "contains_suspicious_url"
    ]].mean()
    plt.figure(figsize=(11, 5))
    sns.heatmap(heat, annot=True, fmt=".1f", cmap="YlOrRd")
    plt.title("Phishing Email Pattern Comparison")
    plt.tight_layout(); plt.savefig(GRAPH_DIR/"08_phishing_pattern_heatmap.png", dpi=160); plt.close()

    # Text report
    phishing_n = int(counts.get("Phishing", 0))
    legit_n = int(counts.get("Legitimate", 0))
    top_words = ", ".join(f"{r.word} ({r.frequency})" for r in common_words.head(10).itertuples())
    top_domains = ", ".join(f"{d} ({n})" for d, n in work["sender_domain"].value_counts().head(10).items())
    report = f"""PHISHING EMAIL DETECTION AND ANALYSIS USING PYTHON
================================================
Dataset rows loaded: {len(df)}
Rows after duplicate removal: {len(work)}
Phishing emails: {phishing_n}
Legitimate emails: {legit_n}
Unknown labels: {int((work['label']=='Unknown').sum())}

Top frequently used words:
{top_words or 'No words found'}

Top sender domains:
{top_domains or 'No sender domains found'}

URL summary:
{url_summary.to_string(index=False)}

Keyword comparison file: suspicious_keyword_comparison.csv
URL details file: extracted_urls.csv
Sender analysis file: sender_domain_analysis.csv

IMPORTANT:
A suspicious-looking URL or keyword is an indicator for manual review,
not proof that a website or email is malicious. Do not open suspicious links.
This project performs data analytics; it does not guarantee a security verdict.
"""
    (REPORT_DIR/"final_analysis_report.txt").write_text(report, encoding="utf-8")

    print("\nPROJECT COMPLETED SUCCESSFULLY.")
    print("Cleaned data and reports:", REPORT_DIR)
    print("Charts saved:", GRAPH_DIR)
    print("\n", report)

if __name__ == "__main__":
    main()
