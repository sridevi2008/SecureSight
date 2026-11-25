
from pathlib import Path
from functools import wraps
import os
import io
import csv
import re

import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_from_directory,
    Response
)

ROOT = Path(__file__).resolve().parent

app = Flask(
    __name__,
    static_folder=str(ROOT / "static"),
    static_url_path="/static"
)


app.secret_key = os.environ.get("SECRET_KEY")

APP_USERNAME = os.environ.get("APP_USERNAME")
APP_PASSWORD = os.environ.get("APP_PASSWORD")

if not app.secret_key or not APP_USERNAME or not APP_PASSWORD:
    raise RuntimeError(
        "Please configure SECRET_KEY, APP_USERNAME and APP_PASSWORD."
    )

DATASET_FILE = ROOT / "Dataset" / "phishing_emails.csv"
SAMPLE_FILE = ROOT / "sample_phishing_emails.csv"
MODEL_FILE = ROOT / "Models" / "email_model.pkl"


# ---------------- AUTHENTICATION ----------------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


# ---------------- EMAIL DATA ----------------

def get_email_records():
    possible_files = [
        ROOT / "Reports" / "cleaned_email_dataset.csv",
        DATASET_FILE,
        SAMPLE_FILE
    ]

    for file in possible_files:
        if file.exists():
            try:
                df = pd.read_csv(file)
                df = df.astype(object).where(pd.notna(df), "")
                return df.to_dict("records")
            except Exception as error:
                print(f"Dataset reading error: {error}")

    return []


def get_sender_domain(sender):
    sender = str(sender).strip().lower()

    if "@" in sender:
        return sender.rsplit("@", 1)[-1]

    return "Unknown"


# ---------------- DASHBOARD DATA ----------------

def load_dashboard_data():
    records = get_email_records()
    df = pd.DataFrame(records)

    total = len(records)
    phishing = 0
    legitimate = 0
    urls = 0
    suspicious = 0

    if not df.empty:

        label_col = (
            "label" if "label" in df.columns
            else "label_original"
        )

        if label_col in df.columns:
            labels = df[label_col].astype(str).str.lower()

            phishing = int(
                labels.str.contains(
                    r"phish|spam|fraud|malicious|^1$",
                    regex=True
                ).sum()
            )

            legitimate = int(
                labels.str.contains(
                    r"legit|ham|safe|benign|^0$",
                    regex=True
                ).sum()
            )

        if "url_count" in df.columns:
            urls = int(
                pd.to_numeric(
                    df["url_count"],
                    errors="coerce"
                ).fillna(0).sum()
            )

        if "suspicious_keyword_count" in df.columns:
            suspicious = int(
                pd.to_numeric(
                    df["suspicious_keyword_count"],
                    errors="coerce"
                ).fillna(0).gt(0).sum()
            )

    # Sender domain statistics
    domain_counts = {}

    for row in records:
        domain = get_sender_domain(row.get("sender", ""))

        domain_counts[domain] = (
            domain_counts.get(domain, 0) + 1
        )

    domain_list = [
        {"domain": domain, "count": count}
        for domain, count in sorted(
            domain_counts.items(),
            key=lambda item: item[1],
            reverse=True
        )
    ]

    # Available graph images
    charts = [
        ("01_phishing_vs_legitimate.png", "Phishing vs Legitimate"),
        ("02_email_category_pie.png", "Email Category Distribution"),
        ("03_top10_suspicious_keywords.png", "Top Suspicious Keywords"),
        ("04_email_length_distribution.png", "Email Length Distribution"),
        ("05_sender_domain_frequency.png", "Sender Domain Frequency"),
        ("06_url_count_per_email.png", "URL Count Per Email"),
        ("07_phishing_keyword_comparison.png", "Keyword Comparison"),
        ("08_phishing_pattern_heatmap.png", "Phishing Pattern Heatmap"),
    ]

    available_charts = [
        {"file": filename, "title": title}
        for filename, title in charts
        if (ROOT / "Graphs" / filename).is_file()
    ]

    # Recent email records
    recent = []

    for row in records[:8]:
        recent.append({
            "sender": str(
                row.get("sender", "Not available")
            ),
            "subject": str(
                row.get("subject", "No subject")
            ),
            "label": str(
                row.get(
                    "label",
                    row.get("label_original", "Unknown")
                )
            ).title(),
            "urls": row.get(
                "url_count",
                row.get("urls", 0)
            )
        })

    return {
        "total": total,
        "phishing": phishing,
        "legitimate": legitimate,
        "urls": urls,
        "suspicious": suspicious,
        "domains": domain_list,
        "charts": available_charts,
        "recent": recent
    }


# ---------------- HOME ----------------

@app.route("/")
def home():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get(
            "username", ""
        ).strip()

        password = request.form.get(
            "password", ""
        )

        if (
            username == APP_USERNAME
            and password == APP_PASSWORD
        ):
            session.clear()
            session["logged_in"] = True
            session["username"] = username

            return redirect(url_for("dashboard"))

        flash(
            "Incorrect username or password.",
            "error"
        )

    return render_template("login.html")


# ---------------- DASHBOARD ----------------

@app.route("/dashboard")
@login_required
def dashboard():

    data = load_dashboard_data()

    phishing_percent = (
        data["phishing"] / data["total"] * 100
        if data["total"] else 0
    )

    legitimate_percent = (
        data["legitimate"] / data["total"] * 100
        if data["total"] else 0
    )

    risk_level = (
        "HIGH" if phishing_percent >= 60
        else "MEDIUM" if phishing_percent >= 30
        else "LOW"
    )

    risk_color = (
        "#ff647c" if risk_level == "HIGH"
        else "#ffbd59" if risk_level == "MEDIUM"
        else "#24d6d0"
    )

    return render_template(
        "dashboard.html",
        data=data,
        username=session.get("username", "User"),
        phishing_percent=phishing_percent,
        legitimate_percent=legitimate_percent,
        risk_level=risk_level,
        risk_color=risk_color
    )


# ---------------- ABOUT ----------------

@app.route("/about")
@login_required
def about():

    return render_template(
        "about.html",
        username=session.get("username", "User")
    )


# ---------------- VISUAL ANALYTICS ----------------

@app.route("/visual-analytics")
@login_required
def visual_analytics():
    dashboard_data = load_dashboard_data()

    return render_template(
        "visual_analytics.html",
        data=dashboard_data,
        charts=dashboard_data["charts"],
        username=session.get("username", "User")
    )


# ---------------- SENDER DOMAINS ----------------


# ---------------- SENDER DOMAINS ----------------


@app.route("/sender-domains")
@login_required
def sender_domains():
    records = get_email_records()
    domain_counts = {}

    for row in records:
        sender = str(row.get("sender", "")).strip().lower()

        if "@" in sender:
            domain = sender.rsplit("@", 1)[-1].strip()
        else:
            domain = "Unknown"

        if not domain:
            domain = "Unknown"

        domain_counts[domain] = domain_counts.get(domain, 0) + 1

    sorted_domains = [
        {
            "domain": domain,
            "count": count
        }
        for domain, count in sorted(
            domain_counts.items(),
            key=lambda item: item[1],
            reverse=True
        )
    ]

    total_emails = sum(item["count"] for item in sorted_domains)
    total_domains = len(sorted_domains)

    return render_template(
        "sender_domains.html",
        domains=sorted_domains,
        total_emails=total_emails,
        total_domains=total_domains,
        username=session.get("username", "User")
    )


# ---------------- EMAIL RECORDS ----------------

@app.route("/email-records")
@login_required
def email_records():

    return render_template(
        "email_records.html",
        records=get_email_records(),
        username=session.get("username", "User")
    )


# ---------------- DOWNLOAD REPORTS ----------------

@app.route("/download-reports")
@login_required
def download_reports():

    records = get_email_records()

    output = io.StringIO()
    writer = csv.writer(output)

    if records:

        headers = list(records[0].keys())
        writer.writerow(headers)

        for row in records:
            writer.writerow([
                row.get(key, "")
                for key in headers
            ])

    else:
        writer.writerow(["Message"])
        writer.writerow(["No email records available"])

    csv_data = "\ufeff" + output.getvalue()

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={
            "Content-Disposition":
            "attachment; filename=securesight_report.csv"
        }
    )


# ---------------- EMAIL PREDICTION ----------------

@app.route("/predict", methods=["GET", "POST"])
@login_required
def predict_email():

    prediction = None
    email_text = ""
    subject = ""
    body = ""

    if request.method == "POST":

        subject = request.form.get("subject", "").strip()
        body = request.form.get("body", "").strip()
        email_text = (subject + " " + body).strip()

        if not email_text:

            flash(
                "Please enter email content.",
                "error"
            )

        elif not MODEL_FILE.exists():

            flash(
                "Model file not found.",
                "error"
            )

        else:

            try:
                model = joblib.load(MODEL_FILE)

                result = model.predict([email_text])[0]

                prediction = str(result)

            except Exception as error:

                flash(
                    "Prediction failed: " + str(error),
                    "error"
                )

    return render_template(
        "email_prediction.html",
        result=prediction,
        prediction=prediction,
        email_text=email_text,
        subject=subject,
        body=body,
        username=session.get("username", "User")
    )


# ---------------- GRAPH IMAGES ----------------

@app.route("/graphs/<path:filename>")
@login_required
def graph_file(filename):

    return send_from_directory(
        ROOT / "Graphs",
        filename
    )


# ---------------- LOGOUT ----------------

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# ---------------- RUN APPLICATION ----------------

if __name__ == "__main__":

    port = int(
        os.environ.get("PORT", 10000)
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
