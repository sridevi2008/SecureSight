# Phishing Email Detection and Analysis Using Python

**Domain:** Cybersecurity – Data Analytics

This project follows the six steps in the supplied project specification:
1. Dataset collection and data loading
2. Data understanding and cleaning
3. Email content analysis
4. Sender and URL analysis
5. Phishing pattern analysis
6. Data visualisation

## Folder structure

```text
PHISHING_EMAIL_ANALYSIS/
├── Dataset/
│   └── phishing_emails.csv        # Add your downloaded dataset here
├── Notebooks/
│   ├── 01_data_loading.ipynb
│   ├── 02_data_understanding.ipynb
│   ├── 03_data_cleaning.ipynb
│   ├── 04_email_content_analysis.ipynb
│   ├── 05_phishing_pattern_analysis.ipynb
│   └── 06_data_visualization.ipynb
├── Graphs/                        # 8 PNG charts are generated here
├── Reports/                       # CSV and TXT analysis reports
├── main.py
└── requirements.txt
```

## 1. Install Python packages

Open Command Prompt / Terminal inside this folder:

```bash
python -m pip install -r requirements.txt
```

## 2. Add the dataset

Download a labelled phishing email CSV dataset from one of the sources below and save it as:

`Dataset/phishing_emails.csv`

Suggested sources from the project specification:
- Kaggle phishing email datasets: https://www.kaggle.com/datasets
- UCI Machine Learning Repository: https://archive.ics.uci.edu/
- PhishTank (URL intelligence; it may not provide email subject/body/labels in the required format): https://phishtank.org/

Choose a dataset that contains email text and a label indicating phishing or legitimate.

### Supported column names

The program automatically recognises common alternatives:

| Required information | Accepted column names |
|---|---|
| Sender | sender, from, sender_email, email_address |
| Subject | subject, email_subject, title |
| Email body | body, message, email_body, text, content, email |
| Label | label, category, class, type, target, email_type |
| Email ID (optional) | email_id, id, message_id |
| URLs (optional) | urls, url, links, email_urls |

The email body and label columns are required. Labels such as `phishing`, `spam`, `1` and `legitimate`, `ham`, `0` are normalised. Check that your dataset's label coding is correct before analysis. If your dataset uses a different coding, edit `normalise_label()` in `main.py`.

## 3. Run the complete project

```bash
python main.py
```

The program creates:
- `Reports/cleaned_email_dataset.csv`
- `Reports/missing_value_summary.csv`
- `Reports/data_quality_summary.csv`
- `Reports/frequently_used_words.csv`
- `Reports/suspicious_keyword_comparison.csv`
- `Reports/sender_domain_analysis.csv`
- `Reports/extracted_urls.csv`
- `Reports/url_count_summary.csv`
- `Reports/phishing_legitimate_summary.csv`
- `Reports/category_characteristics.csv`
- `Reports/final_analysis_report.txt`
- Eight PNG charts inside `Graphs/`

## 4. Run using Jupyter Notebook

```bash
jupyter notebook
```

Open the six notebooks in `Notebooks/`. Each notebook explains the corresponding stage and runs the full analysis script when appropriate.

## Important notes
- The ZIP contains a project template, not a real-world labelled email corpus. Add the dataset you download before running it.
- A suspicious keyword, IP-based URL, or shortened URL is only an indicator for review, not proof of malicious activity.
- Do not open suspicious links or enter credentials into them.
- This is a Python data analytics project, not a production-grade email security gateway or a trained machine-learning classifier.


## 5. Login page and attractive dashboard

This project also includes a Flask web interface:
- Modern login page with show/hide password.
- Dashboard cards for total, phishing, legitimate and URL counts.
- Sender-domain summary, dataset preview and visualisation gallery.
- Sign-out option and protected dashboard routes.

Install requirements (including Flask):

```bash
python -m pip install -r requirements.txt
```

Start the website from the project folder:

```bash
python app.py
```

Open this address in your browser:

`http://127.0.0.1:5000`

**Demo login**
- Username: `admin`
- Password: `Admin@123`

The included demo credentials are for local classroom demonstration only. Before deploying publicly, set strong `APP_USERNAME`, `APP_PASSWORD`, and `SECRET_KEY` environment variables, disable Flask debug mode, and use HTTPS. Do not deploy the demo password as-is.

The included `sample_phishing_emails.csv` is synthetic test data. For your actual project results, add your selected labelled email dataset as `Dataset/phishing_emails.csv`. The dashboard will run the analysis if reports have not been generated yet.
