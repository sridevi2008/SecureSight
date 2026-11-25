
from pathlib import Path
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

ROOT = Path(__file__).resolve().parent
DATASET = ROOT / "phishing_emails.csv"
MODEL_DIR = ROOT / "Models"
MODEL_DIR.mkdir(exist_ok=True)

df = pd.read_csv(DATASET)
df = df.astype(object).where(pd.notna(df), "")

df["text"] = (
    df["subject"].astype(str) + " " +
    df["body"].astype(str)
)

df["label"] = df["label"].astype(str).str.strip().str.lower()
df = df[df["label"].isin(["phishing", "legitimate"])]

X = df["text"]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

model = Pipeline([
    ("tfidf", TfidfVectorizer(ngram_range=(1, 2))),
    ("classifier", LogisticRegression(max_iter=1000))
])

model.fit(X_train, y_train)
predictions = model.predict(X_test)

print("\n===== SECURESIGHT MODEL PERFORMANCE =====")
print("Total records:", len(df))
print("Training records:", len(X_train))
print("Testing records:", len(X_test))
print("Accuracy:", round(accuracy_score(y_test, predictions) * 100, 2), "%")
print("Precision:", round(precision_score(y_test, predictions, pos_label="phishing", zero_division=0) * 100, 2), "%")
print("Recall:", round(recall_score(y_test, predictions, pos_label="phishing", zero_division=0) * 100, 2), "%")
print("F1 Score:", round(f1_score(y_test, predictions, pos_label="phishing", zero_division=0) * 100, 2), "%")

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, predictions, labels=["phishing", "legitimate"]))

print("\nClassification Report:")
print(classification_report(y_test, predictions, zero_division=0))

joblib.dump(model, MODEL_DIR / "email_model_evaluated.pkl")

print("\nEvaluated model saved successfully!")
print("Location:", MODEL_DIR / "email_model_evaluated.pkl")
