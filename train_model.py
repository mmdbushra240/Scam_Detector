import pandas as pd
import numpy as np
import re
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score

# 1. Load the EMSCAD dataset (download fake_job_postings.csv from Kaggle)
df = pd.read_csv('fake_job_postings.csv')

# 2. Combine key text columns into a single feature space
text_columns = ['title', 'company_profile', 'description', 'requirements', 'benefits']
df[text_columns] = df[text_columns].fillna('')

df['combined_text'] = (
    df['title'] + " " + 
    df['company_profile'] + " " + 
    df['description'] + " " + 
    df['requirements'] + " " + 
    df['benefits']
)

# 3. Basic NLP Cleaning Function
def clean_text(text):
    text = text.lower()
    text = re.sub(r'http\S+|www\S+|https\S+', '', text, flags=re.MULTILINE)  # remove URLs
    text = re.sub(r'\W', ' ', text)  # remove non-alphanumeric chars
    text = re.sub(r'\s+', ' ', text).strip()  # remove extra spaces
    return text

df['cleaned_text'] = df['combined_text'].apply(clean_text)

# 4. Define Features (X) and Target (y)
X = df['cleaned_text']
y = df['fraudulent']

# 5. Train-Test Split (stratified due to imbalanced fake/real classes)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# 6. Build a Pipeline (TF-IDF + Classifier)
# Option A: Multinomial Naive Bayes (Fast & robust baseline for text classification)
model_pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(max_features=5000, stop_words='english', ngram_range=(1, 2))),
    ('classifier', MultinomialNB())
])

# Option B: Random Forest Classifier (Uncomment below to use Random Forest instead)
# model_pipeline = Pipeline([
#     ('tfidf', TfidfVectorizer(max_features=5000, stop_words='english', ngram_range=(1, 2))),
#     ('classifier', RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42))
# ])

# 7. Train Model
model_pipeline.fit(X_train, y_train)

# 8. Evaluate Performance
y_pred = model_pipeline.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}\n")
print("Classification Report:")
print(classification_report(y_test, y_pred, target_names=['Real (0)', 'Fake (1)']))

# 9. Save Trained Model to Disk
joblib.dump(model_pipeline, 'model.pkl')
print("Model saved successfully as 'model.pkl'.")