import xgboost as xgb
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import matplotlib.pyplot as plt
import seaborn as sns
import pickle


import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# 1. Load the dataset
print("📂 Loading dataset_final.csv for PCAP-derived data...")
df_pcap = pd.read_csv("dataset_final.csv")

# 2. Handle infinite or null values
#df_pcap = df_pcap.replace([np.inf, -np.inf], np.nan).dropna()
print(f"📊 Dimensions of df_pcap after cleaning: {df_pcap.shape}")

# 3. Separate features (X_pcap) from the target variable (y_pcap)
X_pcap = df_pcap.drop(columns=['Label'])
y_pcap = df_pcap['Label']

# 4. Apply Label Encoding to y_pcap
le_pcap = LabelEncoder()
y_encoded_pcap = le_pcap.fit_transform(y_pcap)
print("✅ PCAP Labels encoded:", dict(zip(le_pcap.classes_, le_pcap.transform(le_pcap.classes_))))

# 5. Save the fitted LabelEncoder
with open("label_encoder_pcap.pkl", "wb") as f:
    pickle.dump(le_pcap, f)
print("💾 PCAP Label Encoder saved under: label_encoder_pcap.pkl")

# 6. Split the data into training and testing sets
X_train_pcap, X_test_pcap, y_train_pcap, y_test_pcap = train_test_split(X_pcap, y_encoded_pcap, test_size=0.2, random_state=42)
print(f"PCAP dataset split into training (80%) and testing (20%) sets.")
print(f"X_train_pcap shape: {X_train_pcap.shape}, y_train_pcap shape: {y_train_pcap.shape}")
print(f"X_test_pcap shape: {X_test_pcap.shape}, y_test_pcap shape: {y_test_pcap.shape}")

model_performance_pcap = {}
print("Created an empty dictionary 'model_performance_pcap' for storing model performance.")


from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import seaborn as sns
import matplotlib.pyplot as plt
import pickle
import joblib

# Ensure le_pcap is loaded and model_performance_pcap is available
if 'le_pcap' not in globals():
    with open("label_encoder_pcap.pkl", "rb") as f:
        le_pcap = pickle.load(f)

target_names_pcap = [str(cls) for cls in le_pcap.classes_]

if 'model_performance_pcap' not in globals():
    model_performance_pcap = {}

# 2. Initialize RandomForestClassifier
print("\n🧠 Initializing and training Random Forest Classifier for PCAP-derived data...")
clf_pcap = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)

# 3. Train the classifier on PCAP-derived data
clf_pcap.fit(X_train_pcap, y_train_pcap)
print("✅ Random Forest Classifier for PCAP-derived data trained successfully!")

# 4. Make predictions
y_pred_pcap_rf = clf_pcap.predict(X_test_pcap)

# 5. Print classification report
print("\n--- Random Forest Classification Report for PCAP-derived data ---")
report_pcap_rf = classification_report(y_test_pcap, y_pred_pcap_rf, target_names=target_names_pcap, labels=le_pcap.transform(le_pcap.classes_), output_dict=True, zero_division=0)
print(classification_report(y_test_pcap, y_pred_pcap_rf, target_names=target_names_pcap, labels=le_pcap.transform(le_pcap.classes_), zero_division=0))

# 6. Create and plot confusion matrix
cm_pcap_rf = confusion_matrix(y_test_pcap, y_pred_pcap_rf, labels=le_pcap.transform(le_pcap.classes_))
plt.figure(figsize=(10, 8))
sns.heatmap(
    cm_pcap_rf,
    annot=True,
    fmt='d',
    cmap='Blues',
    xticklabels=target_names_pcap,
    yticklabels=target_names_pcap
)
plt.xlabel('Predicted Label')
plt.ylabel('True Label')
plt.title('Random Forest Confusion Matrix - PCAP-derived data')
plt.show()

# 7. Calculate overall accuracy
accuracy_pcap_rf = accuracy_score(y_test_pcap, y_pred_pcap_rf)
print(f"🎯 Random Forest Overall Accuracy for PCAP-derived data: {accuracy_pcap_rf:.4f}")

# 8. Store performance metrics in model_performance_pcap
model_performance_pcap['Random Forest'] = {
    'model': clf_pcap,
    'accuracy': accuracy_pcap_rf,
    'classification_report': report_pcap_rf
}
print("Random Forest model performance for PCAP-derived data stored.")

# Save the Random Forest model
joblib.dump(clf_pcap, 'random_forest_model_pcap.pkl')
print("Random Forest model for PCAP-derived data saved as random_forest_model_pcap.pkl")
# The LabelEncoder (le_pcap) was already saved in the data preprocessing step (label_encoder_pcap.pkl).
# Ensure le_pcap and model_performance_pcap are available
# le_pcap is from previous data preprocessing
# model_performance_pcap was initialized previously


target_names_pcap = [str(cls) for cls in le_pcap.classes_]

# 2. Initialize XGBClassifier
print("\nInitializing and training XGBoost Classifier for PCAP-derived data...")
xgb_model_pcap = xgb.XGBClassifier(
    objective='multi:softmax', # For multiclass classification
    num_class=len(le_pcap.classes_),
    use_label_encoder=False,
    eval_metric='mlogloss',
    n_estimators=100,
    random_state=42,
    n_jobs=-1 # Use all available cores
)

# 3. Train the XGBClassifier on PCAP-derived data
xgb_model_pcap.fit(X_train_pcap, y_train_pcap)
print("✅ XGBoost Classifier for PCAP-derived data trained successfully!")

# 4. Make predictions
y_pred_xgb_pcap = xgb_model_pcap.predict(X_test_pcap)

# 5. Print classification report
print("\n--- XGBoost Classification Report for PCAP-derived data ---")
report_xgb_pcap = classification_report(y_test_pcap, y_pred_xgb_pcap, target_names=target_names_pcap, labels=le_pcap.transform(le_pcap.classes_), output_dict=True, zero_division=0)
print(classification_report(y_test_pcap, y_pred_xgb_pcap, target_names=target_names_pcap, labels=le_pcap.transform(le_pcap.classes_), zero_division=0))

# 6. Create and plot confusion matrix
cm_xgb_pcap = confusion_matrix(y_test_pcap, y_pred_xgb_pcap, labels=le_pcap.transform(le_pcap.classes_))
plt.figure(figsize=(10, 8))
sns.heatmap(
    cm_xgb_pcap,
    annot=True,
    fmt='d',
    cmap='Blues',
    xticklabels=target_names_pcap,
    yticklabels=target_names_pcap
)
plt.xlabel('Predicted Label')
plt.ylabel('True Label')
plt.title('XGBoost Confusion Matrix - PCAP-derived data')
plt.show()

# 7. Calculate overall accuracy
accuracy_xgb_pcap = accuracy_score(y_test_pcap, y_pred_xgb_pcap)
print(f"🎯 XGBoost Overall Accuracy for PCAP-derived data: {accuracy_xgb_pcap:.4f}")

# 8. Store performance metrics in model_performance_pcap
model_performance_pcap['XGBoost'] = {
    'model': xgb_model_pcap,
    'accuracy': accuracy_xgb_pcap,
    'classification_report': report_xgb_pcap
}
print("XGBoost model performance for PCAP-derived data stored.")

# Save the XGBoost model (optional)
with open("xgboost_model_pcap.pkl", "wb") as f:
    pickle.dump(xgb_model_pcap, f)
print("XGBoost model for PCAP-derived data saved as xgboost_model_pcap.pkl")