from urllib.parse import urlparse
import re
import streamlit as st
import numpy as np
import joblib

# scaler와 model을 미리 불러옵니다 (경로는 환경에 맞게 수정)
scaler = joblib.load('scaler.pkl')
model = joblib.load('model.pkl')

def extract_features_from_url(url):
    parsed = urlparse(url)
    hostname = parsed.hostname if parsed.hostname else ''
    path = parsed.path

    num_dots = url.count('.')
    num_dash = url.count('-')
    num_numeric = sum(c.isdigit() for c in url)
    at_symbol = 1 if '@' in url else 0

    # IpAddress: URL에 IPv4 또는 IPv6 주소가 포함되어 있으면 1, 아니면 0
    ipv4_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    ipv6_pattern = r'([0-9a-fA-F:]+:+)+[0-9a-fA-F]+'
    ip_address = 1 if re.search(ipv4_pattern, url) or re.search(ipv6_pattern, url) else 0

    # HttpsInHostname: hostname에 'https'가 포함되어 있으면 1, 아니면 0
    https_in_hostname = 1 if 'https' in hostname.lower() else 0

    path_level = path.count('/')
    url_length = len(url)
    path_length = len(path)

    return [
        num_dots,
        path_level,
        url_length,
        num_dash,
        at_symbol,
        ip_address,
        https_in_hostname,
        path_length,
        num_numeric
    ]

# Streamlit UI
st.title("🔍 Phishing URL Detection App")
st.markdown("Enter a URL below to check if it is a phishing attempt.")

url_input = st.text_input("Enter a URL:")

if st.button("Predict"):
    if url_input:
        try:
            # URL feature 추출
            features = extract_features_from_url(url_input)
            X_input = np.array(features).reshape(1, -1)
            X_scaled = scaler.transform(X_input)
            
            # 모델 예측
            prediction = model.predict(X_scaled)[0]
            probability = model.predict_proba(X_scaled)[0].tolist()
            
            # 결과 표시
            result_text = "✅ Legitimate URL" if prediction == 0 else "⚠️ Phishing URL!"
            st.markdown(f"## Result: {result_text}")
            st.write(f"Probability: {probability}")
            st.write(f"Extracted Features: {features}")
        except Exception as e:
            st.error(f"An error occurred during prediction: {e}")
    else:
        st.warning("Please enter a URL.")
