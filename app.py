from urllib.parse import urlparse
import re
import streamlit as st
import numpy as np
import joblib

# scaler와 model을 미리 불러옵니다 (경로는 환경에 맞게 수정)
scaler = joblib.load('scaler.pkl')
model = joblib.load('xgb_phishing_model.pkl')

def extract_features_from_url(url):
    parsed = urlparse(url)
    hostname = parsed.hostname if parsed.hostname else ''
    path = parsed.path

    num_dots = url.count('.')
    path_level = path.count('/')
    url_length = len(url)
    num_dash = url.count('-')
    at_symbol = 1 if '@' in url else 0

    # IpAddress: URL에 IPv4 또는 IPv6 주소가 포함되어 있으면 1, 아니면 0
    ipv4_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    ipv6_pattern = r'([0-9a-fA-F:]+:+)+[0-9a-fA-F]+'
    ip_address = 1 if re.search(ipv4_pattern, url) or re.search(ipv6_pattern, url) else 0

    # HttpsInHostname: hostname에 'https'가 포함되어 있으면 1, 아니면 0
    https_in_hostname = 1 if 'https' in hostname.lower() else 0

    path_length = len(path)
    num_numeric = sum(c.isdigit() for c in url)

    # feature 순서 반드시 모델 학습과 동일하게 유지
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

            # 라벨 매핑 (0: Legitimate, 1: Phishing) - 필요시 수정
            label_map = {0: "✅ Legitimate URL", 1: "⚠️ Phishing URL!"}
            result_text = label_map.get(prediction, f"Unknown ({prediction})")

            st.markdown(f"## Result: {result_text}")

            # 확률 정보 명확히 표시
            st.write(f"Probability (Legitimate): {probability[0]:.4f}")
            st.write(f"Probability (Phishing): {probability[1]:.4f}")

            # 추출된 feature 값 표시
            st.write("Extracted Features (순서: num_dots, path_level, url_length, num_dash, at_symbol, ip_address, https_in_hostname, path_length, num_numeric):")
            st.write(features)
        except Exception as e:
            st.error(f"An error occurred during prediction: {e}")
    else:
        st.warning("Please enter a URL.")
