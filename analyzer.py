

# analyzer.py
import requests
import hashlib
import socket
import ssl
from datetime import datetime
import whois
import base64
from io import BytesIO
from joblib import load


model = load('real_phishing_model.joblib')

# function to extract SSL info
def extract_ssl_info(url):
    """"This function extracts ssl details from a given URL.
     Returns a dictionary with SSL details and status."""
    ssl_data = {
        'has_ssl': 0,
        'expired': 0,
        'details': None,
        'message': None
    }

    try:
        hostname = url.replace('https://', '').replace('http://', '').split('/')[0]
        ctx = ssl.create_default_context()

        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()

            ssl_data['has_ssl'] = 1
            ssl_data['details'] = {
                'subject': dict(x[0] for x in cert.get('subject', [])),
                'issuer': dict(x[0] for x in cert.get('issuer', [])),
                'version': cert.get('version'),
                'serialNumber': cert.get('serialNumber'),
                'notBefore': cert.get('notBefore'),
                'notAfter': cert.get('notAfter'),
            }

            not_after = cert.get('notAfter')
            if not_after:
                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                ssl_data['expired'] = 1 if expiry_date < datetime.utcnow() else 0
                ssl_data['message'] = 'SSL certificate retrieved successfully.'
            else:
                ssl_data['message'] = 'SSL certificate retrieved but no expiry date found.'

    except socket.gaierror:
        ssl_data['message'] = 'SSL check failed: invalid or unreachable hostname.'
    except ssl.SSLError:
        ssl_data['message'] = 'SSL check failed: SSL error (no certificate or handshake failed).'
    except Exception:
        ssl_data['message'] = 'SSL check failed: general error or timeout.'

    return ssl_data


def get_domain_age(url):
    """
    This function retrieves the age of a domain using RDAP (Registration Data Access Protocol).
    RDAP is the modern, HTTPS-native replacement for WHOIS.
    """
    from datetime import datetime
    import requests

    age_info = {'age': 0, 'message': None}

    try:
        # Extract the clean hostname
        domain = url.replace('https://', '').replace('http://', '').split('/')[0]

        # Query the official RDAP bootstrap server
        api_url = f"https://rdap.org/domain/{domain}"

        # Mask the script as a standard web browser to bypass basic bot blocks
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }

        response = requests.get(api_url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            creation_str = None

            # RDAP standardizes data into an 'events' list. We search for the registration event.
            for event in data.get('events', []):
                if event.get('eventAction') == 'registration':
                    creation_str = event.get('eventDate')
                    break

            if creation_str:
                # RDAP dates are formatted like "1997-09-15T04:00:00Z"
                # Slice the first 10 characters to extract just "YYYY-MM-DD"
                creation_date = datetime.strptime(creation_str[:10], "%Y-%m-%d")

                age = (datetime.utcnow() - creation_date).days
                age_info['age'] = age
                age_info['message'] = f'Domain age is {age} days.'
            else:
                age_info['message'] = 'Domain registration date missing from RDAP record.'
        else:
            age_info['message'] = f'RDAP lookup failed (HTTP {response.status_code}).'

    except Exception as e:
        age_info['age'] = 0
        age_info['message'] = f'Domain age could not be determined ({str(e)}).'

    return age_info


def get_hashes(url):
    md5_hash = hashlib.md5(url.encode()).hexdigest()
    sha256_hash = hashlib.sha256(url.encode()).hexdigest()
    return {'md5': md5_hash, 'sha256': sha256_hash}


def get_screenshot_base64(url, api_key):
    import requests
    import base64

    base_url = "https://api.apiflash.com/v1/urltoimage"
    params = {
        "access_key": api_key,
        "url": url,
        "wait_until": "page_loaded",
        "width": 1280,
        "height": 720,
        "format": "png",
        "full_page": True,
    }
    try:
        response = requests.get(base_url, params=params)
        response.raise_for_status()
        # Encode the image in base64 for embedding in HTML
        img_base64 = base64.b64encode(response.content).decode('utf-8')
        return {'screenshot_base64': img_base64}
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code if e.response else None
        if status_code == 400:
            return {'error': "Screenshot not available: Bad request or invalid URL."}
        else:
            return {'error': f"Screenshot error: Received status code {status_code}."}
    except requests.exceptions.RequestException:
        return {'error': "Screenshot not available: Network or API error."}
    except Exception:
        return {'error': "Screenshot not available: Unexpected error."}


def analyze_url(url, api_key):
    """
    This function analyzes a URL and generates a report.
    """
    report = {}
    reasons = []
    good_traits = []
    bad_traits = []
    score = 0

    # SSL Info
    ssl_info = extract_ssl_info(url)
    report['ssl_info'] = ssl_info
    if ssl_info.get('has_ssl') == 0:
        reasons.append('No SSL certificate detected (+3 points).')
        score += 3
    elif ssl_info.get('expired') == 1:
        reasons.append('SSL certificate is expired (+3 points).')
        score += 3
    else:
        reasons.append('SSL certificate is valid (+0 points).')

    # Domain Age
    age_info = get_domain_age(url)
    report['domain_age'] = age_info
    age_days = age_info.get('age', 0)
    if age_days < 30:
        reasons.append(f"Domain is very new ({age_days} days old) (+3 points).")
        score += 3
    elif age_days < 180:
        reasons.append(f"Domain is newish ({age_days} days old) (+2 points).")
        score += 2
    else:
        reasons.append(f"Domain is established ({age_days} days old) (+0 points).")

    # Screenshot
    screenshot = get_screenshot_base64(url, api_key)
    report['screenshot'] = screenshot

    # Hashes
    hashes = get_hashes(url)
    report['hashes'] = hashes

    # Prediction and feature-based trait analysis
    try:
        import pandas as pd
        from feature_extrator import extract_features_from_url

        features_df = extract_features_from_url(url)
        if not isinstance(features_df, pd.DataFrame):
            features_df = pd.DataFrame([features_df])

        if 'status' in features_df.columns:
            features_df = features_df.drop(columns=['status'])

        prediction = int(model.predict(features_df)[0])
        label = "Phishing" if prediction == 1 else "Legitimate"
        reasons.append(f"Model prediction: {label} (+{6 if prediction == 1 else 0} points).")
        if prediction == 1:
            score += 6

        # Transparency: good and bad traits based on selected features
        selected_features = [
            'google_index', 'web_traffic', 'page_rank', 'nb_www',
            'longest_word_path', 'length_hostname', 'longest_words_raw',
            'url', 'links_in_tags', 'domain_in_title'
        ]

        feature_values = features_df.iloc[0].to_dict()

        for feature in selected_features:
            value = feature_values.get(feature)

            if feature in ['google_index', 'web_traffic', 'page_rank', 'nb_www', 'links_in_tags', 'domain_in_title']:
                if value and value > 0:
                    good_traits.append(f"{feature} is present/positive ")
                else:
                    bad_traits.append(f"{feature} is missing or low ")
            elif feature in ['length_hostname', 'longest_word_path', 'longest_words_raw', 'url']:
                if value is not None and value < 50:
                    good_traits.append(f"{feature} length is short ")
                else:
                    bad_traits.append(f"{feature} length is long or excessive ")

        if not good_traits:
            good_traits.append("No good traits detected.")
        if not bad_traits:
            bad_traits.append("No bad traits detected.")

        report['prediction'] = {'label': label}

    except Exception as e:
        report['prediction'] = {'error': f"Prediction error: {str(e)}"}
        reasons.append(f"Prediction error: {str(e)}")

    # Final score clamped
    final_score = min(score, 10)
    if final_score <= 3:
        risk_level = "Safe / Legitimate"
    elif 4 <= final_score <= 7:
        risk_level = "Suspicious"
    else:
        risk_level = "Phishing / Illegitimate"

    report.update({
        'reasons': reasons,
        'good_traits': good_traits,
        'bad_traits': bad_traits,
        'score': final_score,
        'risk_level': risk_level
    })

    return report
