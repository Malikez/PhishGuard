import re
import socket
import urllib
import whois
import requests
import numpy as np
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime
from collections import Counter


def extract_features_from_url(url):
    """This function checks for some features in some URL and extract them for analysis """
    features = {}

    # Basic URL parsing
    parsed_url = urlparse(url if url.startswith('http') else "http://" + url)
    domain = parsed_url.netloc
    path = parsed_url.path
    hostname = parsed_url.hostname if parsed_url.hostname else ''

    # WHOIS domain info
    try:
        domain_info = whois.whois(domain)
        if domain_info.domain_name:
            domain_registration_length = (
                (domain_info.expiration_date - domain_info.creation_date).days
                if domain_info.creation_date and domain_info.expiration_date
                else 0
            )
            domain_age = (
                (datetime.now() - domain_info.creation_date).days
                if domain_info.creation_date
                else 0
            )
            whois_status = 0
        else:
            domain_registration_length = 0
            domain_age = 0
            whois_status = 1
    except:
        domain_registration_length = 0
        domain_age = 0
        whois_status = 1

    features['status'] = whois_status

    # Page content-based features
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        hyperlinks = soup.find_all('a', href=True)
        features['nb_hyperlinks'] = len(hyperlinks)
        features['nb_www'] = sum(1 for a in hyperlinks if 'www' in a['href'])
        features['ratio_extHyperlinks'] = sum(1 for a in hyperlinks if urlparse(a['href']).netloc and domain not in a['href']) / len(hyperlinks) if hyperlinks else 0
        features['ratio_intHyperlinks'] = sum(1 for a in hyperlinks if domain in a['href']) / len(hyperlinks) if hyperlinks else 0
        features['safe_anchor'] = sum(1 for a in hyperlinks if '#' not in a['href']) / len(hyperlinks) if hyperlinks else 0
        features['links_in_tags'] = len(soup.find_all(['meta', 'script', 'link']))
        title = soup.title.string.lower() if soup.title else ''
    except:
        hyperlinks = []
        features['nb_hyperlinks'] = 0
        features['nb_www'] = 0
        features['ratio_extHyperlinks'] = 0
        features['ratio_intHyperlinks'] = 0
        features['safe_anchor'] = 0
        features['links_in_tags'] = 0
        title = ''

    # Raw character and path analysis
    path_words = re.split(r'\W+', path)
    raw_words = re.split(r'\W+', url)
    host_words = re.split(r'\W+', hostname)

    features['domain_in_title'] = 1 if domain.lower() in title else 0
    features['ratio_extRedirection'] = sum(1 for a in hyperlinks if a['href'].startswith('http')) / len(hyperlinks) if hyperlinks else 0
    features['domain_age'] = domain_age
    features['ratio_digits_url'] = sum(c.isdigit() for c in url) / len(url) if url else 0
    features['longest_words_raw'] = max([len(w) for w in raw_words]) if raw_words else 0
    features['char_repeat'] = max(Counter(url).values()) if url else 0
    features['length_words_raw'] = sum(len(w) for w in raw_words)
    features['shortest_word_host'] = min([len(w) for w in host_words]) if host_words else 0
    features['length_url'] = len(url)
    features['length_hostname'] = len(hostname)
    features['ratio_digits_host'] = sum(c.isdigit() for c in hostname) / len(hostname) if hostname else 0
    features['domain_registration_length'] = domain_registration_length
    features['nb_dots'] = url.count('.')
    features['nb_slash'] = url.count('/')

    return {
        'status': features['status'],
        'nb_hyperlinks': features['nb_hyperlinks'],
        'nb_www': features['nb_www'],
        'ratio_extHyperlinks': features['ratio_extHyperlinks'],
        'domain_age': features['domain_age'],
        'ratio_intHyperlinks': features['ratio_intHyperlinks'],
        'ratio_digits_url': features['ratio_digits_url'],
        'domain_in_title': features['domain_in_title'],
        'ratio_extRedirection': features['ratio_extRedirection'],
        'safe_anchor': features['safe_anchor'],
        'links_in_tags': features['links_in_tags'],
        'longest_words_raw': features['longest_words_raw'],
        'char_repeat': features['char_repeat'],
        'length_words_raw': features['length_words_raw'],
        'shortest_word_host': features['shortest_word_host'],
        'length_url': features['length_url'],
        'length_hostname': features['length_hostname'],
        'ratio_digits_host': features['ratio_digits_host'],
        'domain_registration_length': features['domain_registration_length'],
        'nb_dots': features['nb_dots'],
        'nb_slash': features['nb_slash']
    }
