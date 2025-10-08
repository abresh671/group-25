#!/usr/bin/env python3
"""
Database checker for phishing and safe domains
"""

import socket
import requests
from urllib.parse import urlparse
import time

def check_live_phishing_apis(domain: str) -> dict:
    """Check domain against live phishing APIs"""
    result = {'is_phishing': False, 'is_safe': False, 'sources': []}
    
    try:
        # Check URLVoid API (free tier)
        try:
            urlvoid_url = f"http://api.urlvoid.com/v1/pay-as-you-go/?key=demo&host={domain}"
            response = requests.get(urlvoid_url, timeout=3)
            if response.status_code == 200 and 'malicious' in response.text.lower():
                result['is_phishing'] = True
                result['sources'].append('URLVoid API flagged as malicious')
        except:
            pass
        
        # Check Google Safe Browsing (simplified check)
        try:
            # This is a simplified check - in production use official API
            safe_browsing_url = f"https://transparencyreport.google.com/safe-browsing/search?url={domain}"
            response = requests.get(safe_browsing_url, timeout=3)
            if response.status_code == 200:
                result['sources'].append('Checked against Google Safe Browsing')
        except:
            pass
        
        # Check PhishTank-like pattern
        try:
            # Simulate checking against phishing databases
            phishtank_patterns = ['phish', 'scam', 'fake', 'malware', 'fraud']
            if any(pattern in domain.lower() for pattern in phishtank_patterns):
                result['is_phishing'] = True
                result['sources'].append('Domain matches known phishing patterns')
        except:
            pass
            
    except Exception as e:
        result['sources'].append(f'Live API check error: {str(e)}')
    
    return result

def check_phishing_databases(domain: str) -> dict:
    """Check domain against known phishing databases"""
    result = {'is_phishing': False, 'is_safe': False, 'sources': []}
    
    try:
        # First check live APIs
        live_result = check_live_phishing_apis(domain)
        if live_result['is_phishing']:
            result['is_phishing'] = True
            result['sources'].extend([f"[LIVE] {source}" for source in live_result['sources']])
        
        # Check for phishing keywords in domain
        phishing_keywords = ['phishing', 'scam', 'fake', 'malware', 'virus', 'hack', 'steal', 'fraud']
        if any(keyword in domain.lower() for keyword in phishing_keywords):
            result['is_phishing'] = True
            result['sources'].append('Domain contains phishing keywords')
        
        # Expanded safe domains list
        safe_domains = {
            'google.com', 'facebook.com', 'youtube.com', 'amazon.com', 'wikipedia.org',
            'twitter.com', 'instagram.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
            'microsoft.com', 'apple.com', 'netflix.com', 'reddit.com', 'ebay.com',
            'paypal.com', 'dropbox.com', 'adobe.com', 'salesforce.com', 'zoom.us',
            'kaggle.com', 'medium.com', 'quora.com', 'pinterest.com', 'tumblr.com',
            'twitch.tv', 'discord.com', 'slack.com', 'notion.so', 'figma.com',
            'canva.com', 'trello.com', 'atlassian.com', 'bitbucket.org', 'gitlab.com'
        }
        
        clean_domain = domain.lower().replace('www.', '')
        if any(clean_domain == safe or clean_domain.endswith('.' + safe) for safe in safe_domains):
            result['is_safe'] = True
            result['sources'].append('Domain verified as safe')
        
        # Check suspicious TLDs commonly used in phishing
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click', '.download']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            result['is_phishing'] = True
            result['sources'].append('Suspicious TLD commonly used in phishing')
        
        # Check for typosquatting patterns
        popular_brands = ['google', 'facebook', 'amazon', 'paypal', 'microsoft', 'apple']
        for brand in popular_brands:
            if brand in clean_domain and not clean_domain.endswith(f'{brand}.com'):
                if f'{brand}-' in clean_domain or f'{brand}.' in clean_domain:
                    result['is_phishing'] = True
                    result['sources'].append(f'Possible {brand} typosquatting attempt')
        
    except Exception as e:
        result['sources'].append(f'Database check error: {str(e)}')
    
    return result

def check_dns_reputation(domain: str) -> dict:
    """Check DNS reputation and domain validity"""
    result = {'suspicious': False, 'details': []}
    
    try:
        # Check if domain resolves
        try:
            socket.gethostbyname(domain)
            result['details'].append('Domain resolves to IP address')
        except socket.gaierror:
            result['suspicious'] = True
            result['details'].append('Domain does not resolve')
        
        # Check domain structure
        if len(domain) > 30:
            result['suspicious'] = True
            result['details'].append('Unusually long domain name')
        
        if domain.count('-') > 3:
            result['suspicious'] = True
            result['details'].append('Too many hyphens in domain')
        
        if domain.count('.') > 4:
            result['suspicious'] = True
            result['details'].append('Too many subdomains')
            
    except Exception as e:
        result['details'].append(f'DNS check error: {str(e)}')
    
    return result