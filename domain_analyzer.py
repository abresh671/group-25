#!/usr/bin/env python3
"""
Domain analysis module with WHOIS and registration verification
"""

import whois
import socket
import requests
from datetime import datetime, timedelta
from urllib.parse import urlparse
import re

class DomainAnalyzer:
    def __init__(self):
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.cc', '.info']
        self.trusted_registrars = ['godaddy', 'namecheap', 'google', 'amazon', 'cloudflare']
    
    def extract_domain(self, url):
        """Extract domain from URL"""
        try:
            parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'http://{url}')
            return parsed.netloc.lower()
        except:
            return None
    
    def get_whois_info(self, domain):
        """Get WHOIS information for domain"""
        try:
            w = whois.whois(domain)
            return {
                'domain': domain,
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'updated_date': w.updated_date,
                'name_servers': w.name_servers,
                'status': w.status,
                'country': w.country,
                'org': w.org,
                'emails': w.emails
            }
        except Exception as e:
            return {'error': str(e), 'domain': domain}
    
    def check_domain_age(self, whois_info):
        """Check if domain is newly registered (suspicious)"""
        if 'creation_date' not in whois_info or not whois_info['creation_date']:
            return {'age_days': None, 'is_new': None, 'risk': 'unknown'}
        
        creation_date = whois_info['creation_date']
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if isinstance(creation_date, str):
            return {'age_days': None, 'is_new': None, 'risk': 'unknown'}
        
        age = datetime.now() - creation_date
        age_days = age.days
        
        is_new = age_days < 30  # Less than 30 days is suspicious
        risk = 'high' if age_days < 7 else 'medium' if age_days < 30 else 'low'
        
        return {
            'age_days': age_days,
            'is_new': is_new,
            'risk': risk,
            'creation_date': creation_date.isoformat()
        }
    
    def check_registrar_reputation(self, whois_info):
        """Check if registrar is reputable"""
        if 'registrar' not in whois_info or not whois_info['registrar']:
            return {'is_trusted': None, 'risk': 'unknown'}
        
        registrar = whois_info['registrar'].lower()
        is_trusted = any(trusted in registrar for trusted in self.trusted_registrars)
        
        return {
            'registrar': whois_info['registrar'],
            'is_trusted': is_trusted,
            'risk': 'low' if is_trusted else 'medium'
        }
    
    def check_suspicious_tld(self, domain):
        """Check if domain uses suspicious TLD"""
        tld = '.' + domain.split('.')[-1] if '.' in domain else ''
        is_suspicious = tld in self.suspicious_tlds
        
        return {
            'tld': tld,
            'is_suspicious': is_suspicious,
            'risk': 'high' if is_suspicious else 'low'
        }
    
    def check_dns_records(self, domain):
        """Check DNS records for domain"""
        try:
            ip = socket.gethostbyname(domain)
            return {
                'has_dns': True,
                'ip_address': ip,
                'risk': 'low'
            }
        except socket.gaierror:
            return {
                'has_dns': False,
                'ip_address': None,
                'risk': 'high'
            }
    
    def analyze_domain(self, url):
        """Complete domain analysis"""
        domain = self.extract_domain(url)
        if not domain:
            return {'error': 'Invalid URL or domain'}
        
        # Get WHOIS info
        whois_info = self.get_whois_info(domain)
        
        # Perform various checks
        age_check = self.check_domain_age(whois_info)
        registrar_check = self.check_registrar_reputation(whois_info)
        tld_check = self.check_suspicious_tld(domain)
        dns_check = self.check_dns_records(domain)
        
        # Calculate overall risk score
        risk_scores = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'unknown': 1.5
        }
        
        total_risk = (
            risk_scores.get(age_check['risk'], 1.5) +
            risk_scores.get(registrar_check['risk'], 1.5) +
            risk_scores.get(tld_check['risk'], 1) +
            risk_scores.get(dns_check['risk'], 1)
        )
        
        avg_risk = total_risk / 4
        overall_risk = 'high' if avg_risk >= 2.5 else 'medium' if avg_risk >= 1.8 else 'low'
        
        return {
            'domain': domain,
            'url': url,
            'whois_info': whois_info,
            'age_analysis': age_check,
            'registrar_analysis': registrar_check,
            'tld_analysis': tld_check,
            'dns_analysis': dns_check,
            'overall_risk': overall_risk,
            'risk_score': round(avg_risk, 2),
            'timestamp': datetime.now().isoformat()
        }

def analyze_domain_cli(url):
    """CLI function for domain analysis"""
    analyzer = DomainAnalyzer()
    result = analyzer.analyze_domain(url)
    
    if 'error' in result:
        print(f"[ERROR] {result['error']}")
        return
    
    print(f"\n{'='*60}")
    print(f"DOMAIN ANALYSIS: {result['domain']}")
    print(f"{'='*60}")
    
    # WHOIS Info
    whois = result['whois_info']
    if 'error' not in whois:
        print(f"Registrar: {whois.get('registrar', 'Unknown')}")
        print(f"Creation Date: {whois.get('creation_date', 'Unknown')}")
        print(f"Expiration Date: {whois.get('expiration_date', 'Unknown')}")
        print(f"Country: {whois.get('country', 'Unknown')}")
    else:
        print(f"WHOIS Error: {whois['error']}")
    
    # Risk Analysis
    print(f"\nRISK ANALYSIS:")
    print(f"Overall Risk: {result['overall_risk'].upper()} ({result['risk_score']}/3.0)")
    
    age = result['age_analysis']
    if age['age_days'] is not None:
        print(f"Domain Age: {age['age_days']} days ({'NEW' if age['is_new'] else 'ESTABLISHED'})")
    
    reg = result['registrar_analysis']
    if reg['is_trusted'] is not None:
        print(f"Registrar: {'TRUSTED' if reg['is_trusted'] else 'UNKNOWN'}")
    
    tld = result['tld_analysis']
    print(f"TLD: {tld['tld']} ({'SUSPICIOUS' if tld['is_suspicious'] else 'NORMAL'})")
    
    dns = result['dns_analysis']
    print(f"DNS: {'RESOLVED' if dns['has_dns'] else 'NO RESOLUTION'}")
    if dns['ip_address']:
        print(f"IP Address: {dns['ip_address']}")
    
    print(f"{'='*60}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        analyze_domain_cli(sys.argv[1])
    else:
        print("Usage: python domain_analyzer.py <url>")