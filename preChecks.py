"""
Pre-checks and quick lookups for phishing detection
Fast heuristics and external source checks before full feature extraction
"""

import re
import time
import logging
from typing import Dict, Any, Tuple, Optional
from urllib.parse import urlparse
import socket

logger = logging.getLogger(__name__)

class QuickPreChecker:
    """
    Performs quick pre-checks before full feature extraction
    Fast heuristics and simple lookups to catch obvious cases
    """
    
    def __init__(self):
        # Compile regex patterns for performance
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.suspicious_pattern = re.compile(r'(login|verify|secure|update|account|suspended)', re.IGNORECASE)
        
        # Known malicious domains (in production, use threat intelligence feeds)
        self.known_malicious = {
            'phishing-site.tk',
            'fake-paypal.ml', 
            'scam-bank.ga',
            'malware-download.cf',
            'suspicious-login.xyz'
        }
        
        # Legitimate domains whitelist
        self.known_legitimate = {
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'paypal.com', 'github.com', 'stackoverflow.com',
            'linkedin.com', 'twitter.com', 'instagram.com', 'youtube.com',
            'netflix.com', 'spotify.com', 'reddit.com', 'wikipedia.org'
        }
        
        # Suspicious TLDs
        self.suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.click'}
        
        # URL shorteners
        self.url_shorteners = {
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'short.link', 'tiny.cc', 'is.gd', 'buff.ly'
        }
    
    def quick_check(self, url: str) -> Dict[str, Any]:
        """
        Perform quick pre-checks on URL
        
        Args:
            url: URL to check
            
        Returns:
            Dictionary with check results and confidence
        """
        start_time = time.time()
        
        try:
            # Normalize URL
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Initialize results
            results = {
                'url': url,
                'domain': domain,
                'quick_decision': None,  # 'legitimate', 'suspicious', 'malicious', None
                'confidence': 0.0,
                'reasons': [],
                'should_skip_ml': False,  # If True, don't need ML prediction
                'risk_score': 0.0
            }
            
            # 1. Format validation
            format_check = self._check_url_format(url, parsed)
            results.update(format_check)
            
            # 2. Whitelist check (known legitimate)
            whitelist_check = self._check_whitelist(domain)
            if whitelist_check['is_whitelisted']:
                results['quick_decision'] = 'legitimate'
                results['confidence'] = 0.95
                results['should_skip_ml'] = True
                results['reasons'].append('Known legitimate domain')
                results['risk_score'] = 0.1
            
            # 3. Blacklist check (known malicious)
            elif self._check_blacklist(domain):
                results['quick_decision'] = 'malicious'
                results['confidence'] = 0.98
                results['should_skip_ml'] = True
                results['reasons'].append('Known malicious domain')
                results['risk_score'] = 0.95
            
            # 4. Quick heuristics
            else:
                heuristic_results = self._quick_heuristics(url, parsed, domain)
                results.update(heuristic_results)
            
            # 5. Calculate overall risk if no definitive decision
            if results['quick_decision'] is None:
                results['risk_score'] = self._calculate_risk_score(results)
                
                if results['risk_score'] > 0.8:
                    results['quick_decision'] = 'suspicious'
                    results['confidence'] = 0.7
                elif results['risk_score'] < 0.2:
                    results['quick_decision'] = 'legitimate'
                    results['confidence'] = 0.6
            
            results['check_time'] = time.time() - start_time
            
            logger.debug(f"Quick check completed in {results['check_time']:.3f}s: {results['quick_decision']}")
            
            return results
            
        except Exception as e:
            logger.error(f"Quick check failed for {url}: {e}")
            return {
                'url': url,
                'quick_decision': None,
                'confidence': 0.0,
                'reasons': [f'Check failed: {str(e)}'],
                'should_skip_ml': False,
                'risk_score': 0.5,
                'check_time': time.time() - start_time
            }
    
    def _check_url_format(self, url: str, parsed) -> Dict[str, Any]:
        """Check URL format and structure"""
        issues = []
        
        # Check for IP address instead of domain
        if self.ip_pattern.search(parsed.netloc):
            issues.append('Uses IP address instead of domain')
        
        # Check for suspicious characters
        suspicious_chars = ['@', '#']
        for char in suspicious_chars:
            if char in parsed.netloc:
                issues.append(f'Suspicious character in domain: {char}')
        
        # Check for excessive length
        if len(url) > 200:
            issues.append('Extremely long URL')
        
        # Check for multiple subdomains
        if parsed.netloc.count('.') > 4:
            issues.append('Excessive subdomain levels')
        
        # Check for non-standard ports
        if parsed.port and parsed.port not in [80, 443]:
            issues.append(f'Non-standard port: {parsed.port}')
        
        return {
            'format_issues': issues,
            'has_format_issues': len(issues) > 0
        }
    
    def _check_whitelist(self, domain: str) -> Dict[str, Any]:
        """Check against whitelist of known legitimate domains"""
        # Remove www. prefix for checking
        clean_domain = domain.replace('www.', '')
        
        # Check exact match
        if clean_domain in self.known_legitimate:
            return {'is_whitelisted': True, 'whitelist_match': clean_domain}
        
        # Check if it's a subdomain of a legitimate domain
        for legit_domain in self.known_legitimate:
            if clean_domain.endswith('.' + legit_domain):
                return {'is_whitelisted': True, 'whitelist_match': legit_domain}
        
        return {'is_whitelisted': False, 'whitelist_match': None}
    
    def _check_blacklist(self, domain: str) -> bool:
        """Check against blacklist of known malicious domains"""
        clean_domain = domain.replace('www.', '')
        return clean_domain in self.known_malicious
    
    def _quick_heuristics(self, url: str, parsed, domain: str) -> Dict[str, Any]:
        """Apply quick heuristic rules"""
        reasons = []
        risk_factors = 0
        
        # 1. Suspicious TLD check
        if any(tld in url.lower() for tld in self.suspicious_tlds):
            reasons.append('Uses suspicious TLD (.tk, .ml, .ga, .cf, etc.)')
            risk_factors += 2
        
        # 2. URL shortener check
        if any(shortener in domain for shortener in self.url_shorteners):
            reasons.append('URL shortener detected')
            risk_factors += 1
        
        # 3. Suspicious keywords
        suspicious_matches = self.suspicious_pattern.findall(url)
        if suspicious_matches:
            reasons.append(f'Contains suspicious keywords: {", ".join(set(suspicious_matches))}')
            risk_factors += len(set(suspicious_matches))
        
        # 4. Brand name abuse detection
        brand_abuse = self._check_brand_abuse(domain)
        if brand_abuse:
            reasons.append(f'Potential brand abuse: {brand_abuse}')
            risk_factors += 3
        
        # 5. Homograph/typosquatting detection
        if self._check_typosquatting(domain):
            reasons.append('Potential typosquatting detected')
            risk_factors += 2
        
        # 6. No HTTPS for sensitive operations
        if not url.startswith('https://') and any(word in url.lower() for word in ['login', 'account', 'secure']):
            reasons.append('No HTTPS for sensitive operations')
            risk_factors += 1
        
        return {
            'heuristic_reasons': reasons,
            'risk_factors': risk_factors
        }
    
    def _check_brand_abuse(self, domain: str) -> Optional[str]:
        """Check for brand name abuse in domain"""
        brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook']
        
        for brand in brands:
            if brand in domain.lower():
                # Check if it's the legitimate domain
                if domain.lower() in [f'{brand}.com', f'www.{brand}.com']:
                    continue
                # Check if it's a legitimate subdomain
                if domain.lower().endswith(f'.{brand}.com'):
                    continue
                # Otherwise, it's suspicious
                return brand
        
        return None
    
    def _check_typosquatting(self, domain: str) -> bool:
        """Basic typosquatting detection"""
        # Check for common typosquatting patterns
        typo_patterns = [
            r'g[o0]{2}gle',  # google variations
            r'fac[e3]b[o0]{2}k',  # facebook variations
            r'amaz[o0]n',  # amazon variations
            r'micr[o0]s[o0]ft',  # microsoft variations
        ]
        
        for pattern in typo_patterns:
            if re.search(pattern, domain.lower()):
                return True
        
        return False
    
    def _calculate_risk_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall risk score from quick checks"""
        score = 0.0
        
        # Format issues
        if results.get('has_format_issues'):
            score += 0.3
        
        # Risk factors from heuristics
        risk_factors = results.get('risk_factors', 0)
        score += min(risk_factors * 0.15, 0.6)
        
        # Ensure score is between 0 and 1
        return min(max(score, 0.0), 1.0)
    
    def check_connectivity(self, domain: str, timeout: int = 3) -> Dict[str, Any]:
        """
        Check if domain is reachable (optional network check)
        
        Args:
            domain: Domain to check
            timeout: Connection timeout
            
        Returns:
            Connectivity information
        """
        try:
            # Try to resolve domain
            ip = socket.gethostbyname(domain)
            
            # Try to connect to port 80
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, 80))
            sock.close()
            
            return {
                'is_reachable': result == 0,
                'resolved_ip': ip,
                'connection_successful': result == 0
            }
            
        except Exception as e:
            return {
                'is_reachable': False,
                'resolved_ip': None,
                'connection_successful': False,
                'error': str(e)
            }

def quick_pre_check(url: str) -> Dict[str, Any]:
    """
    Convenience function for quick pre-checking
    
    Args:
        url: URL to check
        
    Returns:
        Pre-check results
    """
    checker = QuickPreChecker()
    return checker.quick_check(url)

if __name__ == "__main__":
    import sys
    
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "https://paypal-security-alert.tk",
        "http://192.168.1.1/login",
        "https://www.amazon.com/login",
        "https://fake-paypal.ml/verify-account"
    ]
    
    if len(sys.argv) > 1:
        test_urls = [sys.argv[1]]
    
    checker = QuickPreChecker()
    
    for url in test_urls:
        print(f"\n{'='*60}")
        print(f"Quick check: {url}")
        print('='*60)
        
        results = checker.quick_check(url)
        
        print(f"Decision: {results['quick_decision']}")
        print(f"Confidence: {results['confidence']:.2f}")
        print(f"Risk Score: {results['risk_score']:.2f}")
        print(f"Skip ML: {results['should_skip_ml']}")
        print(f"Check Time: {results['check_time']:.3f}s")
        
        if results['reasons']:
            print("Reasons:")
            for reason in results['reasons']:
                print(f"  - {reason}")
        
        if results.get('heuristic_reasons'):
            print("Heuristic flags:")
            for reason in results['heuristic_reasons']:
                print(f"  - {reason}")