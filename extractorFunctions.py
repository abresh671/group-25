"""
Individual feature extraction functions for phishing detection
Each class handles a specific category of features
"""

import re
import math
import time
import hashlib
import socket
from collections import Counter
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

class URLFeatureExtractor:
    """Extract features directly from URL structure"""
    
    def __init__(self):
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.hex_pattern = re.compile(r'%[0-9a-fA-F]{2}')
        
    def extract(self, url: str, parsed_url) -> Dict[str, Any]:
        """Extract URL-based features"""
        features = {}
        
        # Basic length features
        features['url_length'] = len(url)
        features['host_length'] = len(parsed_url.netloc)
        features['path_length'] = len(parsed_url.path or '')
        features['query_length'] = len(parsed_url.query or '')
        features['fragment_length'] = len(parsed_url.fragment or '')
        
        # Character counts
        features['count_dots'] = url.count('.')
        features['count_hyphens'] = url.count('-')
        features['count_underscores'] = url.count('_')
        features['count_slashes'] = url.count('/')
        features['count_at_symbols'] = url.count('@')
        features['count_question_marks'] = url.count('?')
        features['count_equals'] = url.count('=')
        features['count_ampersands'] = url.count('&')
        features['count_percent'] = url.count('%')
        features['count_hash'] = url.count('#')
        
        # Character ratios
        total_chars = len(url)
        if total_chars > 0:
            features['ratio_digits'] = sum(c.isdigit() for c in url) / total_chars
            features['ratio_letters'] = sum(c.isalpha() for c in url) / total_chars
            features['ratio_special'] = sum(not c.isalnum() for c in url) / total_chars
        else:
            features['ratio_digits'] = features['ratio_letters'] = features['ratio_special'] = 0
        
        # Protocol and security
        features['has_https'] = 1 if url.lower().startswith('https://') else 0
        features['has_www'] = 1 if 'www.' in parsed_url.netloc.lower() else 0
        
        # IP address detection
        features['has_ip'] = 1 if self.ip_pattern.search(parsed_url.netloc) else 0
        
        # Port detection (non-standard ports)
        port = parsed_url.port
        if port:
            features['has_port'] = 1
            features['is_standard_port'] = 1 if port in [80, 443] else 0
        else:
            features['has_port'] = 0
            features['is_standard_port'] = 1
        
        # URL encoding
        features['hex_chars_count'] = len(self.hex_pattern.findall(url))
        features['has_punycode'] = 1 if 'xn--' in parsed_url.netloc else 0
        
        # Path analysis
        path_parts = [p for p in parsed_url.path.split('/') if p]
        features['path_depth'] = len(path_parts)
        features['has_file_extension'] = 1 if path_parts and '.' in path_parts[-1] else 0
        
        # Query parameters
        query_params = parse_qs(parsed_url.query)
        features['query_param_count'] = len(query_params)
        
        return features
    
    def get_feature_names(self) -> List[str]:
        return [
            'url_length', 'host_length', 'path_length', 'query_length', 'fragment_length',
            'count_dots', 'count_hyphens', 'count_underscores', 'count_slashes',
            'count_at_symbols', 'count_question_marks', 'count_equals', 'count_ampersands',
            'count_percent', 'count_hash', 'ratio_digits', 'ratio_letters', 'ratio_special',
            'has_https', 'has_www', 'has_ip', 'has_port', 'is_standard_port',
            'hex_chars_count', 'has_punycode', 'path_depth', 'has_file_extension',
            'query_param_count'
        ]

class DomainFeatureExtractor:
    """Extract domain-based features including WHOIS and DNS"""
    
    def __init__(self, use_network: bool = False):
        self.use_network = use_network
        
    def extract(self, url: str, parsed_url, timeout: int = 5) -> Dict[str, Any]:
        """Extract domain-based features"""
        features = {}
        domain = parsed_url.netloc.lower()
        
        # Domain structure
        domain_parts = domain.split('.')
        features['domain_parts_count'] = len(domain_parts)
        
        if len(domain_parts) >= 2:
            features['tld_length'] = len(domain_parts[-1])
            features['domain_name_length'] = len(domain_parts[-2])
            features['subdomain_count'] = len(domain_parts) - 2
        else:
            features['tld_length'] = 0
            features['domain_name_length'] = len(domain)
            features['subdomain_count'] = 0
        
        # Network-based features (if enabled)
        if self.use_network:
            features.update(self._extract_network_features(domain, timeout))
        else:
            features.update(self.get_default_features())
        
        return features
    
    def _extract_network_features(self, domain: str, timeout: int) -> Dict[str, Any]:
        """Extract network-based domain features"""
        features = {}
        
        # WHOIS information
        try:
            features.update(self._get_whois_features(domain, timeout))
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {domain}: {e}")
            features.update({
                'domain_age_days': -1,
                'whois_available': 0
            })
        
        # DNS information
        try:
            features.update(self._get_dns_features(domain, timeout))
        except Exception as e:
            logger.debug(f"DNS lookup failed for {domain}: {e}")
            features.update({
                'dns_a_records': 0,
                'dns_mx_records': 0,
                'dns_available': 0
            })
        
        return features
    
    def _get_whois_features(self, domain: str, timeout: int) -> Dict[str, Any]:
        """Get WHOIS-based features"""
        try:
            import whois
            w = whois.whois(domain)
            
            features = {'whois_available': 1}
            
            # Domain age
            creation_date = w.creation_date
            if creation_date:
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                age_days = (time.time() - creation_date.timestamp()) / (24 * 3600)
                features['domain_age_days'] = max(0, int(age_days))
            else:
                features['domain_age_days'] = -1
            
            return features
            
        except ImportError:
            logger.warning("python-whois not available")
            return {'domain_age_days': -1, 'whois_available': 0}
        except Exception:
            return {'domain_age_days': -1, 'whois_available': 0}
    
    def _get_dns_features(self, domain: str, timeout: int) -> Dict[str, Any]:
        """Get DNS-based features"""
        try:
            import dns.resolver
            
            features = {'dns_available': 1}
            
            # A records
            try:
                a_records = dns.resolver.resolve(domain, 'A', lifetime=timeout)
                features['dns_a_records'] = len(list(a_records))
            except:
                features['dns_a_records'] = 0
            
            # MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX', lifetime=timeout)
                features['dns_mx_records'] = len(list(mx_records))
            except:
                features['dns_mx_records'] = 0
            
            return features
            
        except ImportError:
            logger.warning("dnspython not available")
            return {'dns_a_records': 0, 'dns_mx_records': 0, 'dns_available': 0}
        except Exception:
            return {'dns_a_records': 0, 'dns_mx_records': 0, 'dns_available': 0}
    
    def get_default_features(self) -> Dict[str, Any]:
        """Default values when network features are disabled"""
        return {
            'domain_age_days': -1,
            'whois_available': 0,
            'dns_a_records': 0,
            'dns_mx_records': 0,
            'dns_available': 0
        }
    
    def get_feature_names(self) -> List[str]:
        return [
            'domain_parts_count', 'tld_length', 'domain_name_length', 'subdomain_count',
            'domain_age_days', 'whois_available', 'dns_a_records', 'dns_mx_records', 'dns_available'
        ]

class ContentFeatureExtractor:
    """Extract features from webpage content"""
    
    def __init__(self):
        self.form_pattern = re.compile(r'<form[^>]*>', re.IGNORECASE)
        self.input_pattern = re.compile(r'<input[^>]*>', re.IGNORECASE)
        self.link_pattern = re.compile(r'<a[^>]*href=["\']([^"\']*)["\'][^>]*>', re.IGNORECASE)
        
    def extract(self, url: str, parsed_url, timeout: int = 10) -> Dict[str, Any]:
        """Extract content-based features"""
        try:
            import requests
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=timeout, verify=False)
            content = response.text
            
            return self._analyze_content(content, parsed_url)
            
        except ImportError:
            logger.warning("requests not available for content extraction")
            return self.get_default_features()
        except Exception as e:
            logger.debug(f"Content fetch failed for {url}: {e}")
            return self.get_default_features()
    
    def _analyze_content(self, content: str, parsed_url) -> Dict[str, Any]:
        """Analyze webpage content"""
        features = {}
        
        # Basic content metrics
        features['content_length'] = len(content)
        features['has_content'] = 1 if content else 0
        
        # Form analysis
        forms = self.form_pattern.findall(content)
        inputs = self.input_pattern.findall(content)
        features['form_count'] = len(forms)
        features['input_count'] = len(inputs)
        features['has_forms'] = 1 if forms else 0
        
        # Link analysis
        links = self.link_pattern.findall(content)
        features['link_count'] = len(links)
        
        # External links
        external_links = 0
        for link in links:
            try:
                link_parsed = urlparse(link)
                if link_parsed.netloc and link_parsed.netloc != parsed_url.netloc:
                    external_links += 1
            except:
                continue
        
        features['external_link_count'] = external_links
        features['external_link_ratio'] = external_links / max(1, len(links))
        
        # Suspicious content patterns
        suspicious_words = ['login', 'password', 'verify', 'account', 'suspended', 'urgent']
        features['suspicious_word_count'] = sum(
            content.lower().count(word) for word in suspicious_words
        )
        
        return features
    
    def get_default_features(self) -> Dict[str, Any]:
        """Default values when content extraction fails"""
        return {
            'content_length': 0,
            'has_content': 0,
            'form_count': 0,
            'input_count': 0,
            'has_forms': 0,
            'link_count': 0,
            'external_link_count': 0,
            'external_link_ratio': 0,
            'suspicious_word_count': 0
        }
    
    def get_feature_names(self) -> List[str]:
        return [
            'content_length', 'has_content', 'form_count', 'input_count', 'has_forms',
            'link_count', 'external_link_count', 'external_link_ratio', 'suspicious_word_count'
        ]

class HeuristicFeatureExtractor:
    """Extract heuristic-based features using pattern matching"""
    
    def __init__(self):
        self.suspicious_tokens = [
            'login', 'signin', 'verify', 'secure', 'account', 'update',
            'confirm', 'suspended', 'limited', 'locked', 'expired',
            'urgent', 'immediate', 'action', 'required', 'click'
        ]
        
        self.brand_names = [
            'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
            'twitter', 'instagram', 'linkedin', 'netflix', 'spotify',
            'ebay', 'yahoo', 'adobe', 'dropbox', 'github'
        ]
        
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.click',
            '.download', '.stream', '.science', '.work', '.party'
        ]
        
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'short.link', 'tiny.cc', 'is.gd'
        ]
    
    def extract(self, url: str, parsed_url) -> Dict[str, Any]:
        """Extract heuristic features"""
        features = {}
        url_lower = url.lower()
        domain_lower = parsed_url.netloc.lower()
        
        # Suspicious token analysis
        features['suspicious_token_count'] = sum(
            1 for token in self.suspicious_tokens if token in url_lower
        )
        features['has_suspicious_tokens'] = 1 if features['suspicious_token_count'] > 0 else 0
        
        # Brand name analysis
        brand_in_domain = sum(1 for brand in self.brand_names if brand in domain_lower)
        features['brand_name_count'] = brand_in_domain
        
        # Check if brand name appears but not in official domain
        features['suspicious_brand_usage'] = 0
        for brand in self.brand_names:
            if brand in domain_lower and not domain_lower.startswith(f'www.{brand}.com'):
                features['suspicious_brand_usage'] = 1
                break
        
        # TLD analysis
        features['has_suspicious_tld'] = 1 if any(tld in url_lower for tld in self.suspicious_tlds) else 0
        
        # URL shortener detection
        features['is_url_shortener'] = 1 if any(short in domain_lower for short in self.url_shorteners) else 0
        
        # Redirect parameter detection
        query_lower = parsed_url.query.lower()
        redirect_params = ['redirect', 'url', 'next', 'return', 'goto', 'continue']
        features['has_redirect_param'] = 1 if any(param in query_lower for param in redirect_params) else 0
        
        # Homograph detection (basic)
        features['has_homograph_chars'] = 1 if any(ord(c) > 127 for c in url) else 0
        
        # Multiple subdomain levels (potential subdomain abuse)
        subdomain_levels = domain_lower.count('.') - 1
        features['excessive_subdomains'] = 1 if subdomain_levels > 3 else 0
        
        return features
    
    def get_feature_names(self) -> List[str]:
        return [
            'suspicious_token_count', 'has_suspicious_tokens', 'brand_name_count',
            'suspicious_brand_usage', 'has_suspicious_tld', 'is_url_shortener',
            'has_redirect_param', 'has_homograph_chars', 'excessive_subdomains'
        ]

class BlacklistChecker:
    """Check URLs against known blacklists"""
    
    def __init__(self):
        # Simple in-memory blacklists (in production, use external services)
        self.malicious_domains = {
            'phishing-site.tk', 'fake-bank.ml', 'scam-paypal.ga',
            'malware-download.cf', 'suspicious-login.xyz'
        }
        
        self.suspicious_patterns = [
            r'.*-security-.*\.tk$',
            r'.*-verify-.*\.ml$',
            r'.*-suspended-.*\.ga$',
            r'.*-locked-.*\.cf$'
        ]
    
    def check(self, url: str, parsed_url) -> Dict[str, Any]:
        """Check URL against blacklists"""
        features = {}
        domain = parsed_url.netloc.lower()
        
        # Direct blacklist check
        features['is_blacklisted'] = 1 if domain in self.malicious_domains else 0
        
        # Pattern-based suspicious domain check
        features['matches_suspicious_pattern'] = 0
        for pattern in self.suspicious_patterns:
            if re.match(pattern, domain):
                features['matches_suspicious_pattern'] = 1
                break
        
        # Reputation score (simplified)
        reputation_score = 1.0  # Start with good reputation
        
        if features['is_blacklisted']:
            reputation_score = 0.0
        elif features['matches_suspicious_pattern']:
            reputation_score = 0.3
        elif any(tld in domain for tld in ['.tk', '.ml', '.ga', '.cf']):
            reputation_score = 0.6
        
        features['reputation_score'] = reputation_score
        
        return features
    
    def get_feature_names(self) -> List[str]:
        return ['is_blacklisted', 'matches_suspicious_pattern', 'reputation_score']

class StatisticalFeatureExtractor:
    """Extract statistical features from URL text"""
    
    def extract(self, url: str, parsed_url) -> Dict[str, Any]:
        """Extract statistical features"""
        features = {}
        
        # Entropy calculation
        features['entropy_score'] = self._calculate_entropy(url)
        features['domain_entropy'] = self._calculate_entropy(parsed_url.netloc)
        features['path_entropy'] = self._calculate_entropy(parsed_url.path or '')
        
        # Character frequency analysis
        char_freq = Counter(url.lower())
        features['most_frequent_char_count'] = max(char_freq.values()) if char_freq else 0
        features['unique_char_count'] = len(char_freq)
        features['char_diversity'] = len(char_freq) / max(1, len(url))
        
        # Token analysis
        tokens = re.findall(r'[a-zA-Z]+', url)
        if tokens:
            features['token_count'] = len(tokens)
            features['avg_token_length'] = sum(len(token) for token in tokens) / len(tokens)
            features['max_token_length'] = max(len(token) for token in tokens)
        else:
            features['token_count'] = 0
            features['avg_token_length'] = 0
            features['max_token_length'] = 0
        
        # Digit sequences
        digit_sequences = re.findall(r'\d+', url)
        features['digit_sequence_count'] = len(digit_sequences)
        features['max_digit_sequence'] = max(len(seq) for seq in digit_sequences) if digit_sequences else 0
        
        return features
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        char_counts = Counter(text.lower())
        text_len = len(text)
        
        entropy = 0.0
        for count in char_counts.values():
            probability = count / text_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def get_feature_names(self) -> List[str]:
        return [
            'entropy_score', 'domain_entropy', 'path_entropy',
            'most_frequent_char_count', 'unique_char_count', 'char_diversity',
            'token_count', 'avg_token_length', 'max_token_length',
            'digit_sequence_count', 'max_digit_sequence'
        ]