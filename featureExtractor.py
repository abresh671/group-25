"""
Main feature extraction module for phishing detection
Simplified version that works with existing extractorFunctions.py
"""

import logging
from typing import Dict, Any
from urllib.parse import urlparse
import time

try:
    from extractorFunctions import (
        URLFeatureExtractor,
        DomainFeatureExtractor, 
        ContentFeatureExtractor,
        HeuristicFeatureExtractor,
        BlacklistChecker,
        StatisticalFeatureExtractor
    )
    EXTRACTORS_AVAILABLE = True
except ImportError:
    EXTRACTORS_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def extract_all_features(url: str, use_network: bool = False, use_content: bool = False) -> Dict[str, Any]:
    """
    Extract all features from a URL
    
    Args:
        url: URL to analyze
        use_network: Whether to use network-based features
        use_content: Whether to fetch and analyze page content
        
    Returns:
        Dictionary of extracted features
    """
    start_time = time.time()
    features = {}
    
    try:
        # Parse URL once
        parsed_url = urlparse(url if url.startswith(('http://', 'https://')) else f'http://{url}')
        
        if EXTRACTORS_AVAILABLE:
            # Use advanced extractors if available
            url_extractor = URLFeatureExtractor()
            heuristic_extractor = HeuristicFeatureExtractor()
            statistical_extractor = StatisticalFeatureExtractor()
            blacklist_checker = BlacklistChecker()
            domain_extractor = DomainFeatureExtractor(use_network=use_network)
            
            # Extract features
            features.update(url_extractor.extract(url, parsed_url))
            features.update(heuristic_extractor.extract(url, parsed_url))
            features.update(statistical_extractor.extract(url, parsed_url))
            features.update(blacklist_checker.check(url, parsed_url))
            
            # Domain features (network dependent)
            if use_network:
                try:
                    features.update(domain_extractor.extract(url, parsed_url, timeout=5))
                except Exception as e:
                    logger.warning(f"Domain feature extraction failed: {e}")
                    features.update(domain_extractor.get_default_features())
            else:
                features.update(domain_extractor.get_default_features())
            
            # Content features (if requested)
            if use_content:
                try:
                    content_extractor = ContentFeatureExtractor()
                    features.update(content_extractor.extract(url, parsed_url, timeout=10))
                except Exception as e:
                    logger.warning(f"Content feature extraction failed: {e}")
                    content_extractor = ContentFeatureExtractor()
                    features.update(content_extractor.get_default_features())
        else:
            # Fallback to basic features if extractors not available
            features = _extract_basic_features(url, parsed_url)
        
        # Add metadata
        extraction_time = time.time() - start_time
        features['extraction_time'] = extraction_time
        
        logger.info(f"Extracted {len(features)} features in {extraction_time:.3f}s")
        
    except Exception as e:
        logger.error(f"Feature extraction failed for {url}: {e}")
        features = _get_minimal_features(url)
    
    return features

def _extract_basic_features(url: str, parsed_url) -> Dict[str, Any]:
    """Extract basic features when advanced extractors are not available"""
    features = {}
    
    # Basic URL features
    features['url_length'] = len(url)
    features['host_length'] = len(parsed_url.netloc)
    features['path_length'] = len(parsed_url.path or '')
    features['has_https'] = 1 if url.lower().startswith('https://') else 0
    features['has_www'] = 1 if 'www.' in parsed_url.netloc.lower() else 0
    
    # Character counts
    features['count_dots'] = url.count('.')
    features['count_hyphens'] = url.count('-')
    features['count_slashes'] = url.count('/')
    features['count_at_symbols'] = url.count('@')
    
    # Suspicious patterns
    suspicious_words = ['login', 'verify', 'secure', 'account', 'update']
    features['suspicious_word_count'] = sum(1 for word in suspicious_words if word in url.lower())
    
    # Domain analysis
    domain_parts = parsed_url.netloc.split('.')
    features['domain_parts_count'] = len(domain_parts)
    features['subdomain_count'] = max(0, len(domain_parts) - 2)
    
    # IP detection
    import re
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    features['has_ip'] = 1 if ip_pattern.search(parsed_url.netloc) else 0
    
    return features

def _get_minimal_features(url: str) -> Dict[str, Any]:
    """Return minimal feature set when extraction fails"""
    return {
        'url_length': len(url),
        'has_https': 1 if url.startswith('https://') else 0,
        'count_dots': url.count('.'),
        'count_hyphens': url.count('-'),
        'extraction_failed': 1
    }

if __name__ == "__main__":
    import sys
    
    # Test the feature extractor
    test_urls = [
        "https://www.google.com",
        "https://paypal-security-alert.tk",
        "http://192.168.1.1/login"
    ]
    
    if len(sys.argv) > 1:
        test_urls = [sys.argv[1]]
    
    for url in test_urls:
        print(f"\n{'='*60}")
        print(f"Analyzing: {url}")
        print('='*60)
        
        features = extract_all_features(url, use_network=False, use_content=False)
        
        # Print features
        print(f"Total features extracted: {len(features)}")
        print(f"Extraction time: {features.get('extraction_time', 0):.3f}s")
        
        # Show key features
        key_features = ['url_length', 'has_https', 'has_ip', 'suspicious_word_count', 'count_dots']
        
        print("\nKey features:")
        for feat in key_features:
            if feat in features:
                print(f"  {feat}: {features[feat]}")