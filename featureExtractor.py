"""
Main feature extraction module for phishing detection
Coordinates all feature extraction processes
"""

import logging
from typing import Dict, Any, Optional
from urllib.parse import urlparse
import time

from extractorFunctions import (
    URLFeatureExtractor,
    DomainFeatureExtractor, 
    ContentFeatureExtractor,
    HeuristicFeatureExtractor,
    BlacklistChecker,
    StatisticalFeatureExtractor
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PhishingFeatureExtractor:
    """
    Main feature extraction coordinator
    Orchestrates all feature extraction components
    """
    
    def __init__(self, use_network: bool = False, use_content: bool = False):
        self.use_network = use_network
        self.use_content = use_content
        
        # Initialize extractors
        self.url_extractor = URLFeatureExtractor()
        self.domain_extractor = DomainFeatureExtractor(use_network=use_network)
        self.content_extractor = ContentFeatureExtractor() if use_content else None
        self.heuristic_extractor = HeuristicFeatureExtractor()
        self.blacklist_checker = BlacklistChecker()
        self.statistical_extractor = StatisticalFeatureExtractor()
        
        logger.info(f"FeatureExtractor initialized (network={use_network}, content={use_content})")
    
    def extract_all_features(self, url: str, timeout: int = 10) -> Dict[str, Any]:
        """
        Extract all features from a URL
        
        Args:
            url: URL to analyze
            timeout: Timeout for network operations
            
        Returns:
            Dictionary of all extracted features
        """
        start_time = time.time()
        features = {}
        
        try:
            # Parse URL once for all extractors
            parsed_url = urlparse(url if url.startswith(('http://', 'https://')) else f'http://{url}')
            
            # 1. URL-based features (always fast)
            logger.debug("Extracting URL features...")
            url_features = self.url_extractor.extract(url, parsed_url)
            features.update(url_features)
            
            # 2. Heuristic features (fast pattern matching)
            logger.debug("Extracting heuristic features...")
            heuristic_features = self.heuristic_extractor.extract(url, parsed_url)
            features.update(heuristic_features)
            
            # 3. Statistical features (fast text analysis)
            logger.debug("Extracting statistical features...")
            statistical_features = self.statistical_extractor.extract(url, parsed_url)
            features.update(statistical_features)
            
            # 4. Blacklist checks (network dependent)
            logger.debug("Checking blacklists...")
            blacklist_features = self.blacklist_checker.check(url, parsed_url)
            features.update(blacklist_features)
            
            # 5. Domain-based features (network dependent, slower)
            if self.use_network:
                logger.debug("Extracting domain features...")
                try:
                    domain_features = self.domain_extractor.extract(url, parsed_url, timeout=timeout)
                    features.update(domain_features)
                except Exception as e:
                    logger.warning(f"Domain feature extraction failed: {e}")
                    # Add default values for failed network features
                    features.update(self.domain_extractor.get_default_features())
            else:
                features.update(self.domain_extractor.get_default_features())
            
            # 6. Content-based features (slowest, requires page fetch)
            if self.use_content and self.content_extractor:
                logger.debug("Extracting content features...")
                try:
                    content_features = self.content_extractor.extract(url, parsed_url, timeout=timeout)
                    features.update(content_features)
                except Exception as e:
                    logger.warning(f"Content feature extraction failed: {e}")
                    features.update(self.content_extractor.get_default_features())
            elif self.content_extractor:
                features.update(self.content_extractor.get_default_features())
            
            # Add metadata
            features['extraction_time'] = time.time() - start_time
            features['feature_count'] = len(features) - 1  # Exclude extraction_time
            
            logger.info(f"Extracted {features['feature_count']} features in {features['extraction_time']:.3f}s")
            
        except Exception as e:
            logger.error(f"Feature extraction failed for {url}: {e}")
            # Return minimal feature set on failure
            features = self._get_minimal_features(url)
        
        return features
    
    def _get_minimal_features(self, url: str) -> Dict[str, Any]:
        """Return minimal feature set when extraction fails"""
        return {
            'url_length': len(url),
            'has_https': 1 if url.startswith('https://') else 0,
            'suspicious_chars': sum(c in url for c in '@#?'),
            'extraction_failed': 1,
            'feature_count': 4
        }
    
    def get_feature_names(self) -> list:
        """Get list of all possible feature names"""
        feature_names = []
        
        # Collect from all extractors
        feature_names.extend(self.url_extractor.get_feature_names())
        feature_names.extend(self.heuristic_extractor.get_feature_names())
        feature_names.extend(self.statistical_extractor.get_feature_names())
        feature_names.extend(self.blacklist_checker.get_feature_names())
        feature_names.extend(self.domain_extractor.get_feature_names())
        
        if self.content_extractor:
            feature_names.extend(self.content_extractor.get_feature_names())
        
        # Add metadata features
        feature_names.extend(['extraction_time', 'feature_count'])
        
        return sorted(list(set(feature_names)))  # Remove duplicates and sort
    
    def validate_features(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and clean extracted features"""
        validated = {}
        
        for name, value in features.items():
            try:
                # Convert to appropriate types
                if isinstance(value, bool):
                    validated[name] = int(value)
                elif isinstance(value, (int, float)):
                    # Handle inf and nan values
                    if value == float('inf'):
                        validated[name] = 999999
                    elif value == float('-inf'):
                        validated[name] = -999999
                    elif value != value:  # NaN check
                        validated[name] = -1
                    else:
                        validated[name] = float(value)
                else:
                    # Convert other types to string length or hash
                    validated[name] = len(str(value))
            except Exception:
                validated[name] = -1
        
        return validated

# Convenience function for backward compatibility
def extract_all_features(url: str, use_network: bool = False, use_content: bool = False) -> Dict[str, Any]:
    """
    Convenience function to extract features from a URL
    
    Args:
        url: URL to analyze
        use_network: Whether to use network-based features
        use_content: Whether to fetch and analyze page content
        
    Returns:
        Dictionary of extracted features
    """
    extractor = PhishingFeatureExtractor(use_network=use_network, use_content=use_content)
    return extractor.extract_all_features(url)

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
    
    extractor = PhishingFeatureExtractor(use_network=False, use_content=False)
    
    for url in test_urls:
        print(f"\n{'='*60}")
        print(f"Analyzing: {url}")
        print('='*60)
        
        features = extractor.extract_all_features(url)
        
        # Print features in categories
        print(f"Total features extracted: {features.get('feature_count', 0)}")
        print(f"Extraction time: {features.get('extraction_time', 0):.3f}s")
        
        # Show top features
        important_features = [
            'url_length', 'has_https', 'has_ip', 'suspicious_token_count',
            'domain_age_days', 'is_blacklisted', 'entropy_score'
        ]
        
        print("\nKey features:")
        for feat in important_features:
            if feat in features:
                print(f"  {feat}: {features[feat]}")