#!/usr/bin/env python3
"""
Advanced CLI interface for phishing detection system
"""

import argparse
import sys
import json
from datetime import datetime
from predict_advanced import predict, predict_batch, get_model_info
from explain import explain_url

def print_banner():
    banner = """
╔══════════════════════════════════════════════════════════════╗
║              Advanced Phishing Detection System              ║
║                     CLI Interface v2.0                      ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_result(url, pred, proba, explanations=None):
    """Print formatted result for a single URL"""
    status = "🚨 PHISHING" if pred == 1 else "✅ LEGITIMATE"
    confidence = f"({proba:.1%})" if proba is not None else ""
    
    print(f"\\n{'='*60}")
    print(f"URL: {url}")
    print(f"Result: {status} {confidence}")
    
    if explanations:
        print("\\nTop Contributing Features:")
        for i, (feature, value) in enumerate(explanations[:5], 1):
            print(f"  {i}. {feature}: {value:+.3f}")
    
    print('='*60)

def single_url_mode(args):
    """Analyze a single URL"""
    url = args.url or input("Enter URL to analyze: ").strip()
    
    if not url:
        print("❌ No URL provided")
        return
    
    print(f"🔍 Analyzing: {url}")
    
    try:
        pred, proba = predict(url, use_network=args.network)
        
        if pred is None:
            print("❌ Prediction failed")
            return
        
        explanations = None
        if args.explain:
            try:
                explanations = explain_url(url, top_k=8, use_network=args.network)
            except Exception as e:
                print(f"⚠️  Explanation failed: {e}")
        
        print_result(url, pred, proba, explanations)
        
        if args.json:
            result = {
                "url": url,
                "prediction": int(pred),
                "label": "PHISHING" if pred == 1 else "LEGITIMATE",
                "probability": float(proba) if proba is not None else None,
                "timestamp": datetime.now().isoformat()
            }
            if explanations:
                result["explanations"] = [{"feature": f, "value": float(v)} for f, v in explanations]
            
            print("\\nJSON Output:")
            print(json.dumps(result, indent=2))
    
    except Exception as e:
        print(f"❌ Error: {e}")

def batch_mode(args):
    """Analyze multiple URLs from file"""
    try:
        with open(args.file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"❌ File not found: {args.file}")
        return
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        return
    
    if not urls:
        print("❌ No URLs found in file")
        return
    
    print(f"🔍 Analyzing {len(urls)} URLs from {args.file}")
    
    try:
        results = predict_batch(urls, use_network=args.network)
        
        phishing_count = 0
        legitimate_count = 0
        
        print("\\nResults:")
        print("-" * 80)
        
        for result in results:
            url = result['url']
            pred = result['prediction']
            proba = result['probability']
            
            if pred is not None:
                status = "PHISHING" if pred == 1 else "LEGITIMATE"
                confidence = f"({proba:.1%})" if proba is not None else ""
                
                if pred == 1:
                    phishing_count += 1
                    icon = "🚨"
                else:
                    legitimate_count += 1
                    icon = "✅"
                
                print(f"{icon} {status:<12} {confidence:<8} {url}")
            else:
                print(f"❌ ERROR        {'':8} {url}")
        
        print("-" * 80)
        print(f"Summary: {legitimate_count} legitimate, {phishing_count} phishing, {len(results) - legitimate_count - phishing_count} errors")
        
        if args.json:
            output = {
                "total_urls": len(urls),
                "legitimate_count": legitimate_count,
                "phishing_count": phishing_count,
                "results": results,
                "timestamp": datetime.now().isoformat()
            }
            
            output_file = args.file.replace('.txt', '_results.json')
            with open(output_file, 'w') as f:
                json.dump(output, f, indent=2)
            print(f"\\n📄 Results saved to: {output_file}")
    
    except Exception as e:
        print(f"❌ Batch processing error: {e}")

def interactive_mode(args):
    """Interactive mode for continuous URL analysis"""
    print("🔄 Interactive mode - Enter URLs to analyze (type 'quit' to exit)")
    print("Commands: 'info' for model info, 'help' for help")
    
    while True:
        try:
            user_input = input("\\n🔍 Enter URL: ").strip()
            
            if not user_input or user_input.lower() in ['quit', 'exit', 'q']:
                print("👋 Goodbye!")
                break
            
            if user_input.lower() == 'help':
                print("""
Available commands:
  - Enter any URL to analyze it
  - 'info' - Show model information
  - 'quit'/'exit'/'q' - Exit interactive mode
                """)
                continue
            
            if user_input.lower() == 'info':
                info = get_model_info()
                if info and 'error' not in info:
                    print(f"\\nModel Information:")
                    print(f"  Type: {info.get('model_type', 'Unknown')}")
                    print(f"  Features: {info.get('feature_count', 'Unknown')}")
                    print(f"  Training Score: {info.get('training_score', 'Unknown')}")
                else:
                    print("❌ Model information not available")
                continue
            
            # Analyze URL
            pred, proba = predict(user_input, use_network=args.network)
            
            if pred is not None:
                explanations = None
                if args.explain:
                    try:
                        explanations = explain_url(user_input, top_k=5, use_network=args.network)
                    except:
                        pass
                
                print_result(user_input, pred, proba, explanations)
            else:
                print("❌ Prediction failed")
        
        except KeyboardInterrupt:
            print("\\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Phishing URL Detection CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://suspicious-site.com
  %(prog)s --file urls.txt --json
  %(prog)s --interactive --explain
  %(prog)s --info
        """
    )
    
    parser.add_argument("url", nargs='?', help="URL to analyze")
    parser.add_argument("-f", "--file", help="File containing URLs (one per line)")
    parser.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    parser.add_argument("-e", "--explain", action="store_true", help="Show feature explanations")
    parser.add_argument("-n", "--network", action="store_true", help="Use network-based features (slower)")
    parser.add_argument("-j", "--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--info", action="store_true", help="Show model information")
    parser.add_argument("--no-banner", action="store_true", help="Don't show banner")
    
    args = parser.parse_args()
    
    if not args.no_banner:
        print_banner()
    
    # Show model info
    if args.info:
        info = get_model_info()
        if info and 'error' not in info:
            print("Model Information:")
            for key, value in info.items():
                print(f"  {key.replace('_', ' ').title()}: {value}")
        else:
            print("❌ Model not available or error loading model info")
        return
    
    # Determine mode
    if args.file:
        batch_mode(args)
    elif args.interactive:
        interactive_mode(args)
    elif args.url:
        single_url_mode(args)
    else:
        # Default to interactive if no URL provided
        args.interactive = True
        interactive_mode(args)

if __name__ == "__main__":
    main()