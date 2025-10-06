import argparse
from predict_advanced import predict

def main():
    parser = argparse.ArgumentParser(description="Phishing URL Detector (CLI)")
    parser.add_argument("url", nargs='?', help="URL to classify. If omitted, interactive mode.")
    args = parser.parse_args()

    if args.url:
        pred, proba = predict(args.url, use_network=False)
        label = "PHISHING" if pred == 1 else "LEGIT"
        print(f"{args.url} -> {label} (score={proba})")
        return

    print("Phishing URL Detector (interactive). Type exit or ctrl+c to quit.")
    while True:
        try:
            u = input("Enter URL: ").strip()
            if not u or u.lower() in ("exit","quit"):
                break
            pred, proba = predict(u, use_network=False)
            label = "PHISHING" if pred == 1 else "LEGIT"
            print(f"{label} (score={proba})")
        except KeyboardInterrupt:
            break
        except Exception as e:
            print("Error:", e)

if __name__ == "__main__":
    main()
