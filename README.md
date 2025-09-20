<!--                        _____                                 _ ___ _____  
                           / ____|                               |___ \| ____| 
                          | |  __ _ __ ___  _   _ _ __    ______     ) | |__   
                          | | |_ | '__/ _ \| | | | '_ \  |______|   / /|___ \  
                          | |__| | | | (_) | |_| | |_) |           / /_ ___) | 
                           \_____|_|  \___/ \__,_| .__/           |____|____/  
                                                 | |                           
                                                 |_|     -->

                         #  Quick Links


<!--[![](https://raw.githubusercontent.com/adamalston/adamalston/master/profile.gif)](https://www.adamalston.com/)-->

# Hooked - Phishing Detection & Analysis Toolkit


**Hooked** ia a phishing detection and analysis toolkit we plan to build using Python, we will designed it to automate the detection and analysis of phishing websites and scale it on the way.


## Features

- **Phishing URL Detection** using:
  - Public blacklists
  - Heuristic methods
  - Domain pattern analysis
- **Feature Extraction** from URLs and websites
- **Machine Learning Model** for URL classification
- **Web Interface** for easy interaction
- Fast, reliable, and beginner-friendly

<!--img src="" alt="" width="200" height="200"-->

## DEMO
To be updated soon... 

---

## Local Setup / Installation

### 1. Clone the repository

```bash
git clone https://github.com/abresh671/group-25.git
cd group-25
```

---

### 2. Create a virtual environment
```bash
python -m venv venv
```
#### For Linux / Mac:

```bash
source venv/bin/activate
```

#### For Windows:

```bash
venv\Scripts\activate
```
### 3. Install Dependencies

```bash
pip install -r requirements.txt
```
### 4. Ensure model files are in model/

```text
The model/ directory should contain the trained machine learning model (phishingdetection.pkl). 
If missing, train the model first using the provided scripts.
```
## Usage
### Command-Line Interface(CLI)
#### 1. Run the main application:
```bash
python main.py
```
#### 2. Input a URL when prompted:
```bash
Enter URL to test: http://example-phishing.com
```
#### 3. Example output:
```bash
Analyzing...
URL is detected as: Phishing
Confidence Score: 92%
```

### Web Interface (if available)

#### 1. Start the web server:
```bash
python app.py
```
#### 2. Open your browser and navigate to:
```bash
http://localhost:5000
```
#### 3. Enter the URL in the input box and click Analyze to see the result.

### Getting Started Example
```bash
$ python main.py
Enter URL to test: http://fakebank-login.com
Analyzing...
URL is detected as: Phishing
Confidence Score: 92%
```
- The result will show whether the URL is Safe or Phishing, along with a confidence score.
- For the web interface, simply paste the URL in the input box and click Analyze.
#### Updating
To get the latest version of the toolkit:
```bash
cd group-25
git pull origin main
```
After updating, make sure to update dependencies if requirements.txt has changed:
 ```bash
 pip install -r requirements.txt
 ```
#### Uninstalling
### 1. Deactivate and remove the virtual environment
```bash
deactivate       # Only if currently active
rm -rf venv      # Linux/Mac
rmdir /s /q venv # Windows
```
### 2. Remove the project files (optional)
```bash
rm -rf group-25      # Linux/Mac
rmdir /s /q group-25  # Windows
```
### 3. Uninstall dependencies globally (optional)
```bash
pip uninstall -r requirements.txt
```
### Project Structure
```bash
group-25/
│
├── main.py                 # Entry point
├── app.py                  # Web application logic
├── extractorFunctions.py   # Functions to extract URL features
├── featureExtractor.py     # Additional feature extraction utilities
├── model/                  # Trained machine learning models
│   └── phishingdetection.pkl
├── templates/              # HTML templates for web interface
├── requirements.txt        # Python dependencies
└── README.md               # Project documentation
```

## Developed At

> **INSA Summer Camp 2025 - Cyber Security Stream**  
> Project Lead: Group-25  

## Team Members

<ul>
<li>Abreham Addis
<li>Eden Dirshaye  
<li>Kamil Mohammed  
<li>Kidus Mengistu
<li>Mikiyas Alemseged
</ul>


## Feedback
Got feedback or ideas? Start a discussion on: [Hooked Discussions](https://github.com//hooked/discussions).

### License

This project is licensed under the MIT License – see the LICENSE
 file for details.
```pgsql

---

✅ This version uses **Markdown consistently**:  

- All commands are in **fenced code blocks** (```bash```)  
- Steps are numbered and bold where needed  
- Text descriptions are outside code blocks  
- Ready to paste into **VS Code** directly  

If you want, I can also **add a “Screenshots / Demo Section”** with placeholder images so it looks fully polished and mentor-ready.  

Do you want me to add that next?
```
> *Stay alert. Stay safe. Stay Hooked.*

<!-- [![Feedback](https://button.flattr.com/button-compact-static-100x17.png)](https://flattr.com/@theabbie) -->
