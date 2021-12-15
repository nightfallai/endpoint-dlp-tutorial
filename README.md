# Building Endpoint DLP to Detect PII on Your Machine in Real-Time

#### In this tutorial, we will build a lightweight endpoint DLP scanner that scans files on your device in real-time for sensitive data like PII & secrets using Nightfall's data loss prevention APIs.

Endpoint data loss prevention (DLP) discovers, classifies, and protects sensitive data - like PII, credit card numbers, and secrets - that proliferates onto endpoint devices, like your computer or EC2 machines. This is a way to help keep data safe, so that you can detect and stop occurrences of data exfiltration. Our endpoint DLP application will be composed of two core services that will run locally. The first service will monitor for file system events using the [Watchdog](https://github.com/gorakhargosh/watchdog) package in Python. When a file system event is triggered, such as when a file is created or modified, the service will send the file to [Nightfall](https://nightfall.ai/developer-platform) to be scanned for sensitive data. The second service is a webhook server that will receive scan results from Nightfall, parse the sensitive findings, and write them to a CSV file as output. You'll build familiarity with the following tools and frameworks:

* Python
* Flask
* Nightfall
* Ngrok
* Watchdog

## Key Concepts

Before we get started on our implementation, start by familiarizing yourself with [how file scanning works](https://docs.nightfall.ai/docs/scanning-files#prerequisites) with Nightfall, so you're acquainted with the flow we are implementing. 

In a nutshell, file scanning is done asynchronously by Nightfall; after you upload a file to Nightfall and trigger the scan, we perform the scan in the background. When the scan completes, Nightfall delivers the results to you by making a request to your webhook server. This asynchronous behavior allows Nightfall to scan files of varying sizes and complexities without requiring you to hold open a long synchronous request, or continuously poll for updates. The impact of this pattern is that you need a webhook endpoint that can receive inbound notifications from Nightfall when scans are completed - that's one of the two services we are building in this tutorial.

## Getting Started

You can fork the sample repo and view the complete code [here](https://github.com/nightfallai/endpoint-dlp-tutorial), or follow along below. If you're starting from scratch, create a new GitHub repository. This tutorial was developed on a Mac and assumes that's the endpoint operating system you're running, however this tutorial should work across operating systems with minor modifications. For example, you may wish to extend this tutorial by running endpoint DLP on an EC2 machine to monitor your production systems.

## Setting Up Dependencies

First, let's start by installing our dependencies. We'll be using Nightfall for data classification, the [Flask](https://flask.palletsprojects.com/en/2.0.x/) web framework in Python, [watchdog](https://github.com/gorakhargosh/watchdog) for monitoring file system events, and [Gunicorn](https://gunicorn.org/) as our web server. Create `requirements.txt` and add the following to the file:

```
nightfall
Flask
Gunicorn
watchdog
```

Then run `pip install -r requirements.txt` to do the installation.

## Configuring Detection with Nightfall

Next, we'll need our Nightfall API Key and Webhook Signing Secret; the former authenticates us to the Nightfall API, while the latter authenticates that incoming webhooks are originating from Nightfall. You can retrieve your API Key and Webhook Signing Secret from the Nightfall [Dashboard](https://app.nightfall.ai). Complete the Nightfall [Quickstart](https://docs.nightfall.ai/docs/quickstart) for a more detailed walk-through. [Sign up](https://app.nightfall.ai/sign-up) for a free Nightfall account if you don't have one.

These values are unique to your account and should be kept safe. This means that we will store them as environment variables and should not store them directly in code or commit them into version control. If these values are ever leaked, be sure to visit the Nightfall Dashboard to re-generate new values for these secrets.


```bash
export NIGHTFALL_API_KEY=<your_key_here>
export NIGHTFALL_SIGNING_SECRET=<your_secret_here>
```

## Monitoring File System Events

Watchdog is a Python module that watches for file system events. Create a file called `scanner.py`. We'll start by importing our dependencies and setting up a basic event handler. This event handler responds to file change events for file paths that match a given set of regular expressions (regexes). In this case, the `.*` indicates we are matching on any file path - we'll customize this a bit later. When a file system event is triggered, we'll print a line to the console.

```python
import os
import time
from watchdog.observers import Observer
from watchdog.events import RegexMatchingEventHandler
from nightfall import Confidence, DetectionRule, Detector, RedactionConfig, MaskConfig, Nightfall

class MyHandler(RegexMatchingEventHandler):
    # event handler callback that is called when a file is modified (created or changed)
    def on_modified(self, event):
        print(f'Event type: {event.event_type} | Path: {event.src_path}')

if __name__ == "__main__":
    regexes = [ ".*" ]

    # register event handler to monitor file paths that match our regex
    event_handler = MyHandler(regexes)
    observer = Observer()
    observer.schedule(event_handler,  path='',  recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
```

Run `python scanner.py` and you'll notice lots of lines getting printed to the console. These are all the files that are getting created and changed on your machine in real-time. You'll notice that your operating system and the apps you're running are constantly writing, modifying, and deleting files on disk!

```bash
Event type: modified | Path: /Users/myuser/Library/Caches
Event type: modified | Path: /Users/myuser/Library/Caches/com.apple.nsservicescache.plist
Event type: modified | Path: /Users/myuser/Library/Caches
Event type: modified | Path: /Users/myuser/Library/Caches/Google/Chrome/Default/Cache
Event type: modified | Path: /private/tmp
Event type: modified | Path: /Users/myuser/Library/Preferences/ContextStoreAgent.plist
Event type: modified | Path: /private/tmp
Event type: modified | Path: /Users/myuser/Library/Assistant
Event type: modified | Path: /Users/myuser/Library/Assistant/SyncSnapshot.plist
...
```

Next, we'll update our event handler so that instead of simply printing to the console, we are sending the file to Nightfall to be scanned. We will initiate the scan request to Nightfall, by specifying the filepath of the changed/created file, a webhook URL where the scan results should be sent, and our Detection Rule that specifies what sensitive data we are looking for. If the file scan is initiated successfully, we'll print the corresponding Upload ID that Nightfall provides us to the console. This ID will be useful later when identifying scan results.

Here's our complete `scanner.py`, explained further below:

```python
import os
import time
from watchdog.observers import Observer
from watchdog.events import RegexMatchingEventHandler
from nightfall import Confidence, DetectionRule, Detector, RedactionConfig, MaskConfig, Nightfall

class MyHandler(RegexMatchingEventHandler):
    def scan_file(self, filepath):
        nightfall = Nightfall() # reads API key from NIGHTFALL_API_KEY environment variable by default
        webhook_url = f"{os.getenv('NIGHTFALL_SERVER_URL')}/ingest" # webhook server we'll create

        try:
            scan_id, message = nightfall.scan_file(
                filepath, 
                webhook_url=webhook_url,
                # detection rule to detect credit card numbers, SSNs, and API keys
                detection_rules=[ DetectionRule([ 
                    Detector(
                        min_confidence=Confidence.LIKELY,
                        nightfall_detector="CREDIT_CARD_NUMBER",
                        display_name="Credit Card Number"),
                    Detector(
                        min_confidence=Confidence.LIKELY,
                        nightfall_detector="US_SOCIAL_SECURITY_NUMBER",
                        display_name="US Social Security Number"),
                    Detector(
                        min_confidence=Confidence.LIKELY,
                        nightfall_detector="API_KEY",
                        display_name="API Key")
                    ])
                ])
            return scan_id, message
        except Exception as err:
            print(f"Error processing {filepath} | {err}")
            return None, None

    def on_modified(self, event):
        # scan file with Nightfall
        scan_id, message = self.scan_file(event.src_path)
        if scan_id:
            print(f"Scan initiated | Path {event.src_path} | UploadID {scan_id}")
        print(f'Event type: {event.event_type} | Path: {event.src_path}')

if __name__ == "__main__":
    regexes = [ ".*/Downloads/.*", ".*/Desktop/.*", ".*/Documents/.*" ]

    # register event handler to monitor file paths that match our regexes
    event_handler = MyHandler(regexes)
    observer = Observer()
    observer.schedule(event_handler,  path='',  recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
```

We can't run this just yet, since we need to set our webhook URL, which is currently reading from an environment variable that we haven't set yet. We'll create our webhook server and set the webhook URL in the next set of steps.

In this example, we have specified an inline Detection Rule that detects Likely Credit Card Numbers, Social Security Numbers, and API Keys. This Detection Rule is a simple starting point that just scratches the surface of the types of detection you can build with Nightfall. Learn more about building inline detection rules [here](https://docs.nightfall.ai/docs/creating-an-inline-detection-rule) or how to configure them in the Nightfall [Dashboard](https://app.nightfall.ai/developer-platform).

Also note that we've updated our regex from `.*` to a set of file paths on Macs that commonly contain user generated files - the Desktop, Documents, and Downloads folders:

```python
regexes = [ ".*/Downloads/.*", ".*/Desktop/.*", ".*/Documents/.*" ]
```

You can customize these regexes to whatever file paths are of interest to you. Another option is to write a catch-all regex that ignores/excludes paths to config and temp files:

```python
regexes = [ "(?!/opt/|.*/Library/|.*/private/|/System/|/Applications/|/usr/).*" ]
```

## Setting Up Our Webhook Server

Next, we'll set up our Flask webhook server, so we can receive file scanning results from Nightfall. Create a file called `app.py`. We'll start by importing our dependencies and initializing the Flask and Nightfall clients:

```python
import os
from flask import Flask, request, render_template
from nightfall import Confidence, DetectionRule, Detector, RedactionConfig, MaskConfig, Nightfall
from datetime import datetime, timedelta
import urllib.request, urllib.parse, json
import csv

app = Flask(__name__)

nightfall = Nightfall(
	key=os.getenv('NIGHTFALL_API_KEY'),
	signing_secret=os.getenv('NIGHTFALL_SIGNING_SECRET')
)
```

Next, we'll add our first route, which will display "Hello World" when the client navigates to `/ping` simply as a way to validate things are working:

```python
@app.route("/ping")
def ping():
	return "Hello World", 200
```

In a second command line window, run `gunicorn app:app` on the command line to fire up your server, and navigate to your local server in your web browser. You'll see where the web browser is hosted in the Gunicorn logs, typically it will be `127.0.0.1:8000` aka `localhost:8000`.

```bash
[2021-11-26 14:22:53 -0800] [61196] [INFO] Starting gunicorn 20.1.0
[2021-11-26 14:22:53 -0800] [61196] [INFO] Listening at: http://127.0.0.1:8000 (61196)
[2021-11-26 14:22:53 -0800] [61196] [INFO] Using worker: sync
[2021-11-26 14:22:53 -0800] [61246] [INFO] Booting worker with pid: 61246
```

To expose our local webhook server via a public tunnel that Nightfall can send requests to, we'll use ngrok. Download and install ngrok via their quickstart documentation [here](https://ngrok.com/docs/guides/quickstart). We'll create an ngrok tunnel as follows:

```bash
./ngrok http 8000
```

After running this command, `ngrok` will create a tunnel on the public internet that redirects traffic from their site to your local machine. Copy the HTTPS tunnel endpoint that ngrok has created: we can use this as the webhook URL when we trigger a file scan.

```bash
Account                       Nightfall Example
Version                       2.3.40
Region                        United States (us)
Web Interface                 http://127.0.0.1:4040
Forwarding                    http://3ecedafba368.ngrok.io -> http://localhost:8000
Forwarding                    https://3ecedafba368.ngrok.io -> http://localhost:8000
```

Let's set this HTTPS endpoint as a local environment variable so we can reference it later:

```bash
export NIGHTFALL_SERVER_URL=https://3ecedafba368.ngrok.io
```

**Tip:** With a Pro ngrok account, you can create a subdomain so that your tunnel URL is consistent, instead of randomly generated each time you start the tunnel.

## Handling an Inbound Webhook

Before we send a file scan request to Nightfall, let's implement our incoming webhook endpoint, so that when Nightfall finishes scanning a file, it can successfully send the sensitive findings to us.

First, what does it mean to have findings? If a file has findings, this means that Nightfall identified sensitive data in the file that matched the detection rules you configured. For example, if you told Nightfall to look for credit card numbers, any substring from the request payload that matched our credit card detector would constitute sensitive findings.

We'll host our incoming webhook at `/ingest` with a POST method.

Nightfall will POST to the webhook endpoint, and in the inbound payload, Nightfall will indicate if there are sensitive findings in the file, and provide a link where we can access the sensitive findings as JSON.

We'll validate the inbound webhook from Nightfall, retrieve the JSON findings from the link provided, and write the findings to a CSV file. First, let's initialize our CSV file where we will write results, and add our `/ingest` POST method.

```python
# create CSV where sensitive findings will be written
headers = ["upload_id", "#", "datetime", "before_context", "finding", "after_context", "detector", "confidence", "loc", "detection_rules"]
with open(f"results.csv", 'a') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(headers)

# respond to POST requests at /ingest
# Nightfall will send requests to this webhook endpoint with file scan results
@app.route("/ingest", methods=['POST'])
def ingest():
    data = request.get_json(silent=True)
    # validate webhook URL with challenge response
    challenge = data.get("challenge") 
    if challenge:
        return challenge
    # challenge was passed, now validate the webhook payload
    else: 
        # get details of the inbound webhook request for validation
        request_signature = request.headers.get('X-Nightfall-Signature')
        request_timestamp = request.headers.get('X-Nightfall-Timestamp')
        request_data = request.get_data(as_text=True)

        if nightfall.validate_webhook(request_signature, request_timestamp, request_data):
            # check if any sensitive findings were found in the file, return if not
            if not data["findingsPresent"]: 
                print("No sensitive data present!")
                return "", 200

            # there are sensitive findings in the file
            output_results(data)
            return "", 200
        else:
            return "Invalid webhook", 500
```

You'll notice that when there are sensitive findings, we call the `output_results()` method. Let's write that next. In `output_results()`, we are going to parse the findings and write them as rows into our CSV file.

```python
def output_results(data):
	findings_url = data['findingsURL']
	# open findings URL provided by Nightfall to access findings
	with urllib.request.urlopen(findings_url) as url:
		findings = json.loads(url.read().decode())
		findings = findings['findings']

	print(f"Sensitive data found, outputting {len(findings)} finding(s) to CSV | UploadID {data['uploadID']}")
	table = []
	# loop through findings JSON, get relevant finding metadata, write each finding as a row into output CSV
	for i, finding in enumerate(findings):
		row = [
			data['uploadID'],
			i+1,
			datetime.now(),
			repr(finding['beforeContext']), 
			repr(finding['finding']),
			repr(finding['afterContext']),
			finding['detector']['name'],
			finding['confidence'],
			finding['location']['byteRange'],
			finding['matchedDetectionRules']
		]
		table.append(row)
		with open(f"results.csv", 'a') as csvfile:
			writer = csv.writer(csvfile)
			writer.writerow(row)
	return
```

Restart your server so the changes propagate. We'll take a look at the console and CSV output of our webhook endpoint in the next section.

## Scan Changed Files in Real-Time

In our earlier command line window, we can now turn our attention back to `scanner.py`. We now have our webhook URL so let's set it here as well and run our scanner.

```bash
export NIGHTFALL_SERVER_URL=https://3ecedafba368.ngrok.io
python scanner.py
```

To trigger a file scan event, download the following [sample data file](https://raw.githubusercontent.com/nightfallai/dlp-sample-data/main/sample-pci.csv). Assuming it automatically downloads to your Downloads folder, this should immediately trigger a file change event and you'll see console log output! If not, you can also download the file with `curl` into a location that matches your event handler's regex we set earlier.

```bash
curl https://raw.githubusercontent.com/nightfallai/dlp-sample-data/main/sample-pci.csv > ~/Downloads/sample-pci.csv
```

You'll see the following console output from `scanner.py`:

```bash
Event type: modified | Path: /Users/myuser/Downloads/sample-pci.csv
Scan initiated | Path /Users/myuser/Downloads/sample-pci.csv | UploadID c23fdde2-5e98-4183-90b0-31e2cdd20ac0
```

And the following console output from our webhook server:

```bash
Sensitive data found, outputting 10 finding(s) to CSV | UploadID ac6a4a9d-a7b9-4a78-810d-8a66f7644704
```

And the following sensitive findings written to `results.csv`:

```csv
upload_id,#,datetime,before_context,finding,after_context,detector,confidence,loc,detection_rules
ac6a4a9d-a7b9-4a78-810d-8a66f7644704,1,2021-12-04 22:12:21.039602,'Name\tCredit Card\nRep. Viviana Hintz\t','5433-9502-3725-7862','\nEloisa Champlin\t3457-389808-83234\nOmega',Credit Card Number,VERY_LIKELY,"{'start': 36, 'end': 55}",[]
...
```

Each row in the output CSV will correspond to a sensitive finding. Each row will have the following fields, which you can customize in `app.py`: the upload ID provided by Nightfall, an incrementing index, timestamp, characters before the sensitive finding (for context), the sensitive finding itself, characters after the sensitive finding (for context), the confidence level of the detection, the byte range location (character indicies) of the sensitive finding in its parent file, and the corresponding detection rules that flagged the sensitive finding.

Note that you may also see events for system files like `.DS_Store` or errors corresponding to failed attempts to scan temporary versions of files. This is because doing things like downloading a file can trigger multiple file modification events. As an extension to this tutorial, you could consider filtering those out further, though they shouldn't impact our ability to scan files of interest.

If we leave these services running, we'll continue to monitor files for sensitive data and appending to our results CSV when sensitive findings are discovered!

## Running Endpoint DLP in the Background

We can run our two services in the background using `nohup` so that we don't need to leave two command line tabs open indefinitely. We'll pipe console output to log files so that we can always reference the application's output or determine if the services crashed for any reason.

```
nohup python -u scanner.py > scanner.log &
nohup gunicorn app:app > server.log &
```

This will return the corresponding process IDs - we can always check on these later with the `ps` command.

```bash
[1] 93373
[2] 93374
```

## Next Steps

This post is simply of a proof of concept version of endpoint DLP. Building a production-grade endpoint DLP application will have additional complexity and functionality. However, the detection engine is one of the biggest components of an endpoint DLP system, and this example should give you a sense of how easy it is to integrate with Nightfall's APIs and the power of Nightfall's detection engine.

Here are few ideas on how you can extend upon this service further:

* Run the scanner on EC2 machines to scan your production machines in real-time
* Respond to more system events like I/O of USB drives and external ports
* Implement remediation actions like end-user notifications or file deletion
* Redact the sensitive findings prior to writing them to the results file
* Store the results in the cloud for central reporting
* Package in an executable so the application can be run easily
* Scan all files on disk on the first boot of the application
