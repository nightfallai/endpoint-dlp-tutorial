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
