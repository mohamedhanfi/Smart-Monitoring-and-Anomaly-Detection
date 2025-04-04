import threading
import queue
import cv2
import time
from datetime import datetime
import os
from PIL import Image
import torch
from transformers import VideoMAEImageProcessor, VideoMAEForVideoClassification

# Device setup
device = "cuda" if torch.cuda.is_available() else "cpu"

# Load VideoMAE model and processor
model_name = "MCG-NJU/videomae-large"
processor = VideoMAEImageProcessor.from_pretrained(model_name)
model = VideoMAEForVideoClassification.from_pretrained(
    model_name,
    num_labels=6,
    ignore_mismatched_sizes=True
)
model.load_state_dict(torch.load("araby_model_weight.pth", map_location=torch.device('cpu')))
model.to(device)
model.eval()

# Define class details with severity and solution
class_details = {
    "Arson": {"severity": "High", "solution": "Activate fire suppression systems and notify fire department."},
    "Fighting": {"severity": "Medium", "solution": "Dispatch security personnel to intervene."},
    "RoadAccidents": {"severity": "High", "solution": "Notify emergency services and secure the area."},
    "Robbery": {"severity": "High", "solution": "Notify law enforcement immediately."},
    "Shooting": {"severity": "Critical", "solution": "Initiate lockdown procedures and contact police."},
    "Normal_Videos_for_Event_Recognition": {"severity": "None", "solution": "No action needed."}
}

# Update label mapping to match the new classes
label_mapping = {
    0: "Arson",
    1: "Fighting",
    2: "RoadAccidents",
    3: "Robbery",
    4: "Shooting",
    5: "Normal_Videos_for_Event_Recognition"
}
model.config.id2label = label_mapping
model.config.label2id = {v: k for k, v in label_mapping.items()}

class Camera:
    def __init__(self, path, name):
        self.path = path
        self.name = name

class Report:
    def __init__(self, camera_name, incident_type, timestamp, severity, solution):
        self.camera_name = camera_name
        self.incident_type = incident_type
        self.timestamp = timestamp
        self.severity = severity
        self.solution = solution

class SecurityMonitoring:
    def __init__(self):
        self.cameras = []
        self.reports = []
        self.frame_queues = {}
        self.threads = {}
        self.running = False
        self.lock = threading.Lock()

    def load_predefined_cameras(self):
        """Load predefined cameras with specific video files."""
        predefined = [
            ("C:/Users/dell/Desktop/Forth-Year/Graduation project/videos/Road_accidents.mp4", "Road Accidents Camera"),
            ("C:/Users/dell/Desktop/Forth-Year/Graduation project/videos/Robbery.mp4", "Robbery Camera"),
            ("C:/Users/dell/Desktop/Forth-Year/Graduation project/videos/shooting.mp4", "Shooting Camera"),
            ("C:/Users/dell/Desktop/Forth-Year/Graduation project/videos/Arson.mp4", "Arson Camera"),
            ("C:/Users/dell/Desktop/Forth-Year/Graduation project/videos/Fighting.mp4", "Fighting Camera"),
            ("C:/Users/dell/Desktop/Forth-Year/Graduation project/videos/normal.mp4", "Normal Camera"),
        ]
        with self.lock:
            for path, name in predefined:
                if not any(c.path == path for c in self.cameras):
                    self.add_camera(path, name)

    def add_camera(self, path, name):
        """Add a new camera to the system and initialize its frame queue."""
        with self.lock:
            camera = Camera(path, name)
            self.cameras.append(camera)
            self.frame_queues[len(self.cameras) - 1] = queue.Queue(maxsize=1)
            if self.running:
                self.start_camera_thread(len(self.cameras) - 1)

    def start_monitoring(self):
        """Start monitoring threads for all cameras."""
        with self.lock:
            if not self.running:
                self.running = True
                for idx in range(len(self.cameras)):
                    if idx not in self.threads or not self.threads[idx].is_alive():
                        self.start_camera_thread(idx)

    def stop_monitoring(self):
        """Stop all monitoring threads."""
        with self.lock:
            self.running = False
            for thread in self.threads.values():
                if thread.is_alive():
                    thread.join()

    def start_camera_thread(self, camera_idx):
        """Start a thread to process the camera feed."""
        thread = threading.Thread(target=self.process_camera_feed, args=(camera_idx,))
        thread.daemon = True
        thread.start()
        self.threads[camera_idx] = thread

    def process_camera_feed(self, camera_idx):
        """Process the camera feed, classify frames, and update the frame queue."""
        camera = self.cameras[camera_idx]
        cap = cv2.VideoCapture(camera.path if camera.path.isdigit() else camera.path)
        if not cap.isOpened():
            return

        frame_buffer = []
        while self.running:
            ret, frame = cap.read()
            if not ret:
                break

            # Add frame to queue for streaming
            try:
                self.frame_queues[camera_idx].put_nowait(frame)
            except queue.Full:
                pass

            # Add frame to buffer for classification
            frame_buffer.append(frame)
            if len(frame_buffer) == 16:
                self.classify_frames(camera_idx, frame_buffer)
                frame_buffer = []  # Reset buffer for non-overlapping sequences

        cap.release()

    def classify_frames(self, camera_idx, frame_buffer):
        """Classify a sequence of frames using the VideoMAE model."""
        # Convert BGR frames to RGB
        rgb_frames = [cv2.cvtColor(frame, cv2.COLOR_BGR2RGB) for frame in frame_buffer]
        pil_frames = [Image.fromarray(frame) for frame in rgb_frames]

        # Process frames with VideoMAE processor
        inputs = processor(pil_frames, return_tensors="pt")
        inputs = {k: v.to(device) for k, v in inputs.items()}

        # Run model inference
        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits
            predicted_class = torch.argmax(logits, dim=1).item()
            incident_type = model.config.id2label[predicted_class]

        # Record incident if not "Normal_Videos_for_Event_Recognition"
        if incident_type != "Normal_Videos_for_Event_Recognition":
            self.record_incident(camera_idx, incident_type, frame_buffer[-1])

    def record_incident(self, camera_idx, incident_type, frame):
        """Record an incident and save a snapshot."""
        camera = self.cameras[camera_idx]
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Use class_details to get severity and solution, with a fallback
        if incident_type in class_details:
            severity = class_details[incident_type]["severity"]
            solution = class_details[incident_type]["solution"]
        else:
            severity = "Unknown"
            solution = "Review footage"

        with self.lock:
            report = Report(camera.name, incident_type, timestamp, severity, solution)
            self.reports.append(report)

        # Save snapshot
        os.makedirs("snapshots", exist_ok=True)
        cv2.imwrite(f"snapshots/{camera.name}_{timestamp.replace(':', '-')}.jpg", frame)

    def generate_frames(self, camera_idx):
        """Generate frames for streaming in Flask."""
        while True:
            try:
                frame = self.frame_queues[camera_idx].get(timeout=1)
                ret, buffer = cv2.imencode('.jpg', frame)
                frame_bytes = buffer.tobytes()
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
            except queue.Empty:
                time.sleep(0.1)  # Wait briefly if no frame is available