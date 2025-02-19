import cv2
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from PIL import Image, ImageTk
import threading
import time
import random
from datetime import datetime
import re
from tkinter import PhotoImage
class SmartMonitoringApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Smart Monitoring & Anomaly Detection")
        self.root.state('zoomed')  # Start in full-screen mode

        # Load background image
        self.bg_image_path = "C:\\Users\\hanfy\\OneDrive\\Desktop\\GUI\\111.jpg"  
        self.bg_image = Image.open(self.bg_image_path)
        self.bg_image = self.bg_image.resize((self.root.winfo_screenwidth(), self.root.winfo_screenheight()))
        self.bg_photo = ImageTk.PhotoImage(self.bg_image)

        # Create a Label to display background
        self.bg_label = tk.Label(self.root, image=self.bg_photo)
        self.bg_label.place(relwidth=1, relheight=1)

        # Load users from the file
        self.users_file = "C:\\Users\\hanfy\\OneDrive\\Desktop\\GUI\\users.txt"
        self.users = self.load_users()

        # Styling for login frame
        style = ttk.Style()
        style.theme_use('clam')  # Use clam theme for better color control
        style.configure("TFrame", background="black")
        style.configure("TLabel", background="black", foreground="white")
        style.configure("TEntry", fieldbackground="black", foreground="white")
        style.configure("TButton", background="black", foreground="white")

        # Set root window background
        self.root.configure(bg="black")

        # Create login frame with padding and border
        self.login_frame = ttk.Frame(self.root, padding=20, style="TFrame")
        self.login_frame.place(relx=0.5, rely=0.5, anchor="center")

        # Load icons for username and password
        self.user_icon = PhotoImage(file="C:\\Users\\hanfy\\OneDrive\\Desktop\\GUI\\icons8-male-user-50.png")
        self.password_icon = PhotoImage(file="C:\\Users\\hanfy\\OneDrive\\Desktop\\GUI\\icons8-password-48.png")

        # Username label, icon, and entry
        self.username_label = ttk.Label(self.login_frame, font=("Arial", 14))
        self.username_label.grid(row=0, column=0, padx=10, pady=15, sticky="w")

        # Add user icon
        self.user_icon_label = ttk.Label(self.login_frame, image=self.user_icon, background="black")
        self.user_icon_label.grid(row=0, column=1, padx=(0, 10))

        self.username_entry = ttk.Entry(self.login_frame, font=("Arial", 14))
        self.username_entry.grid(row=0, column=2, padx=(0, 10), pady=15)

        # Password label, icon, and entry
        self.password_label = ttk.Label(self.login_frame,font=("Arial", 14))
        self.password_label.grid(row=1, column=0, padx=10, pady=15, sticky="w")

        # Add password icon
        self.password_icon_label = ttk.Label(self.login_frame, image=self.password_icon, background="black")
        self.password_icon_label.grid(row=1, column=1, padx=(0, 10))

        self.password_entry = ttk.Entry(self.login_frame, show="*", font=("Arial", 14))
        self.password_entry.grid(row=1, column=2, padx=(0, 10), pady=15)

        # Login button
        self.login_button = ttk.Button(self.login_frame, text="Login", command=self.login)
        self.login_button.grid(row=2, column=1, columnspan=2, padx=20, pady=15)

        # Main Application Frames
        self.main_frame = ttk.Frame(root)
        self.report_frame = ttk.Frame(root)

        # Initialize camera captures
        self.num_cameras = 8
        self.captures = [cv2.VideoCapture(f"D:\\Graduation Project\\UCF_Crimes\\Videos\\Arson\\Arson00{i+1}_x264.mp4") for i in range(self.num_cameras)]
        self.camera_labels = []

        # Reports Panel
        self.report_listbox = tk.Listbox(self.report_frame, width=50, height=15, font=("Arial", 14),background="black",fg="white")
        self.report_listbox.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Admin Panel
        self.admin_frame = ttk.Frame(root)
        self.operator_listbox = tk.Listbox(self.admin_frame, width=50, height=15, font=("Arial", 14),background="black",fg="white")
        self.operator_listbox.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.add_operator_button = ttk.Button(self.admin_frame, text="Add Operator", command=self.add_operator)
        self.add_operator_button.pack(padx=10, pady=10)

        self.delete_operator_button = ttk.Button(self.admin_frame, text="Delete Operator", command=self.delete_operator)
        self.delete_operator_button.pack(padx=10, pady=10)

        # Go Back Button for Admin and Operator Interfaces
        self.go_back_button = ttk.Button(self.root, text="Go Back", command=self.go_back)
        self.go_back_button.pack(padx=10, pady=10)

    def load_users(self):
        """Loads users from the file into a dictionary."""
        users = {}
        try:
            with open(self.users_file, "r") as file:
                for line in file:
                    username, password, role = line.strip().split(",")
                    users[username] = {"password": password, "role": role}
        except FileNotFoundError:
            # If the file doesn't exist, create it with default admin user
            with open(self.users_file, "w") as file:
                file.write("admin,admin123,admin\n")
            users = {"admin": {"password": "admin123", "role": "admin"}}
        return users

    def save_user(self, username, password, role):
        """Saves a new user to the file."""
        with open(self.users_file, "a") as file:
            file.write(f"{username},{password},{role}\n")

    def delete_user(self, username):
        """Deletes a user from the file."""
        with open(self.users_file, "r") as file:
            lines = file.readlines()
        with open(self.users_file, "w") as file:
            for line in lines:
                if not line.startswith(username + ","):
                    file.write(line)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        # Validate username (must be a string with no numbers or special characters)
        if not self.validate_username(username):
            messagebox.showerror("Invalid Username", "Username must contain only letters (no numbers or special characters).")
            return

        # Validate password (must be at least 8 characters long)
        if not self.validate_password(password):
            messagebox.showerror("Invalid Password", "Password must be at least 8 characters long.")
            return

        if username in self.users and self.users[username]["password"] == password:
            self.login_frame.destroy()  # Destroy the login frame
            if self.users[username]["role"] == "admin":
                self.show_admin_interface()
            else:
                self.show_operator_interface()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    def add_operator(self):
        """Adds a new operator."""
        username = simpledialog.askstring("Add Operator", "Enter username:")
        if username:
            # Validate username (must be a string with no numbers or special characters)
            if not self.validate_username(username):
                messagebox.showerror("Invalid Username", "Username must contain only letters (no numbers or special characters).")
                return

            if username in self.users:  # Check if the username already exists
                messagebox.showerror("Error", "Username already exists!")
                return

            password = simpledialog.askstring("Add Operator", "Enter password:", show="*")
            if password:
                # Validate password (must be at least 8 characters long)
                if not self.validate_password(password):
                    messagebox.showerror("Invalid Password", "Password must be at least 8 characters long.")
                    return

                self.save_user(username, password, "operator")  # Save to file
                self.users[username] = {"password": password, "role": "operator"}
                self.update_operator_listbox()  # Update the listbox
                messagebox.showinfo("Success", f"Operator '{username}' added successfully!")
            else:
                messagebox.showerror("Error", "Password cannot be empty!")
        else:
            messagebox.showerror("Error", "Username cannot be empty!")

    def validate_username(self, username):
        """Validates that the username contains only letters (no numbers or special characters)."""
        return bool(re.match("^[A-Za-z]+$", username))  # Only letters allowed

    def validate_password(self, password):
        """Validates that the password is at least 8 characters long."""
        return len(password) >= 8  # Password must be at least 8 characters

    def show_admin_interface(self):
        self.admin_frame.pack(padx=20, pady=20, side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.report_frame.pack(padx=20, pady=20, side=tk.RIGHT, fill=tk.BOTH, expand=True)
        self.update_operator_listbox()
        self.fake_detection_thread()

    def show_operator_interface(self):
        self.main_frame.pack(padx=20, pady=20, side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.report_frame.pack(padx=20, pady=20, side=tk.RIGHT, fill=tk.BOTH, expand=True)
        self.create_camera_grid()
        self.start_video_threads()
        self.fake_detection_thread()

    def create_camera_grid(self):
        """Creates a grid layout for multiple camera feeds with full-screen size."""
        rows = 4
        cols = 2
        for i in range(self.num_cameras):
            frame = ttk.LabelFrame(self.main_frame, text=f"Camera {i+1}")
            frame.grid(row=i // cols, column=i % cols, padx=10, pady=10, sticky="nsew")
            label = tk.Label(frame, text="[There is some issue]", font=("Arial", 14), fg="red")
            label.pack(fill=tk.BOTH, expand=True)
            self.camera_labels.append(label)

        # Configure grid weights to make all frames the same size
        for i in range(rows):
            self.main_frame.grid_rowconfigure(i, weight=1)
        for j in range(cols):
            self.main_frame.grid_columnconfigure(j, weight=1)

    def start_video_threads(self):
        """Starts threads to update each camera feed."""
        for i in range(self.num_cameras):
            threading.Thread(target=self.update_camera, args=(i,), daemon=True).start()

    def update_camera(self, index):
        """Fetches frames from the videos and updates the GUI."""
        while True:
            ret, frame = self.captures[index].read()
            if not ret:
                self.captures[index].set(cv2.CAP_PROP_POS_FRAMES, 0)  # Restart video
                continue

            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            frame = cv2.resize(frame, (400, 300))  # Adjusted size for full-screen
            img = ImageTk.PhotoImage(image=Image.fromarray(frame))

            self.camera_labels[index].imgtk = img
            self.camera_labels[index].config(image=img)
            time.sleep(0.03)

    def fake_detection_thread(self):
        """Simulates anomaly detection events and updates the report listbox."""
        emergency_count = 0  # Counter for emergencies

        def add_real_reports():
                while True:
                    time.sleep(random.randint(3, 8))
                    event_data = random.choice(real_reports)
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    severity = event_data["severity"]
                    event = event_data["event"]
                    solution = event_data["solution"]
                    emergency_count = event_data["emergency_count"]

                    report = f"[{timestamp}]\n[Severity: {severity}]\nEvent: {event}\nSolution: {solution}\nEmergencies: {emergency_count}\n"

                    self.report_listbox.insert(tk.END, report)
                    self.report_listbox.insert(tk.END, "-" * 50 + "\n")  # Separator line for better readability

        threading.Thread(target=add_real_reports, daemon=True).start()
        def add_fake_reports():
            fake_reports = [
                {
                    "event": "Intruder detected in restricted area",
                    "severity": "High",
                    "solution": "Activate security protocols, notify law enforcement, and lock down the area."
                },
                {
                    "event": "Unusual motion detected in storage room",
                    "severity": "Medium",
                    "solution": "Review camera footage, dispatch security personnel, and investigate the cause."
                },
                {
                    "event": "Fire alert triggered in the kitchen",
                    "severity": "High",
                    "solution": "Evacuate the area, activate fire suppression systems, and contact the fire department."
                },
                {
                    "event": "Suspicious package left in the lobby",
                    "severity": "High",
                    "solution": "Evacuate the area, notify bomb disposal units, and secure the perimeter."
                },
                {
                    "event": "Unauthorized access attempt at server room",
                    "severity": "Medium",
                    "solution": "Lock server room doors, review access logs, and identify the individual."
                },
                {
                    "event": "Person loitering near the entrance for over 30 minutes",
                    "severity": "Low",
                    "solution": "Approach the individual, verify their purpose, and escort them if necessary."
                },
                {
                    "event": "High-temperature anomaly detected in electrical room",
                    "severity": "High",
                    "solution": "Shut down affected equipment, notify maintenance, and investigate the cause."
                },
                {
                    "event": "Loud noise detected in the parking lot",
                    "severity": "Medium",
                    "solution": "Dispatch security to investigate, check for signs of disturbance, and report findings."
                },
                {
                    "event": "Broken window detected on the ground floor",
                    "severity": "Medium",
                    "solution": "Secure the area, repair the window, and investigate for signs of forced entry."
                },
                {
                    "event": "Object left unattended in the hallway",
                    "severity": "Low",
                    "solution": "Inspect the object, remove it if safe, and notify security for further investigation."
                }
            ]
            while True:
                time.sleep(random.randint(3, 8))
                event = random.choice(fake_reports)
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                report = f"[{timestamp}]\n{event['event']}\nSeverity: {event['severity']}\nSolution: {event['solution']}\n"
                self.report_listbox.insert(tk.END, report)
                self.report_listbox.insert(tk.END, "-" * 200 + "\n")  

        threading.Thread(target=add_fake_reports, daemon=True).start()

    def update_operator_listbox(self):
        """Updates the listbox with current operators."""
        self.operator_listbox.delete(0, tk.END)
        for username, info in self.users.items():
            if info["role"] == "operator":
                self.operator_listbox.insert(tk.END, username)

    def delete_operator(self):
        """Deletes the selected operator."""
        selected = self.operator_listbox.curselection()
        if selected:
            username = self.operator_listbox.get(selected)
            if username in self.users:
                self.delete_user(username)  # Delete from file
                del self.users[username]
                self.update_operator_listbox()  # Update the listbox
                messagebox.showinfo("Success", f"Operator '{username}' deleted successfully!")
            else:
                messagebox.showerror("Error", "Operator not found!")
        else:
            messagebox.showerror("Error", "No operator selected!")
    def go_back(self):
        """Returns to the login page and resets the UI."""
        for widget in self.root.winfo_children():
            widget.destroy()  # Remove all widgets

        self.__init__(self.root)  # Reinitialize the application UI


    def __del__(self):
        if hasattr(self, 'captures'):  
            for cap in self.captures:
                if cap.isOpened():
                    cap.release()

if __name__ == "__main__":
    root = tk.Tk()
    app = SmartMonitoringApp(root)
    root.mainloop()
