import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
from urllib.parse import urlparse
from detector import (
    gui_register_user, 
    gui_login_user,
    current_user,
    create_database,
    generate_report
)

class PhishingDetectorGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Phishing Detector Pro")
        self.geometry("1000x700")
        self.configure(bg="#f0f0f0")
        
        create_database()
        
        self.style = ttk.Style()
        self.configure_styles()
        
        self.container = ttk.Frame(self)
        self.container.pack(fill="both", expand=True)
        
        self.frames = {}
        for F in (LoginFrame, RegisterFrame, MainMenuFrame):
            frame = F(self.container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(LoginFrame)
        
    def configure_styles(self):
        self.style.theme_use("clam")
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TButton", padding=6, font=('Helvetica', 10), background="#4a7a8c")
        self.style.configure("TLabel", background="#f0f0f0", foreground="#2c3e50")
        self.style.configure("Title.TLabel", font=('Helvetica', 16, 'bold'))
        self.style.configure("Error.TLabel", foreground="#e74c3c")
        
    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()
        frame.event_generate("<<ShowFrame>>")

class LoginFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.create_widgets()
        
    def create_widgets(self):
        title = ttk.Label(self, text="Phishing Detector Login", style="Title.TLabel")
        title.pack(pady=20)
        
        form_frame = ttk.Frame(self)
        form_frame.pack(pady=20)
        
        ttk.Label(form_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5)
        self.username_entry = ttk.Entry(form_frame)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(form_frame, text="Password:").grid(row=1, column=0, padx=5, pady=5)
        self.password_entry = ttk.Entry(form_frame, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)
        
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="Login", command=self.login).pack(side="left", padx=10)
        ttk.Button(btn_frame, text="Register", 
                 command=lambda: self.controller.show_frame(RegisterFrame)).pack(side="left", padx=10)
        
    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showwarning("Input Error", "Please enter both username and password")
            return
            
        success, message = gui_login_user(username, password)
        if success:
            messagebox.showinfo("Success", message)
            self.controller.show_frame(MainMenuFrame)
        else:
            messagebox.showerror("Login Failed", message)

class RegisterFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.create_widgets()
        
    def create_widgets(self):
        title = ttk.Label(self, text="User Registration", style="Title.TLabel")
        title.pack(pady=20)
        
        form_frame = ttk.Frame(self)
        form_frame.pack(pady=20)
        
        ttk.Label(form_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5)
        self.username_entry = ttk.Entry(form_frame)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(form_frame, text="Email:").grid(row=1, column=0, padx=5, pady=5)
        self.email_entry = ttk.Entry(form_frame)
        self.email_entry.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(form_frame, text="Password:").grid(row=2, column=0, padx=5, pady=5)
        self.password_entry = ttk.Entry(form_frame, show="*")
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)
        
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="Register", command=self.register).pack(side="left", padx=10)
        ttk.Button(btn_frame, text="Back", 
                 command=lambda: self.controller.show_frame(LoginFrame)).pack(side="left", padx=10)
        
    def register(self):
        username = self.username_entry.get()
        email = self.email_entry.get()
        password = self.password_entry.get()
        
        success, message = gui_register_user(username, email, password)
        if success:
            messagebox.showinfo("Success", message)
            self.controller.show_frame(LoginFrame)
        else:
            messagebox.showerror("Registration Failed", message)

class MainMenuFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.create_widgets()
        self.bind("<<ShowFrame>>", self.update_greeting)
        
    def create_widgets(self):
        title = ttk.Label(self, text="Phishing Detector Pro", style="Title.TLabel")
        title.pack(pady=20)
        
        self.greeting = ttk.Label(self, text="", style="TLabel")
        self.greeting.pack(pady=10)
        
        input_frame = ttk.Frame(self)
        input_frame.pack(pady=20)
        
        ttk.Label(input_frame, text="Enter URL to analyze:").pack(side="left")
        self.url_entry = ttk.Entry(input_frame, width=40)
        self.url_entry.pack(side="left", padx=10)
        
        ttk.Button(input_frame, text="Analyze", command=self.analyze_url).pack(side="left")
        
        self.results_area = scrolledtext.ScrolledText(self, wrap=tk.WORD, width=80, height=20)
        self.results_area.pack(pady=20, padx=20, fill="both", expand=True)
        self.configure_text_tags()
        
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Logout", command=self.logout).pack(side="left", padx=10)
        
    def configure_text_tags(self):
        self.results_area.tag_configure("header", font=('Helvetica', 12, 'bold'), spacing3=10)
        self.results_area.tag_configure("bold", font=('Helvetica', 10, 'bold'))
        self.results_area.tag_configure("red", foreground="#e74c3c")
        self.results_area.tag_configure("green", foreground="#27ae60")
        self.results_area.tag_configure("orange", foreground="#f39c12")
        
    def update_greeting(self, event=None):
        if current_user:
            self.greeting.config(text=f"Welcome, {current_user['username']}!")
    
    def detect_domain_typo(self, domain):
        common_domains = ['google', 'facebook', 'amazon', 'apple', 'microsoft',
                        'paypal', 'ebay', 'netflix', 'instagram', 'twitter']
        domain_lower = domain.lower()
        
        for correct in common_domains:
            if domain_lower.startswith(correct):
                return False
            if correct.startswith(domain_lower.replace('www.', '').split('.')[0]):
                return f"Did you mean {correct}.com?"
        
        return "This domain appears suspicious. Double-check the spelling!"
        
    def analyze_url(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL to analyze")
            return

        self.results_area.delete(1.0, tk.END)
        self.results_area.insert(tk.END, "Analyzing URL...\n")
        self.update_idletasks()

        try:
            # Validate URL format
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            parsed_url = urlparse(url)
            if not parsed_url.netloc:
                raise ValueError("Invalid URL format")

            # Check DNS resolution
            try:
                socket.gethostbyname(parsed_url.netloc)
            except socket.gaierror as e:
                typo_suggestion = self.detect_domain_typo(parsed_url.netloc)
                error_msg = f"DNS resolution failed for: {parsed_url.netloc}"
                if typo_suggestion:
                    error_msg += f"\n\n{typo_suggestion}"
                raise ValueError(error_msg)

            report = generate_report(url)
            self.display_report(report)

        except Exception as e:
            error_message = f"Analysis failed: {str(e)}\n\nPossible reasons:\n"
            error_message += "- Invalid URL format\n"
            error_message += "- Typo in domain name\n"
            error_message += "- Site is temporarily unavailable\n"
            error_message += "- No internet connection"
            
            self.results_area.delete(1.0, tk.END)
            self.results_area.insert(tk.END, "Analysis Failed!\n", "header")
            self.results_area.insert(tk.END, error_message)
            self.results_area.tag_add("red", "1.0", "end")
            
    def display_report(self, report):
        self.results_area.delete(1.0, tk.END)
        
        # URL Analysis
        self.results_area.insert(tk.END, "URL Analysis:\n", "header")
        self.add_result("HTTPS Enabled", report['features']['url']['uses_https'], bool)
        self.add_result("URL Length", f"{report['features']['url']['url_length']} characters")
        self.add_result("Contains IP", report['features']['url']['has_ip'], bool)
        self.add_result("Subdomains", report['features']['url']['num_subdomains'])
        self.add_result("Domain Age", 
                       f"{report['features']['url']['domain_age_days']} days" 
                       if report['features']['url']['domain_age_days'] != -1 
                       else "Unknown")
        
        # Content Analysis
        self.results_area.insert(tk.END, "\nContent Analysis:\n", "header")
        self.add_result("Password Fields", report['features']['content']['password_fields'])
        self.add_result("Suspicious Terms", report['features']['content']['suspicious_keywords'])
        self.add_result("Insecure Forms", report['features']['content']['insecure_forms'])
        
        # External Checks
        self.results_area.insert(tk.END, "\nExternal Checks:\n", "header")
        self.add_result("Google Safe Browsing", report['features']['google_safe'], bool)
        self.add_result("Suspicious Redirects", report['features']['redirects'], bool)
        self.add_result("VirusTotal Detection", report['features']['virustotal'], bool)
        
        # Risk Assessment
        self.results_area.insert(tk.END, "\nRisk Assessment:\n", "header")
        self.add_result("Total Score", f"{report['score']}/9", score=report['score'])
        
        # Verdict
        self.results_area.insert(tk.END, "\nFinal Verdict: ", "bold")
        verdict_tag = self.get_verdict_tag(report['verdict'])
        self.results_area.insert(tk.END, f"{report['verdict']}\n", verdict_tag)
        
    def add_result(self, label, value, bool=False, score=None):
        self.results_area.insert(tk.END, f"• {label}: ", "bold")
        if bool:
            display_value = "Yes" if value else "No"
            color_tag = "red" if value else "green"
            self.results_area.insert(tk.END, f"{display_value}\n", color_tag)
        elif score is not None:
            color_tag = "red" if score >= 6 else "orange" if score >=3 else "green"
            self.results_area.insert(tk.END, f"{value}\n", color_tag)
        else:
            self.results_area.insert(tk.END, f"{value}\n")
            
    def get_verdict_tag(self, verdict):
        if "High Risk" in verdict:
            return "red"
        elif "Warning" in verdict:
            return "orange"
        return "green"
        
    def logout(self):
        global current_user
        current_user = None
        self.controller.show_frame(LoginFrame)

if __name__ == "__main__":
    app = PhishingDetectorGUI()
    app.mainloop()

