import tkinter as tk
from tkinter import ttk, scrolledtext
from tkinter import messagebox
import google.generativeai as genai
from dotenv import load_dotenv
import os
import threading

class CyberAttackInfoApp:
    def _init_(self, master=None):  # Fixed initialization
        if master is None:
            master = tk.Tk()
        self.root = master
        self.root.title("Guardian Gaze - Cyber Attack Information System")
        self.root.geometry("800x600")
        self.root.configure(bg='#f0f0f0')
        
        # Setup Gemini
        self.setup_gemini()
        # Create GUI elements
        self.create_widgets()

    def setup_gemini(self):
        """Setup Gemini API with proper error handling"""
        try:
            api_key = os.getenv('GEMINI_API_KEY')
            if not api_key:
                raise ValueError("API key not found in .env file")
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel('gemini-pro')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to initialize Gemini API: {str(e)}")
            self.root.destroy()
            return

    def create_widgets(self):
        # Create main frame
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # Style configuration
        style = ttk.Style()
        style.configure('TLabel', font=('Arial', 12))
        style.configure('TButton', font=('Arial', 11))
        
        # Title
        title_label = ttk.Label(
            self.main_frame, 
            text="Guardian Gaze - Cyber Attack Information System",
            font=('Arial', 16, 'bold')
        )
        title_label.grid(row=0, column=0, columnspan=2, pady=10)

        # Attack type selection
        ttk.Label(self.main_frame, text="Select Attack Type:").grid(
            row=1, column=0, pady=5, padx=5, sticky=tk.W
        )

        # Combobox for attack types
        self.attack_types = [
            "Select an attack type...",
            "DoS Attack",
            "DDoS Attack",
            "Brute Force Attack",
            "SQL Injection",
            "Cross-Site Scripting (XSS)",
            "Man-in-the-Middle Attack",
            "Phishing Attack",
            "Ransomware Attack",
            "Data Exfiltration",
            "Zero-day Exploit"
        ]
        
        self.attack_var = tk.StringVar()
        self.attack_combobox = ttk.Combobox(
            self.main_frame, 
            textvariable=self.attack_var,
            values=self.attack_types,
            width=30
        )
        self.attack_combobox.set(self.attack_types[0])
        self.attack_combobox.grid(row=1, column=1, pady=5, padx=5, sticky=tk.W)

        # Custom attack entry
        ttk.Label(self.main_frame, text="Or Enter Custom Attack:").grid(
            row=2, column=0, pady=5, padx=5, sticky=tk.W
        )
        
        self.custom_attack = ttk.Entry(self.main_frame, width=33)
        self.custom_attack.grid(row=2, column=1, pady=5, padx=5, sticky=tk.W)

        # Create button frame for better organization
        button_frame = ttk.Frame(self.main_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)

        # Get Info Button
        self.get_info_button = ttk.Button(
            button_frame,
            text="Get Information",
            command=self.get_attack_info,
            style='TButton'
        )
        self.get_info_button.pack(side=tk.LEFT, padx=5)

        # Clear button
        self.clear_button = ttk.Button(
            button_frame,
            text="Clear",
            command=self.clear_results,
            style='TButton'
        )
        self.clear_button.pack(side=tk.LEFT, padx=5)

        # Loading indicator
        self.loading_label = ttk.Label(
            self.main_frame,
            text="",
            font=('Arial', 10, 'italic')
        )
        self.loading_label.grid(row=4, column=0, columnspan=2)

        # Result area
        self.result_text = scrolledtext.ScrolledText(
            self.main_frame,
            wrap=tk.WORD,
            width=70,
            height=20,
            font=('Arial', 11)
        )
        self.result_text.grid(row=5, column=0, columnspan=2, pady=10, padx=5)

    def get_attack_info(self):
        # Get attack type from either combobox or custom entry
        attack_type = self.custom_attack.get().strip()
        if not attack_type:
            attack_type = self.attack_var.get()
            if attack_type == self.attack_types[0]:
                messagebox.showwarning(
                    "Warning",
                    "Please select an attack type or enter a custom attack"
                )
                return

        # Disable inputs while processing
        self.set_input_state(tk.DISABLED)
        self.loading_label.config(text="Fetching information...")
        
        # Start processing in a separate thread
        thread = threading.Thread(target=self.fetch_info, args=(attack_type,))
        thread.daemon = True
        thread.start()

    def fetch_info(self, attack_type):
        try:
            prompt = f"""
            Provide detailed information about the {attack_type} in the following format:

            ATTACK NAME: {attack_type}
            
            DESCRIPTION:
            [Detailed explanation of what this attack is]

            HOW IT WORKS:
            [Technical explanation of the attack mechanism]

            PREVENTION MEASURES:
            1. [Measure 1]
            2. [Measure 2]
            ...

            BEST PRACTICES:
            1. [Practice 1]
            2. [Practice 2]
            ...

            RECOMMENDED SECURITY TOOLS:
            1. [Tool 1]
            2. [Tool 2]
            ...

            SITES/ACTIVITIES TO AVOID:
            1. [Risk 1]
            2. [Risk 2]
            ...
            """

            response = self.model.generate_content(prompt)
            
            # Update UI in the main thread
            self.root.after(0, self.update_results, response.text)
        except Exception as e:
            self.root.after(0, self.show_error, str(e))

    def update_results(self, text):
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, text)
        self.loading_label.config(text="")
        self.set_input_state(tk.NORMAL)

    def show_error(self, error_message):
        messagebox.showerror("Error", f"Failed to get information: {error_message}")
        self.loading_label.config(text="")
        self.set_input_state(tk.NORMAL)

    def set_input_state(self, state):
        self.attack_combobox.config(state=state)
        self.custom_attack.config(state=state)
        self.get_info_button.config(state=state)
        self.clear_button.config(state=state)

    def clear_results(self):
        self.result_text.delete(1.0, tk.END)
        self.attack_combobox.set(self.attack_types[0])
        self.custom_attack.delete(0, tk.END)

def main():
    root = tk.Tk()
    app = CyberAttackInfoApp(master=root)  # Fixed initialization
    root.mainloop()

if __name__ == "__main__":
    main()