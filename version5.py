import tkinter as tk
from tkinter import filedialog, Text, ttk
import os
import time
from ttkthemes import ThemedStyle

class VirusScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Virus Scanner")
        self.root.geometry("700x600")
        self.root.configure(bg="#34495e")
        
        self.style = ThemedStyle(self.root)
        self.style.set_theme("arc")
        
        self.style.configure("TButton", font=("Helvetica", 12, "bold"), padding=10)
        self.style.configure("TLabel", font=("Helvetica", 16, "bold"), background="#34495e", foreground="white")
        
        self.label = ttk.Label(root, text="Virus Scanner")
        self.label.pack(pady=10)
        
        self.text_area = Text(root, height=20, width=70, bg="#ecf0f1", fg="#2c3e50", font=("Courier", 12))
        self.text_area.pack(pady=10, padx=20)
        
        self.progress = ttk.Progressbar(root, orient='horizontal', mode='determinate', length=400)
        self.progress.pack(pady=10)
        
        self.scan_button = ttk.Button(root, text="Scan Directory", command=self.directory_open)
        self.scan_button.pack(pady=10)
        
        self.style.configure("TFrame", background="#34495e")
        self.bottom_frame = ttk.Frame(root)
        self.bottom_frame.pack(pady=10, fill=tk.BOTH, expand=True)
        
        self.quit_button = ttk.Button(self.bottom_frame, text="Quit", command=root.quit)
        self.quit_button.pack(side=tk.LEFT, padx=10)
        
        self.clear_button = ttk.Button(self.bottom_frame, text="Clear", command=self.clear_text)
        self.clear_button.pack(side=tk.RIGHT, padx=10)
        
    def directory_open(self):
        directory_path = filedialog.askdirectory()
        if directory_path:
            self.scan_directory(directory_path)
        
    def scan_directory(self, directory_path):
        self.text_area.delete(1.0, tk.END)
        start_time = time.time()
        file_count = 0
        result = ""
        virus_found = False
        
        files_list = []
        for root, _, files in os.walk(directory_path):
            for file in files:
                files_list.append(os.path.join(root, file))
        
        total_files = len(files_list)
        self.progress["maximum"] = total_files
        
        for file_path in files_list:
            file_count += 1
            scan_result = self.scan_file(file_path)
            result += scan_result
            if "Virus found" in scan_result:
                virus_found = True
            self.progress["value"] = file_count
            self.root.update_idletasks()
        
        end_time = time.time()
        time_taken = end_time - start_time
        
        self.display_result(result, virus_found, file_count, time_taken)
    
    def scan_file(self, file_path):
        with open(file_path, "rb") as f:
            file_content = f.read()
            
            virus_signatures = {
                b"X0/2132fkiubwjn9we8phffjffiywhnwo;inv0w8hgfnwekp": ("EICAR Test File", "Low"),
                b"7h8y9u0i-jkhg-fdsa-4321-09876abcdefg": ("Test Virus A", "Medium"),
                b"qwertyuiopasdfghjklzxcvbnm123456": ("Test Virus B", "High"),
                b"12345ABCDE67890FGHIJ12345KLMNO67890PQRST": ("Test Virus C", "High")
            }
            
            for signature, (virus_name, threat_level) in virus_signatures.items():
                if signature in file_content:
                    return f"Virus found: {virus_name} (Threat Level: {threat_level}) in file: {file_path}\n"
            return f"No virus found in file: {file_path}\n"
    
    def display_result(self, result, virus_found, file_count, time_taken):
        self.text_area.delete(1.0, tk.END)
        lines = result.split("\n")
        organized_report = {}
        
        for line in lines:
            if "Virus found" in line:
                virus_name = line.split(":")[1].strip().split(" (Threat Level")[0].strip()
                if virus_name not in organized_report:
                    organized_report[virus_name] = []
                organized_report[virus_name].append(line)
            else:
                if "No virus found" not in line:
                    self.text_area.insert(tk.END, line + "\n")
        
        for virus_name, reports in organized_report.items():
            self.text_area.insert(tk.END, f"\nVirus: {virus_name}\n", "virus")
            for report in reports:
                self.text_area.insert(tk.END, report + "\n", "virus")
        
        if virus_found:
            self.text_area.insert(tk.END, "\nPrecautions:\n", "precaution")
            self.text_area.insert(tk.END, "1. Isolate the infected files immediately.\n", "precaution")
            self.text_area.insert(tk.END, "2. Run a full system scan with a reputable antivirus software.\n", "precaution")
            self.text_area.insert(tk.END, "3. Avoid opening suspicious emails or downloading files from untrusted sources.\n", "precaution")
            self.text_area.insert(tk.END, "4. Keep your software and antivirus definitions up to date.\n", "precaution")
        else:
            self.text_area.insert(tk.END, "No viruses found in the scanned directory.\n", "no_virus")
        
        self.text_area.insert(tk.END, f"\nTotal files scanned: {file_count}\n", "info")
        self.text_area.insert(tk.END, f"Time taken: {time_taken:.2f} seconds\n", "info")
        
        self.text_area.tag_configure("virus", foreground="red", font=("Helvetica", 12, "bold"))
        self.text_area.tag_configure("precaution", foreground="orange", font=("Helvetica", 12, "italic"))
        self.text_area.tag_configure("no_virus", foreground="green", font=("Helvetica", 12, "bold"))
        self.text_area.tag_configure("info", foreground="blue", font=("Helvetica", 12, "italic"))

    def clear_text(self):
        self.text_area.delete(1.0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = VirusScannerApp(root)
    root.mainloop()
