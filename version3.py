import tkinter as tk
from tkinter import filedialog, Text, ttk
import os

class VirusScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Virus Scanner")
        self.root.geometry("600x500")
        self.root.configure(bg="#2c3e50")
        
        self.style = ttk.Style()
        self.style.configure("TButton", font=("Helvetica", 12), padding=10, background="#3498db", foreground="white")
        self.style.configure("TLabel", font=("Helvetica", 14), background="#2c3e50", foreground="white")
        
        self.label = ttk.Label(root, text="Virus Scanner")
        self.label.pack(pady=20)
        
        self.text_area = Text(root, height=15, width=60, bg="#ecf0f1", fg="#2c3e50", font=("Helvetica", 12))
        self.text_area.pack(pady=20)
        
        self.scan_button = ttk.Button(root, text="Scan Directory", command=self.directory_open)
        self.scan_button.pack(pady=10)
        
    def directory_open(self):
        directory_path = filedialog.askdirectory()
        if directory_path:
            self.scan_directory(directory_path)
        
    def scan_directory(self, directory_path):
        self.text_area.delete(1.0, tk.END)
        result = ""
        virus_found = False
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                scan_result = self.scan_file(file_path)
                result += scan_result
                if "Virus found" in scan_result:
                    virus_found = True
        
        self.display_result(result, virus_found)
    
    def scan_file(self, file_path):
        with open(file_path, "rb") as f:
            file_content = f.read()
            virus_signature = b"X0/2132fkiubwjn9we8phffjffiywhnwo;inv0w8hgfnwekp"
            if virus_signature in file_content:
                return f"Virus found in file: {file_path}\n"
            else:
                return f"No virus found in file: {file_path}\n"
    
    def display_result(self, result, virus_found):
        self.text_area.delete(1.0, tk.END)
        lines = result.split("\n")
        for line in lines:
            if "Virus found" in line:
                self.text_area.insert(tk.END, line + "\n", "virus")
            else:
                self.text_area.insert(tk.END, line + "\n")
        
        if virus_found:
            self.text_area.insert(tk.END, "\nPrecautions:\n", "precaution")
            self.text_area.insert(tk.END, "1. Isolate the infected files immediately.\n", "precaution")
            self.text_area.insert(tk.END, "2. Run a full system scan with a reputable antivirus software.\n", "precaution")
            self.text_area.insert(tk.END, "3. Avoid opening suspicious emails or downloading files from untrusted sources.\n", "precaution")
            self.text_area.insert(tk.END, "4. Keep your software and antivirus definitions up to date.\n", "precaution")
        
        self.text_area.tag_configure("virus", foreground="red")
        self.text_area.tag_configure("precaution", foreground="orange")

if __name__ == "__main__":
    root = tk.Tk()
    app = VirusScannerApp(root)
    root.mainloop()
 