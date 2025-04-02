import tkinter as tk
from tkinter import messagebox
import os
import platform

# Dictionary to store user credentials
users = {}

# Function to register a new user
def register():
    username = reg_username_entry.get()
    password = reg_password_entry.get()
    sec_question = sec_question_entry.get()
    sec_answer = sec_answer_entry.get()
    
    if username and password and sec_question and sec_answer:
        users[username] = {'password': password, 'sec_question': sec_question, 'sec_answer': sec_answer}
        messagebox.showinfo("Success", "Registration successful! You can now log in.")
        reg_window.destroy()
    else:
        messagebox.showerror("Error", "All fields are required!")

# Function to show registration window
def show_register_window():
    global reg_window, reg_username_entry, reg_password_entry, sec_question_entry, sec_answer_entry
    reg_window = tk.Toplevel(root)
    reg_window.title("Register")
    reg_window.geometry("300x300")
    
    tk.Label(reg_window, text="Username:").pack()
    reg_username_entry = tk.Entry(reg_window)
    reg_username_entry.pack()
    
    tk.Label(reg_window, text="Password:").pack()
    reg_password_entry = tk.Entry(reg_window, show="*")
    reg_password_entry.pack()
    
    tk.Label(reg_window, text="Security Question:").pack()
    sec_question_entry = tk.Entry(reg_window)
    sec_question_entry.pack()
    
    tk.Label(reg_window, text="Answer:").pack()
    sec_answer_entry = tk.Entry(reg_window)
    sec_answer_entry.pack()
    
    tk.Button(reg_window, text="Register", command=register).pack()

# Function to login
def login():
    username = login_username_entry.get()
    password = login_password_entry.get()
    
    if username in users and users[username]['password'] == password:
        messagebox.showinfo("Success", "Login successful!")
        login_window.destroy()
        show_usb_controls()
    else:
        messagebox.showerror("Error", "Invalid username or password!")

# Function to show login window
def show_login_window():
    global login_window, login_username_entry, login_password_entry
    login_window = tk.Toplevel(root)
    login_window.title("Login")
    login_window.geometry("300x200")
    
    tk.Label(login_window, text="Username:").pack()
    login_username_entry = tk.Entry(login_window)
    login_username_entry.pack()
    
    tk.Label(login_window, text="Password:").pack()
    login_password_entry = tk.Entry(login_window, show="*")
    login_password_entry.pack()
    
    tk.Button(login_window, text="Login", command=login).pack()
    tk.Button(login_window, text="Forgot Password?", command=reset_password).pack()

# Function to reset password
def reset_password():
    username = login_username_entry.get()
    if username in users:
        answer = messagebox.askstring("Security Question", users[username]['sec_question'])
        if answer == users[username]['sec_answer']:
            new_password = messagebox.askstring("Reset Password", "Enter new password:")
            if new_password:
                users[username]['password'] = new_password
                messagebox.showinfo("Success", "Password reset successful!")
        else:
            messagebox.showerror("Error", "Incorrect answer!")
    else:
        messagebox.showerror("Error", "User not found!")

# Function to enable USB
def enable_usb():
    if platform.system() == "Windows":
        os.system("reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR /v Start /t REG_DWORD /d 3 /f")
    messagebox.showinfo("Success", "USB Ports have been enabled successfully!")

# Function to disable USB
def disable_usb():
    if platform.system() == "Windows":
        os.system("reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR /v Start /t REG_DWORD /d 4 /f")
    messagebox.showinfo("Success", "USB Ports have been disabled successfully!")

# Function to show project info
def show_project_info():
    info_window = tk.Toplevel(root)
    info_window.title("Project Information")
    info_window.geometry("400x300")
    
    info_label = tk.Label(info_window, text="USB Physical Security", font=("Arial", 14, "bold"))
    info_label.pack(pady=10)
    
    project_details = """
    Project Name: USB Physical Security
    Description: Securing organizations from USB-based threats.
    Developer: TATIKAYALA VISHNU VARDHAN
    Company: SUPRAJA TECHNOLOGIES
    Status: Completed
    """
    details_label = tk.Label(info_window, text=project_details, justify="left")
    details_label.pack(padx=20, pady=10)

# Function to show USB controls after login
def show_usb_controls():
    usb_window = tk.Toplevel(root)
    usb_window.title("USB Security")
    usb_window.geometry("300x200")
    
    tk.Button(usb_window, text="Disable USB", bg="red", fg="white", command=disable_usb).pack(pady=5)
    tk.Button(usb_window, text="Enable USB", bg="green", fg="white", command=enable_usb).pack(pady=5)
    tk.Button(usb_window, text="Project Info", command=show_project_info).pack(pady=5)

# GUI Setup
root = tk.Tk()
root.title("USB Security System")
root.geometry("300x200")

btn_register = tk.Button(root, text="Register", command=show_register_window)
btn_register.pack(pady=10)

btn_login = tk.Button(root, text="Login", command=show_login_window)
btn_login.pack(pady=10)

root.mainloop()