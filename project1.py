import tkinter as tk
from tkinter import messagebox, simpledialog, BooleanVar, Checkbutton, Toplevel, Text, ttk
import random
import re
import requests
import string
import hashlib

# Password strength checker criteria
MIN_LENGTH = 8
MIN_LENGTH_STRONG = 12

# Function to check if the password exactly matches any common words or dictionary words
def is_exact_match(password, file_path):
    password_lower = password.lower()
    
    with open(file_path, 'r', encoding='latin-1') as file:
        for line in file:
            common_word = line.strip().lower()
            if password_lower == common_word:
                return True

    return False

# Function to check for repeated or sequential characters
def has_repeated_or_sequential_chars(password):
    if re.search(r'(.)\1{2,}', password):  # Repeated characters
        return True
    if re.search(r'(012|123|234|345|456|567|678|789)', password):  # Sequential numbers
        return True
    if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk)', password):  # Sequential letters
        return True
    return False

# Function to evaluate the password
def evaluate_password(password):
    # First, check if the password is not unique
    if is_exact_match(password, 'rockyou.txt'):
        return "Your password is not unique. Choose something more unique."

    reasons = []
    
    # Check minimum length
    if len(password) < MIN_LENGTH:
        reasons.append("Password is too short. Consider using at least 8 characters.")
    
    # Check character variety
    has_upper = re.search(r'[A-Z]', password)
    has_lower = re.search(r'[a-z]', password)
    has_digit = re.search(r'\d', password)
    has_special = re.search(r'[!@#$%^&*(),.?\":{}|<>]', password)
    
    if not has_upper:
        reasons.append("Password should include at least one uppercase letter.")
    if not has_lower:
        reasons.append("Password should include at least one lowercase letter.")
    if not has_digit:
        reasons.append("Password should include at least one number.")
    if not has_special:
        reasons.append("Password should include at least one special character.")
    
    # Check for repeated or sequential characters
    if has_repeated_or_sequential_chars(password):
        reasons.append("Password contains repeated or sequential characters. Avoid patterns like 'aaa' or '123'.")
    
    # Length-based strengthening
    if len(password) >= MIN_LENGTH_STRONG:
        if has_digit and has_special and len(reasons) == 0:
            return "Your password is strong and meets all the criteria."
        else:
            return "Your password is of medium strength. Consider addressing the following:\n" + "\n".join(reasons)
    
    if len(reasons) == 0:
        return "Your password is of medium strength. It meets most criteria but could be longer for added strength."
    
    return "Your password is weak:\n" + "\n".join(reasons)

# GUI function for password strength check
def check_password():
    password = password_entry.get()
    result = evaluate_password(password)
    messagebox.showinfo("Password Evaluation", result)

# Function to check if a password has been compromised using the 'Have I Been Pwned' API
def check_pwned_password():
    password = password_entry.get()
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    
    response = requests.get(url)
    
    if response.status_code != 200:
        messagebox.showerror("Error", "Could not connect to the Pwned Passwords API.")
        return
    
    hashes = (line.split(':') for line in response.text.splitlines())
    for hash_suffix, count in hashes:
        if suffix == hash_suffix:
            messagebox.showinfo("Compromised Password", f"Your password has been compromised {count} times. Choose a different one.")
            return
    
    messagebox.showinfo("Compromised Password", "Your password has not been compromised. It is safe to use.")

# Function to generate a password
def generate_password():
    length = simpledialog.askinteger("Password Length", "Enter the desired length of the password:", minvalue=4, maxvalue=128)
    
    if length is None:  # If the user cancels the input dialog
        return

    include_upper = BooleanVar(value=True)
    include_lower = BooleanVar(value=True)
    include_digits = BooleanVar(value=True)
    include_special = BooleanVar(value=True)

    options_window = Toplevel(root)
    options_window.title("Password Options")

    Checkbutton(options_window, text="Include Uppercase Letters", variable=include_upper).pack(anchor='w')
    Checkbutton(options_window, text="Include Lowercase Letters", variable=include_lower).pack(anchor='w')
    Checkbutton(options_window, text="Include Numbers", variable=include_digits).pack(anchor='w')
    Checkbutton(options_window, text="Include Special Characters", variable=include_special).pack(anchor='w')

    def create_password():
        characters = ""
        if include_upper.get():
            characters += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if include_lower.get():
            characters += "abcdefghijklmnopqrstuvwxyz"
        if include_digits.get():
            characters += "0123456789"
        if include_special.get():
            characters += "!@#$%^&*(),.?\":{}|<>"

        if not characters:
            messagebox.showwarning("Warning", "No character types selected! Please select at least one option.")
            return

        password = ''.join(random.choice(characters) for _ in range(length))

        # Display the generated password in a new Toplevel window
        password_window = Toplevel(root)
        password_window.title("Generated Password")

        tk.Label(password_window, text="Your generated password:").pack(pady=10)

        password_text = Text(password_window, height=2, width=50)
        password_text.insert(1.0, password)
        password_text.config(state='disabled')  # Make the text widget read-only
        password_text.pack(pady=10)

        tk.Button(password_window, text="Copy to Clipboard", command=lambda: root.clipboard_append(password)).pack(pady=10)

        # Add Save Password button
        def on_save_password():
            save_password_details(password)
            password_window.destroy()

        save_button = tk.Button(password_window, text="Save Password", command=on_save_password)
        save_button.pack(pady=10)

        options_window.destroy()

    generate_button = tk.Button(options_window, text="Generate Password", command=create_password)
    generate_button.pack(pady=10)

# Function to save generated passwords
def save_password_details(password):
    def save_to_file(platform, email, phone, account):
        with open("passwords.txt", "a") as file:
            file.write(f"{platform},{email},{phone},{account},{password}\n")
    
    # Create a new Toplevel window to input password details
    details_window = Toplevel(root)
    details_window.title("Save Password Details")
    
    tk.Label(details_window, text="Platform Name (e.g., YouTube, Google):").pack(pady=5)
    platform_entry = tk.Entry(details_window, width=50)
    platform_entry.pack(pady=5)
    
    tk.Label(details_window, text="Email Address:").pack(pady=5)
    email_entry = tk.Entry(details_window, width=50)
    email_entry.pack(pady=5)
    
    tk.Label(details_window, text="Phone Number:").pack(pady=5)
    phone_entry = tk.Entry(details_window, width=50)
    phone_entry.pack(pady=5)
    
    tk.Label(details_window, text="Account Name (e.g., myaccount):").pack(pady=5)
    account_entry = tk.Entry(details_window, width=50)
    account_entry.pack(pady=5)

    def save_details():
        platform = platform_entry.get()
        email = email_entry.get()
        phone = phone_entry.get()
        account = account_entry.get()
        save_to_file(platform, email, phone, account)
        details_window.destroy()
    
    save_button = tk.Button(details_window, text="Save", command=save_details)
    save_button.pack(pady=10)

# Function to display the start screen
def show_start_screen():
    for widget in root.winfo_children():
        widget.destroy()
    
    tk.Label(root, text="Welcome to the Password Manager!").pack(pady=20)
    tk.Button(root, text="Check Password Strength", command=show_password_check_screen).pack(pady=10)
    tk.Button(root, text="Check if Password is Compromised", command=show_pwned_check_screen).pack(pady=10)
    tk.Button(root, text="Generate a New Password", command=show_password_generator_screen).pack(pady=10)
    tk.Button(root, text="View Saved Passwords", command=show_saved_passwords_screen).pack(pady=10)

# Function to display the password strength check screen
def show_password_check_screen():
    for widget in root.winfo_children():
        widget.destroy()
    
    tk.Label(root, text="Enter a password:").pack(pady=10)
    global password_entry
    password_entry = tk.Entry(root, width=50)
    password_entry.pack(pady=5)

    check_button = tk.Button(root, text="Check Password", command=check_password)
    check_button.pack(pady=20)
    
    back_button = tk.Button(root, text="Back to Start Screen", command=show_start_screen)
    back_button.pack(pady=10)

# Function to display the compromised password check screen
def show_pwned_check_screen():
    for widget in root.winfo_children():
        widget.destroy()
    
    tk.Label(root, text="Enter a password to check:").pack(pady=10)
    global password_entry
    password_entry = tk.Entry(root, width=50)
    password_entry.pack(pady=5)

    pwned_button = tk.Button(root, text="Check Compromise", command=check_pwned_password)
    pwned_button.pack(pady=20)
    
    back_button = tk.Button(root, text="Back to Start Screen", command=show_start_screen)
    back_button.pack(pady=10)

# Function to display the password generator screen
def show_password_generator_screen():
    for widget in root.winfo_children():
        widget.destroy()
    
    tk.Label(root, text="Password Generator").pack(pady=10)

    generate_button = tk.Button(root, text="Generate Password", command=generate_password)
    generate_button.pack(pady=20)

    back_button = tk.Button(root, text="Back to Start Screen", command=show_start_screen)
    back_button.pack(pady=10)

# Function to show saved passwords screen
def show_saved_passwords_screen():
    def delete_password(platform, email, phone, account):
        with open("passwords.txt", "r") as file:
            lines = file.readlines()
        
        with open("passwords.txt", "w") as file:
            for line in lines:
                # Skip the line that starts with the same platform, email, phone, account
                if not line.startswith(f"{platform},{email},{phone},{account},"):
                    file.write(line)
        
        show_saved_passwords_screen()

    def copy_to_clipboard(text):
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()  # Now it stays on the clipboard

    # Clear current widgets
    for widget in root.winfo_children():
        widget.destroy()

    # Create the main frame
    main_frame = tk.Frame(root)
    main_frame.pack(fill='both', expand=True)

    # Create a canvas widget
    canvas = tk.Canvas(main_frame)
    canvas.pack(side='left', fill='both', expand=True)

    # Create vertical and horizontal scrollbars
    vertical_scrollbar = ttk.Scrollbar(main_frame, orient='vertical', command=canvas.yview)
    vertical_scrollbar.pack(side='right', fill='y')

    horizontal_scrollbar = ttk.Scrollbar(main_frame, orient='horizontal', command=canvas.xview)
    horizontal_scrollbar.pack(side='bottom', fill='x')

    # Create a frame inside the canvas for content
    scrollable_frame = tk.Frame(canvas)
    canvas.create_window((0, 0), window=scrollable_frame, anchor='nw')

    # Update the scroll region when the content frame is resized
    def on_frame_configure(event):
        canvas.configure(scrollregion=canvas.bbox("all"))

    scrollable_frame.bind("<Configure>", on_frame_configure)

    # Configure scrollbars to work with canvas
    canvas.config(xscrollcommand=horizontal_scrollbar.set, yscrollcommand=vertical_scrollbar.set)
    horizontal_scrollbar.config(command=canvas.xview)
    vertical_scrollbar.config(command=canvas.yview)

    tk.Label(scrollable_frame, text="Saved Passwords:").pack(pady=10)

    try:
        with open("passwords.txt", "r") as file:
            for line in file:
                try:
                    platform, email, phone, account, password = line.strip().split(',', 4)
                    
                    frame = tk.Frame(scrollable_frame, borderwidth=2, relief="groove", padx=10, pady=10)
                    frame.pack(fill='x', pady=5)

                    details = f"Platform: {platform}\nEmail: {email}\nPhone: {phone}\nAccount: {account}"
                    tk.Label(frame, text=details, justify='left').pack(side='left', fill='x')

                    password_text = tk.Entry(frame, width=50)
                    password_text.insert(0, password)
                    password_text.config(state='readonly')
                    password_text.pack(side='left', padx=5)

                    def copy_password(pw=password):
                        copy_to_clipboard(pw)
                    
                    copy_button = tk.Button(frame, text="Copy", command=copy_password)
                    copy_button.pack(side='left', padx=5)

                    delete_button = tk.Button(frame, text="Delete", command=lambda p=platform, e=email, ph=phone, a=account: delete_password(p, e, ph, a))
                    delete_button.pack(side='right', padx=5)
                except ValueError:
                    print(f"Skipping malformed line: {line.strip()}")

    except FileNotFoundError:
        tk.Label(scrollable_frame, text="No saved passwords found.").pack(pady=10)

    # Add a "Back to Start Screen" button
    back_button = tk.Button(root, text="Back to Start Screen", command=show_start_screen)
    back_button.pack(side='bottom', pady=10)

    # Ensure scrollbars and canvas are correctly sized
    root.update_idletasks()  # Update window to compute sizes
    canvas.config(scrollregion=canvas.bbox("all"))

    # Ensure the horizontal scrollbar spans the full width
    canvas.update_idletasks()
    canvas.configure(width=canvas.winfo_width())

# Main GUI setup
root = tk.Tk()
root.title("Password Manager by Schimmel - alpha version")
root.geometry("700x400")

show_start_screen()

root.mainloop()