import cv2
import numpy as np
import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import threading

root = ttk.Window(themename="superhero") 
root.title("Steganography Tool")
root.geometry("550x780")
root.resizable(False, False)

is_dark_mode = False 
selected_file = ""

# ---------------- PROGRESS BAR FUNCTION ----------------
def update_progress(value):
    progress_bar["value"] = value
    root.update_idletasks()

# ---------------- GUI FUNCTIONS ----------------
def select_file():
    """Opens a file dialog to select an image."""
    global selected_file
    file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")])
    if file_path:
        selected_file = file_path
        entry_file.delete(0, tk.END)
        entry_file.insert(0, file_path)
        update_char_limit()  

def copy_to_clipboard():
    """Copies the decoded message to clipboard."""
    root.clipboard_clear()
    root.clipboard_append(text_decoded.get("1.0", tk.END).strip())
    root.update()
    messagebox.showinfo("Copied", "Decoded message copied to clipboard!")

def toggle_theme():
    """Switches between Light and Dark mode dynamically."""
    global is_dark_mode
    if is_dark_mode:
        root.style.theme_use("superhero")
        theme_toggle_btn.config(text="🌙 Dark Mode", bootstyle="dark")
    else:
        root.style.theme_use("darkly")
        theme_toggle_btn.config(text="☀️ Light Mode", bootstyle="light")
    is_dark_mode = not is_dark_mode

def update_char_limit():
    """Updates the character limit based on the selected image size."""
    if selected_file:
        img = cv2.imread(selected_file)
        if img is not None:
            # Each pixel has 3 color channels and each character is 8 bits
            max_chars = (img.shape[0] * img.shape[1] * 3) // 8  
            max_char_label.config(text=f"Max characters: {max_chars}")
        else:
            max_char_label.config(text="Max characters: N/A (Image could not be read)")
    else:
        max_char_label.config(text="Max characters: N/A")

# ---------------- IMAGE STEGANOGRAPHY FUNCTIONS ----------------
def encode_image(image_path, message, output_path):
    """Encodes a message into an image using LSB steganography."""
    img = cv2.imread(image_path)
    if img is None:
        messagebox.showerror("Error", "Could not open the image!")
        return

    message += '####'  # End marker
    binary_msg = ''.join(format(ord(char), '08b') for char in message)

    total_pixels = img.shape[0] * img.shape[1] * 3
    step = max(1, total_pixels // 100)
    index = 0

    for row in img:
        for pixel in row:
            for color in range(3):
                if index < len(binary_msg):
                    pixel[color] = np.uint8((int(pixel[color]) & ~1) | int(binary_msg[index]))
                    index += 1
            if index % step == 0:
                update_progress((index / len(binary_msg)) * 100)
    
    cv2.imwrite(output_path, img)
    update_progress(100)
    messagebox.showinfo("Success", f"Message hidden successfully in {output_path}")

def decode_image(image_path):
    """Extracts a hidden message from an image."""
    img = cv2.imread(image_path)
    if img is None:
        messagebox.showerror("Error", "Could not open the image!")
        return ""

    binary_msg = ""
    total_pixels = img.shape[0] * img.shape[1] * 3
    step = max(1, total_pixels // 100)

    for row in img:
        for pixel in row:
            for color in range(3):
                binary_msg += str(pixel[color] & 1)
            if len(binary_msg) % step == 0:
                update_progress((len(binary_msg) / total_pixels) * 100)

    text = ""
    for i in range(0, len(binary_msg), 8):
        char = chr(int(binary_msg[i:i+8], 2))
        if char == '#' and text[-3:] == '###':
            update_progress(100)
            return text[:-3]
        text += char
    
    update_progress(100)
    return text

# ---------------- ENCODING & DECODING FUNCTIONS ----------------
def encode_message():
    """Handles encoding with threading to prevent UI freezing."""
    if not selected_file:
        messagebox.showwarning("Warning", "Please select an image file first!")
        return

    message = text_message.get("1.0", tk.END).strip()
    if not message:
        messagebox.showwarning("Warning", "Please enter a message to encode!")
        return

    progress_bar["value"] = 0
    threading.Thread(target=encode_image, args=(selected_file, message, "encoded_image.png"), daemon=True).start()

def decode_message():
    """Handles decoding with threading to prevent UI freezing."""
    if not selected_file:
        messagebox.showwarning("Warning", "Please select an image file first!")
        return

    progress_bar["value"] = 0

    def run_decoding():
        hidden_text = decode_image(selected_file)
        text_decoded.config(state=tk.NORMAL)
        text_decoded.delete("1.0", tk.END)
        text_decoded.insert(tk.END, hidden_text)
        text_decoded.config(state=tk.DISABLED)

    threading.Thread(target=run_decoding, daemon=True).start()

# ---------------- GUI LAYOUT ----------------
title_label = ttk.Label(root, text="Steganography Tool", font=("Arial", 18, "bold"), bootstyle="primary")
title_label.pack(pady=10)

# Dark Mode Toggle Button
theme_toggle_btn = ttk.Button(root, text="🌙 Dark Mode", command=toggle_theme, bootstyle="dark")
theme_toggle_btn.pack(pady=5)

# File Selection Section
ttk.Label(root, text="Enter the host image file (Supported: .png, .jpg, .jpeg, .bmp)").pack(pady=5)
frame_file = ttk.Frame(root)
frame_file.pack(pady=5)

entry_file = ttk.Entry(frame_file, width=50)
entry_file.pack(side=tk.LEFT, padx=5)
ttk.Button(frame_file, text="Browse", command=select_file, bootstyle="info").pack(side=tk.RIGHT)

# Encode Section
encode_frame = ttk.Labelframe(root, text="Encode Message", padding=10)
encode_frame.pack(pady=10, padx=10, fill="both")

# Max character count label just above the message input area
max_char_label = ttk.Label(encode_frame, text="Max characters: N/A")
max_char_label.pack(pady=5)

ttk.Label(encode_frame, text="Enter Message:").pack()
text_message = tk.Text(encode_frame, height=4, width=60)
text_message.pack(pady=5)

ttk.Button(encode_frame, text="Encode & Save", command=encode_message, bootstyle="success").pack(pady=5)

# Decode Section
decode_frame = ttk.Labelframe(root, text="Decode Message", padding=10)
decode_frame.pack(pady=10, padx=10, fill="both")

ttk.Button(decode_frame, text="Decode", command=decode_message, bootstyle="warning").pack(pady=10)

ttk.Label(decode_frame, text="Decoded Message:").pack()
text_decoded = tk.Text(decode_frame, height=4, width=60, state=tk.DISABLED)
text_decoded.pack(pady=5)

ttk.Button(decode_frame, text="Copy to Clipboard", command=copy_to_clipboard, bootstyle="secondary").pack(pady=5)

# Progress Bar
progress_bar = ttk.Progressbar(root, mode="determinate", length=400)
progress_bar.pack(pady=10)


root.mainloop()
