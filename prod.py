import cv2
import numpy as np
import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import threading

# Import AES-related libraries
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import base64
import os

# ---------------- AES ENCRYPTION / DECRYPTION FUNCTIONS ----------------
def encrypt_message_aes(message, key):
    """
    Encrypts a plaintext message using AES-256 (CBC mode).
    A key is derived from the provided string via SHA-256.
    Returns the base64 encoded string of IV+ciphertext.
    """
    key_bytes = hashlib.sha256(key.encode()).digest()  # 32 bytes for AES-256
    cipher = AES.new(key_bytes, AES.MODE_CBC)  # Generates a random IV automatically
    iv = cipher.iv
    padded_message = pad(message.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_message)
    encrypted = iv + ciphertext  # Prepend IV to ciphertext
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_message_aes(encrypted_message, key):
    """
    Decrypts a base64 encoded string that contains IV+ciphertext.
    Returns the original plaintext message.
    """
    try:
        key_bytes = hashlib.sha256(key.encode()).digest()
        encrypted_bytes = base64.b64decode(encrypted_message)
        iv = encrypted_bytes[:AES.block_size]
        ciphertext = encrypted_bytes[AES.block_size:]
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        padded_message = cipher.decrypt(ciphertext)
        message = unpad(padded_message, AES.block_size)
        return message.decode('utf-8')
    except Exception as e:
        messagebox.showerror("Error", "Decryption failed! Check your key.")
        return ""

# ---------------- MAIN WINDOW & GLOBALS ----------------
root = ttk.Window(themename="superhero")  # Default Light Theme
root.title("Steganography Tool")
root.geometry("550x780")
root.resizable(False, False)

is_dark_mode = False  # Track the theme state
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
        update_char_limit()  # Update the max character count when a file is selected

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
def encode_image(image_path, message, output_path, key):
    """Encodes a message into an image using LSB steganography with AES encryption."""
    img = cv2.imread(image_path)
    if img is None:
        messagebox.showerror("Error", "Could not open the image!")
        return

    # Encrypt the message using AES-256 with the provided key
    message = encrypt_message_aes(message, key)
    # Append end marker (note: base64 encoding does not include '#' so this marker is safe)
    message += '####'
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
    """Extracts a hidden message from an image using LSB steganography."""
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
        byte = binary_msg[i:i+8]
        if len(byte) < 8:
            break
        char = chr(int(byte, 2))
        # Check for our end marker "####"
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

    encryption_key = entry_key_encode.get()
    if not encryption_key:
        messagebox.showwarning("Warning", "Please enter an encryption key!")
        return

    progress_bar["value"] = 0
    threading.Thread(target=encode_image, args=(selected_file, message, "encoded_image.png", encryption_key), daemon=True).start()

def decode_message():
    """Handles decoding with threading to prevent UI freezing."""
    if not selected_file:
        messagebox.showwarning("Warning", "Please select an image file first!")
        return

    progress_bar["value"] = 0

    def run_decoding():
        hidden_text = decode_image(selected_file)
        decryption_key = entry_key_decode.get()
        if decryption_key:
            hidden_text = decrypt_message_aes(hidden_text, decryption_key)
        else:
            messagebox.showwarning("Warning", "Please enter a decryption key!")
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

ttk.Label(encode_frame, text="Encryption Key:").pack(pady=(10, 0))
entry_key_encode = ttk.Entry(encode_frame, width=30, show="*")
entry_key_encode.pack(pady=5)

ttk.Button(encode_frame, text="Encode & Save", command=encode_message, bootstyle="success").pack(pady=5)

# Decode Section
decode_frame = ttk.Labelframe(root, text="Decode Message", padding=10)
decode_frame.pack(pady=10, padx=10, fill="both")

ttk.Label(decode_frame, text="Decryption Key:").pack(pady=(0, 5))
entry_key_decode = ttk.Entry(decode_frame, width=30, show="*")
entry_key_decode.pack(pady=5)

# Moved Decode button below the decryption key input
ttk.Button(decode_frame, text="Decode", command=decode_message, bootstyle="warning").pack(pady=10)

ttk.Label(decode_frame, text="Decoded Message:").pack()
text_decoded = tk.Text(decode_frame, height=4, width=60, state=tk.DISABLED)
text_decoded.pack(pady=5)

ttk.Button(decode_frame, text="Copy to Clipboard", command=copy_to_clipboard, bootstyle="secondary").pack(pady=5)

# Progress Bar
progress_bar = ttk.Progressbar(root, mode="determinate", length=400)
progress_bar.pack(pady=10)

# Run the application
root.mainloop()
