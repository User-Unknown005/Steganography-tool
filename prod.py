import cv2
import numpy as np
import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as ttk  # Modern Theming
from ttkbootstrap.constants import *

def encode_image(image_path, message, output_path):
    """Encodes a message into an image using LSB steganography."""
    img = cv2.imread(image_path)
    if img is None:
        messagebox.showerror("Error", "Could not open the image!")
        return

    message += '####'  # End marker for decoding
    binary_msg = ''.join(format(ord(char), '08b') for char in message)

    index = 0
    for row in img:
        for pixel in row:
            for color in range(3):  # R, G, B channels
                if index < len(binary_msg):
                    pixel[color] = np.uint8((int(pixel[color]) & ~1) | int(binary_msg[index]))
                    index += 1

    cv2.imwrite(output_path, img)
    messagebox.showinfo("Success", f"Message hidden successfully in {output_path}")

def decode_image(image_path):
    """Extracts a hidden message from an image."""
    img = cv2.imread(image_path)
    if img is None:
        messagebox.showerror("Error", "Could not open the image!")
        return ""

    binary_msg = ""

    for row in img:
        for pixel in row:
            for color in range(3):  # R, G, B channels
                binary_msg += str(pixel[color] & 1)

    text = ""
    for i in range(0, len(binary_msg), 8):
        char = chr(int(binary_msg[i:i+8], 2))
        if char == '#' and text[-3:] == '###':
            return text[:-3]  # Stop at marker
        text += char

    return text

# ----------------- GUI Functions -----------------
def select_image_encode():
    file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
    entry_image_encode.delete(0, tk.END)
    entry_image_encode.insert(0, file_path)
    update_char_limit()

def select_image_decode():
    file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
    entry_image_decode.delete(0, tk.END)
    entry_image_decode.insert(0, file_path)

def encode_message():
    image_path = entry_image_encode.get()
    message = text_message.get("1.0", tk.END).strip()
    if not image_path or not message:
        messagebox.showwarning("Warning", "Please select an image and enter a message!")
        return
    encode_image(image_path, message, "encoded_image.png")

def decode_message():
    image_path = entry_image_decode.get()
    if not image_path:
        messagebox.showwarning("Warning", "Please select an image to decode!")
        return
    hidden_text = decode_image(image_path)
    text_decoded.config(state=tk.NORMAL)
    text_decoded.delete("1.0", tk.END)
    text_decoded.insert(tk.END, hidden_text)
    text_decoded.config(state=tk.DISABLED)

def copy_to_clipboard():
    """Copies the decoded message to clipboard."""
    root.clipboard_clear()
    root.clipboard_append(text_decoded.get("1.0", tk.END).strip())
    root.update()
    messagebox.showinfo("Copied", "Decoded message copied to clipboard!")

def update_char_limit():
    """Updates the character limit based on the selected image size."""
    image_path = entry_image_encode.get()
    if image_path:
        img = cv2.imread(image_path)
        if img is not None:
            max_chars = (img.shape[0] * img.shape[1] * 3) // 8  # Max characters that can be hidden
            char_limit_label.config(text=f"Max characters: {max_chars}")
        else:
            char_limit_label.config(text="Max characters: N/A")
    else:
        char_limit_label.config(text="Max characters: N/A")

# ----------------- Dark Mode Toggle -----------------
def toggle_theme():
    """Switches between Light and Dark mode dynamically."""
    global is_dark_mode
    if is_dark_mode:
        root.style.theme_use("superhero")  # Light Mode
        theme_toggle_btn.config(text="🌙 Dark Mode", bootstyle="dark")
    else:
        root.style.theme_use("darkly")  # Dark Mode
        theme_toggle_btn.config(text="☀️ Light Mode", bootstyle="light")
    is_dark_mode = not is_dark_mode

# ----------------- GUI Layout -----------------
root = ttk.Window(themename="superhero")  # Default Light Theme
root.title("Steganography Tool")
root.geometry("500x780")
root.resizable(False, False)

is_dark_mode = False  # Track the theme state

# Title Label
title_label = ttk.Label(root, text="Steganography Tool", font=("Arial", 18, "bold"), bootstyle="primary")
title_label.pack(pady=10)

# Dark Mode Toggle Button
theme_toggle_btn = ttk.Button(root, text="🌙 Dark Mode", command=toggle_theme, bootstyle="dark")
theme_toggle_btn.pack(pady=5)

# Encode Section
encode_frame = ttk.Labelframe(root, text="Encode Message", padding=10)
encode_frame.pack(pady=10, padx=10, fill="both")

frame_encode = ttk.Frame(encode_frame)
frame_encode.pack(pady=5)

entry_image_encode = ttk.Entry(frame_encode, width=40)
entry_image_encode.pack(side=tk.LEFT, padx=5)
ttk.Button(frame_encode, text="Browse", command=select_image_encode, bootstyle="info").pack(side=tk.RIGHT)

char_limit_label = ttk.Label(encode_frame, text="Max characters: N/A")
char_limit_label.pack()

ttk.Label(encode_frame, text="Enter Message:").pack()
text_message = tk.Text(encode_frame, height=4, width=50)
text_message.pack(pady=5)

ttk.Button(encode_frame, text="Encode & Save", command=encode_message, bootstyle="success").pack(pady=10)

# Decode Section
decode_frame = ttk.Labelframe(root, text="Decode Message", padding=10)
decode_frame.pack(pady=10, padx=10, fill="both")

frame_decode = ttk.Frame(decode_frame)
frame_decode.pack(pady=5)

entry_image_decode = ttk.Entry(frame_decode, width=40)
entry_image_decode.pack(side=tk.LEFT, padx=5)
ttk.Button(frame_decode, text="Browse", command=select_image_decode, bootstyle="info").pack(side=tk.RIGHT)

ttk.Button(decode_frame, text="Decode", command=decode_message, bootstyle="warning").pack(pady=10)

ttk.Label(decode_frame, text="Decoded Message:").pack()
text_decoded = tk.Text(decode_frame, height=4, width=50, state=tk.DISABLED)
text_decoded.pack(pady=5)

ttk.Button(decode_frame, text="Copy to Clipboard", command=copy_to_clipboard, bootstyle="secondary").pack(pady=5)

# Run the application
root.mainloop()
