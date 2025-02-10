import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
import base64
import hashlib
from cryptography.fernet import Fernet

def generar_clave(password):
    key = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(key[:32])

def encriptar_mensaje(mensaje, password):
    clave = generar_clave(password)
    f = Fernet(clave)
    return f.encrypt(mensaje.encode())

def desencriptar_mensaje(mensaje_encriptado, password):
    clave = generar_clave(password)
    f = Fernet(clave)
    return f.decrypt(mensaje_encriptado)

def guardar_archivo(mensaje_encriptado):
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "wb") as file:
            file.write(mensaje_encriptado)

def cargar_archivo():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "rb") as file:
            return file.read()
    return None

def encriptar():
    mensaje = mensaje_entry.get("1.0", tk.END).strip()
    password = password_entry.get().strip()
    if mensaje and password:
        mensaje_encriptado = encriptar_mensaje(mensaje, password)
        guardar_archivo(mensaje_encriptado)
        messagebox.showinfo("Éxito", "Mensaje encriptado y guardado con éxito.")
    else:
        messagebox.showwarning("Advertencia", "Debe ingresar un mensaje y una contraseña.")

def desencriptar():
    password = password_entry.get().strip()
    if password:
        mensaje_encriptado = cargar_archivo()
        if mensaje_encriptado:
            try:
                mensaje_desencriptado = desencriptar_mensaje(mensaje_encriptado, password)
                mensaje_entry.delete("1.0", tk.END)
                mensaje_entry.insert(tk.END, mensaje_desencriptado.decode())
                messagebox.showinfo("Éxito", "Mensaje desencriptado con éxito.")
            except Exception as e:
                messagebox.showerror("Error", "Contraseña incorrecta o archivo inválido.")
        else:
            messagebox.showwarning("Advertencia", "Debe seleccionar un archivo.")
    else:
        messagebox.showwarning("Advertencia", "Debe ingresar una contraseña.")

# Crear la interfaz gráfica
root = tk.Tk()
root.title("Herramienta de Encriptación y Desencriptación")

frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

mensaje_label = tk.Label(frame, text="Mensaje:")
mensaje_label.grid(row=0, column=0, sticky=tk.W)

mensaje_entry = tk.Text(frame, height=10, width=50)
mensaje_entry.grid(row=1, column=0, columnspan=2, pady=5)

password_label = tk.Label(frame, text="Contraseña:")
password_label.grid(row=2, column=0, sticky=tk.W)

password_entry = tk.Entry(frame, show="*", width=50)
password_entry.grid(row=3, column=0, columnspan=2, pady=5)

encriptar_button = tk.Button(frame, text="Encriptar", command=encriptar)
encriptar_button.grid(row=4, column=0, pady=5)

desencriptar_button = tk.Button(frame, text="Desencriptar", command=desencriptar)
desencriptar_button.grid(row=4, column=1, pady=5)

root.mainloop()
