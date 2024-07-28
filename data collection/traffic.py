import os
from ftplib import FTP
import random
import time

def send_ping(address):
    i = random.randint(0,7)
    n = random.randint(2,5)
    response = os.system(f"ping -c {n} {address[i]}")
    if response == 0:
        print(f"Ping response from {address[i]}")
    else:
        print(f"No response from {address[i]}")

def ftpsession():
    ftp_host = '10.0.0.4'
    ftp_port = 21
    ftp_username = 'anis'
    ftp_password = '2906'

    ftp = FTP()
    ftp.connect(ftp_host, ftp_port)
    ftp.login(user=ftp_username, passwd=ftp_password)

    for i in range (10):
        ftp.cwd('..')
        dossier = random.choice(['folder1', 'folder2'])

        dossier1 = ['folder1', 'folder2']
        dossier1.remove(dossier)
        dossier2 = dossier1[0]
        
        ftp.cwd(dossier)
        liste_fichiers = ftp.nlst()
        if liste_fichiers:
            fichier = random.choice(liste_fichiers)
        else:
            print(f"No files in {dossier}.")
            print("Exiting ...")
            ftp.quit()
            exit()

        oper = random.randint(0, 3)     # Operations=[opload, download, Rename, delete]
        
        if oper == 0:
            print(f"Operation {i+1} is: UPLOAD")
            fold = '/home/mini/ftp_upload'
            if not os.path.exists(fold):
                os.makedirs(fold)
            file_path = os.path.join(fold, fichier)
            with open(file_path, 'wb') as file:
                ftp.retrbinary('RETR ' + fichier, file.write)

            ftp.cwd('..')
            ftp.cwd(dossier2) 
            with open(file_path, 'rb') as file:
                ftp.storbinary('STOR ' + fichier, file)
            print(f"{fichier} is uploaded to FTP server in {dossier2}.")
        
        elif oper == 1:
            print(f"Operation {i+1} is: DOWNLOAD")
            fold = '/home/test/ftp_downl'
            if not os.path.exists(fold):
                os.makedirs(fold)
            file_path = os.path.join(fold, fichier)
            with open(file_path, 'wb') as file:
                ftp.retrbinary('RETR ' + fichier, file.write)
            print(f"{fichier} is DOWNLOADED from FTP server.")
        
        elif oper == 2:
            print(f"Operation {i+1} is: RENAME")
            if '.' in fichier:
                file_name, file_extension = fichier.rsplit('.', 1)
                new_name = file_name + "_renamed." + file_extension
                ftp.rename(fichier, new_name)
                print(f"{fichier} is RENAMED TO {new_name} on FTP server.")

        elif oper == 3:
            print(f"Operation {i+1} is: DELETE")
            ftp.delete(fichier)
            print(f"{fichier} is DELETED from FTP server.")
    ftp.quit()

def websession():
    import requests
    import random

    SERVER_ADDRESS = "http://10.0.0.2:80"
    req_pictures = requests.get(f"{SERVER_ADDRESS}/Pictures")

    if req_pictures.status_code == 200:
        print("You have accessed to Pictures")
    else:
        print("Unable to access to Pictures", req_pictures.status_code)

    img = random.choice(['1.jpg', '2.jpg', '3.jpg', '4.jpg', '5.jpg', '6.jpg','7.jpg', '8.jpg', '9.jpg', 'a.jpg', 'b.jpg', 'c.jpg'])
    print(f"Image choisie est: {img}")

    fold = '/home/mini/web_downl'

    if not os.path.exists(fold):
        os.makedirs(fold)

    image_url = f"{SERVER_ADDRESS}/Pictures/{img}"

    response = requests.get(image_url)
    if response.status_code == 200:
        with open(os.path.join(fold, img), 'wb') as f:
            f.write(response.content)
        print(f"{img} est telechargee avec succees.")
    else:
        print(f"erreur en telechargement de {img}.")


for j in range(40):
    print(); print(f"SESSION {j+1}: PING")
    add = ["10.0.0.1", "10.0.0.2", "10.0.0.3","10.0.0.4", "10.0.0.5", "10.0.0.6",
                "10.0.0.7", "10.0.0.9"]
    send_ping(add)

    print(); print(f"SESSION {j+1}: FTP")
    ftpsession()

    print(); print(f"SESSION {j+1}: WEB")
    websession()
    
    time.sleep(random.randint(4,20))
