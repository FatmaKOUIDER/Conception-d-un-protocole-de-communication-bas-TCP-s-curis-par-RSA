#!/usr/bin/python3


import os,socket
import random
import subprocess
import re

#Partie 1: Protocole de sécurité RSA

random.seed()

#Définir la constante E qui représente l'exposant de Bob (e_B) = 65537
E = 65537

#Déclaration des fonctions qu'on utilise pour le protocole de chiffrement/déchiffrement des message

#Création de la clé publique 
#Choisir PB et QB deux nombres premiers tels que NB = PB*QB où (NB,EB) représente la clé publique de Bob
#Définir une fonction qui génère des nombres premiers aléatoirement choisis depuis un intervalle définit
def GeneratePrimeNumber():
    L = [i for i in range(257,1000)]
    while 1:

        #Choisir un nombre "num" aléatoirement depuis la liste L
        num = random.choice(L)

        #Vérifier si le nombre "num" est premier en utilisant la fonction "openssl"
        commande = "openssl prime "
        r  = subprocess.run(commande+str(num),shell=True,stdout=subprocess.PIPE) 
        resultat_openssl = r.stdout

        #Utiliser l'expression régulière ("is prime")
        regexp = re.compile(r'is prime')

        #Chercher la chaîne de caractère "is prime" dans la chaîne de caractère "resultat_openssl"
        #Si "is prime" est dans "resultat_openssl" on sort de la boucle "while"
        if regexp.search(str(resultat_openssl)):
            break
    return num

#Calcule de la clé privée:
#Calcule de Ds l'invers de E (l'exposant du Serveur) modulo Phi(Ns)=(Ps-1)(Qs-1) où (Ns,Ds) représente la clé privée du Serveur
#Définir une fonction qui calcule "l'inverse modulaire" (Algorithme d'Euclide Etendu)
def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y

#Définir une fonction qui vérifie que l'inverse modulaire existe et calcule cette inverse modulo Phi(Ns)
def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None
    return x % m

#Chiffrement/Déchiffrement des messages
#Definir une fonction qui calcule les puissances modulaire "Exponentation Rapide"
def lpowmod(x, y, n):
    """puissance modulaire: (x**y)%n avec x, y et n entiers"""
    result = 1
    while y>0:
        if y&1>0:
            result = (result*x)%n
        y >>= 1
        x = (x*x)%n
    return result
#----------------------------------------------------------------------------------------------------------------------

#Calcule des objets nécéssaires pour le protocole de sécurité

#Générer Ps et Qs
Ps = GeneratePrimeNumber()
while 1:
    Qs = GeneratePrimeNumber()
    if (Ps != Qs):
        break

#Calcule du module de Serveur Ns = Ps*Qs
Ns = int(Ps) * int(Qs)

#Calcule de Phi(Ns) = (Ps-1)(Qs-1)
Phi_Ns = (int(Ps)-1) * (int(Qs)-1)

#Calcule de l'exposant secret du Serveur Ds = E^(-1) mod Phi(Ns)
Ds = modinv(E,Phi_Ns)

#Enregistrement du module Ns dans un fichier à titre d'annuaire publique
Module = str(Ns)
try:
  f =  open("Annuaire.txt","w") 
except Exception as e:
  print(a.args)
  sys.exit(1)
f.write(Module)
f.close()

#------------------------------------------------------------------------------------------------------------------------

#Partie 2: Protocole TCP

#Création d'une socket pour permettre la communication TCP
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#Communacation sur le port numéro 8790
s.bind(('',8790))

#Attendre une connexion Client
s.listen(1)

#Accepter de communiquer avec le Client
connexion, tsap_client = s.accept() 


print(tsap_client)

pid = os.fork()

if not pid: 
    #Communication: Client =======>> Serveur
	while 1:
    
        #Lecture du message du Client
		ligne = connexion.recv(1024) 

        #Procéssus de déchiffrement du message du Client
        #initialisation d'une chaîne de caractère qui va contenir le message déchiffré
		dechiffrement = ""

        #Passer d’une chaîne d’octets à une chaîne en UTF-8 avec la méthode decode()
		ligne = ligne.decode('utf-8') 

        #Récupérer le message du Client sous forme d'une liste de chiffré dont on enlevera le caractère ',' avec la méthode split()
		msg = str(ligne).split(',')
        
        #Parcourir la liste "msg" et déchiffrer chaque élément à l'aide de la fonction "lpowmod" et la clé privée  Ds du Serveur
		for ch in msg: 
			dechiffrement += chr(lpowmod(int(ch),Ds,Ns))
        
        #Afficher le message du Client aprés déchiffrement
		print("Client: ",dechiffrement)
else:
    #Communication: Serveur =======>> Client

    #Récupérer la clé publique Nc du Client 
	Nc = connexion.recv(1024)
	Nc = Nc.decode("utf-8")
    
	while 1:
        #Saisie du message du Serveur
		saisie = input('->')

        #Initialisation d'une liste qui va contenir le message chiffré du Serveur
		chiffrement = []

        #Parcourir la chaîne de caractère qui contient le message du Serveur
        #Et chiffrer chaque caractère à l'aide de la fonction "lpowmod" et la clé publique du Client
		for ch in saisie: 
			chiffrement.append(lpowmod(ord(ch),E,int(Nc)))

        #Affecter le résultat dans une chaîne de caractère
		msg = str(chiffrement).strip('[]')

		#Transmettre le message chiffré du Serveur au Client
		connexion.sendall(bytes(msg,'utf-8'))
s.close()
