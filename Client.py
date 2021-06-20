#!/usr/bin/python3

import os,socket
import random
import subprocess
import re

#Partie 1: Protocole de sécurité

random.seed()

#Définir la constante E qui représente l'exposant du Client (Alice), (e_A) = 65537
E = 65537

#Déclaration des fonctions qu'on utilise pour le protocole de chiffrement/déchiffrement des message.

#Création de la clé publique 
#Choisir Pc et Qc deux nombres premiers tels que Nc = Pc*Qc où (Nc,Ec) représente la clé publique du Client.
#Définir une fonction qui génère des nombres premiers aléatoirement choisis depuis un intervalle définit.
def GeneratePrimeNumber():
    L= [i for i in range(257,1000)]
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
#Calcule de Dc l'invers de E modulo Phi(Nc)=(Pc-1)(Qc-1) où (Nc,Dc) représente la clé privée du Client.
#Définir une fonction qui calcule l'Algorithme d'Euclide Etendu
def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y
#Définir une fonction qui vérifie retourne l'inverse modulaire
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
#------------------------------------------------------------------------------------------------------------------------

#Calcule des objets nécéssaire pour le protocole de sécurité RSA

#Générer Pc et Qc distincts
Pc = GeneratePrimeNumber()
while 1:
    Qc = GeneratePrimeNumber()
    if(Pc != Qc) :
        break


#Calcule du module du Client Nc = Pc*Qc
Nc = int(Pc) * int(Qc)

#Calcule de Phi(Nc) = (Pc-1)(Qc-1)
Phi_Nc = (int(Pc)-1) * (int(Qc)-1)

#Calcule de l'exposant secret Dc = E^(-1) mod Phi(Nc)
Dc = modinv(E,Phi_Nc)

#------------------------------------------------------------------------------------------------------------------------

#Partie 2: Programmation d'un Client en TCP

#Etablire une connexion avec le Serveur

#Création d'une socket pour permettre la communication TCP
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#Indiquer l'adresse IP et port de communication avec le Serveur
tsap_serveur = ('127.0.0.1',8790)

#Demander au Serveur d'établire une connexion
s.connect(tsap_serveur)

pid = os.fork() #Scinder le processus courant en deux avec la création d’un nouveau processus (l’un est désigné comme étant le père et l’autre, le fils)

if not pid:
    # je suis l'enfant

    #Récupérer le module publique Ns du Serveur depuis le fichier "Annuaire.txt"
	file = open("Annuaire.txt","r")  
	Ns = file.read() 
	file.close
	
    #Communication: Client =======>> Serveur
	while 1:
        #Saisie du message du Client
		entree_clavier = input('**')
		if not entree_clavier:
			break
        
        #Procéssus de chiffrement des messages envoyés par le Client:

        #Initialisation d'une liste qui va contenir les valeur du message déchiffré
		chiffrement = []

        #Parcourir la chaîne de caractère qui contient le message du Client et effectuer le chiffrement par la clé publique (Ns,Es) du Serveur en utilisant la fonction "lpowmod"
		for ch in entree_clavier: 
			chiffrement.append(lpowmod(ord(ch),E,int(Ns)))#La fonction lpowmod prend en entrée l'ordre de cahque caractère ainsi que l'exposant E et la valeur entière du Ns récupérée de l'annuaire.
        
        #Affecter le résultat du chiffrement dans la chaîne de caractère "msg"
		msg = str(chiffrement).strip('[]')

        #Transmettre le message chiffré du Client au Serveur
		s.sendall(bytes(msg,'utf-8'))
else:
    # je suis le père
    #Communication: Serveur  =======>>  Client

    #Transmettre le module publique Nc du Client au Serveur
	s.sendall(bytes(str(Nc),'utf-8'))

	while 1:
        #Récuperer le message du Serveur
		ligne = s.recv(1024)
		if not ligne:
			break
        
        #Procéssus de déchiffrement du message reçu du Serveur:

        #Initialisation d'une chaîne de caractère qui va contenir le message déchiffré
		dechiffrement = ""

        #Passer d’une chaîne d’octets à une chaîne en UTF-8 avec la méthode decode()
		ligne = ligne.decode('utf-8')

        #Récupérer le message du Serveur sous forme d'une liste de chiffré dont on enlevera le caractère ',' avec la méthode split()
		msg = str(ligne).split(',')

        #Parcourir la liste "msg" et déchiffrer chaque élément à l'aide de la fonction "lpowmod" et la clé privé Dc du Client
		for ch in msg: 
			dechiffrement += chr(lpowmod(int(ch),Dc,Nc))

        #Afficher le message du Serveur aprés déchiffrement	
		print("Serveur: ",dechiffrement)

s.close()
