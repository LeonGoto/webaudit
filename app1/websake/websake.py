# -*- coding: utf-8 -*-
import os
import sys
import codecs
import subprocess
from .fpdf import FPDF

def func_main(security_conf_file,env_file,apache2_cf_file):

    __author__ = "Leon Goto <reingart@gmail.com>"
    __copyright__ = "Copyright (C) 2010 Mariano Reingart"
    __license__ = "LG"


    #Vizualisation


    #ouverture du fichier de configuration sécurité 

    #security_conf_file = open("security.conf", "r+")
    #env_file = open("envvars", "r+")
    #apache2_cf_file = open("apache2.conf", "r+")

    security_conf="security.conf"
    apache2_conf="apache2.conf"

    ServerTokens_OS = ""
    ServerSignature = ""
    Trace_enable = ""
    xframe_option = ""
    xss_option = ""
    envvars_option=""
    choix = ""
    msg_timeout = ""

    # Verification du fichier de configuration de sécurité apache2 (security.conf)

    server_token_list = ["ServerTokens OS","ServerTokens Full","ServerTokens Minimal","ServerTokens Minor","ServerTokens Prod"] #liste des options de tokens serveur
    server_signature_list = ["ServerSignature On","ServerSignature Off","ServerSignature Email"] #liste des options serversignature
    trace_enable_list = ["TraceEnable On","TraceEnable Off","TraceEnable extended"] #liste des options trace_enbale
    xframe_option_list = ["Header set X-Frame-Options: \"sameorigin\"","Header set X-Frame-Options: \"deny\""]
    xss_list = ["Header set X-XSS-Protection \"1; mode=block\","]
    a2_list ="" 

    # Vérification des fichiers de configuration envvars apache2 

    envvars_list = ["APACHE_RUN_USER=www-data","APACHE_RUN_GROUP=www-data"]

    print_list_to_send = []

    print("________________Scan de fichiers de configurations en cours________________\n")
    print_list_to_send.append("________________Scan de fichiers de configurations en cours________________\n")

    # Checking apache2.conf and security.conf file

    for line in security_conf_file: 
        
        for option in server_token_list:
            if line.find(option) != -1 and line[line.find(option)-1] != "#":
                ServerTokens_OS = server_token_list.index(option)
            else:
                msg_token="Flag ServerTokens non présent ou désactivé"
                
                
        for option in server_signature_list:
            
            if line.find(option) != -1 and line[line.find(option)-1] != "#":
                ServerSignature = server_signature_list.index(option)
                
            else:
                msg_sig="Flag ServerSignature non présent ou désactivé "
                
                
                
        for option in trace_enable_list:
            
            if line.find(option) != -1 and line[line.find(option)-1] != "#":
                Trace_enable = trace_enable_list.index(option)
                
            else:
                msg_trace="Flag TraceEnable non présent ou désactivé"

                
                
        for option in xframe_option_list:
            
            if line.find(option) != -1 and line[line.find(option)-1] != "#": 
                xframe_option = xframe_option_list.index(option)
                
            else: 
                msg_xframe="Le Module xframe de protection clicjacking est non présent ou désactivé"
        
                
                        
        for option in xss_list:
            
            if line.find(option) != -1 and line[line.find(option)-1] != "#":
                xss_option = xss_list.index(option)
                print("OK: module de protection xss activé")
                print_list_to_send.append("OK: module de protection xss activé")
            
            else: 
                msg_xss ="KO : Le module de protection xss non trouvé ou désactivé"
                msg_xss_number=0


                
    msg_envvar="www-data n'est pas l'utilisateur par defaut, veuillez vous assurer d'utiliser un utilisateur à faible privilège \n"
    msg_envvar1="www-data n'est pas le groupe par defaut, veuillez vous assurer d'utiliser un utilisateur et un groupe à faible privilège \n"
        
    for line in env_file:
        #m = re.search('(APACHE_RUN_USER=)(.+)', 
    
        if line.find(envvars_list[0]) != -1 and line[line.find(envvars_list[0])-1] != "#": 
            msg_envvar="OK: l'utilisateur apache est www-data \n"
            
        if line.find(envvars_list[1]) != -1 and line[line.find(envvars_list[1])-1] != "#":
            msg_envvar1="OK: le groupe apache est www-data \n"
            
    print(msg_envvar)
    print_list_to_send.append(msg_envvar)
    print(msg_envvar1)
    print_list_to_send.append(msg_envvar1)


    for line in apache2_cf_file: 
        
        if line.find("Timeout 300") != -1 and line[line.find("Timeout 300")-1] != "#":
            print("Timeout par défaut trouvez, vous devez modifier cette valeur \n")
            print_list_to_send.append("Timeout par défaut trouvez, vous devez modifier cette valeur \n")
            msg_timeout="Timeout par défaut trouvez, vous devez modifier cette valeur"
            timeout = 0
        else: 
            timeout = 1
            
            


            
    #Récurpération de l'état du flags ServerToken et sauvegarde des méssages dans une variable pour pour afficher sur un rapport

    if (ServerTokens_OS == 0):
        msg_token="KO: le flag ServerToken est à OS \n"
        msg_token_advice0= "Pour la securité du serveur, nous recommandons que le flag ServerToken_OS soit à Prod \n"
        print(msg_token)
        print_list_to_send.append(msg_token)
        print(msg_token_advice0)
        print_list_to_send.append(msg_token_advice0)
        
    if (ServerTokens_OS == 1): 
        msg_token="KO: le flag ServerToken est à Full \n"
        msg_token_advice1="Pour la securité du serveur, nous recommandons que le flag ServerToken_OS soit à Prod \n"
        print(msg_token)
        print_list_to_send.append(msg_token)
        print(msg_token_advice1)
        print_list_to_send.append(msg_token_advice1)
        
    if (ServerTokens_OS == 2):
        msg_token="KO: le flag ServerToken est à Minimal \n"
        msg_token_advice2="Pour la securité du serveur, nous recommandons que le flag ServerToken_OS soit à Prod \n"
        print(msg_token)
        print_list_to_send.append(msg_token)
        print(msg_token_advice2)
        print_list_to_send.append(msg_token_advice2)
        
    if (ServerTokens_OS == 3):
        msg_token="KO: le flag ServerToken est à Minor \n"
        msg_token_advice3="Pour la securité du serveur, nous recommandons que le flag ServerToken_OS soit à Prod \n"
        print(msg_token)
        print_list_to_send.append(msg_token)
        print(msg_token_advice3)
        print_list_to_send.append(msg_token_advice3)
        
    if (ServerTokens_OS == 4):
        msg_token="OK: le flag ServerToken est à Prod \n"
        msg_token_advice4=""
        print(msg_token)
        print_list_to_send.append(msg_token)
        print(msg_token_advice4)
        print_list_to_send.append(msg_token_advice4)
        
    #Récurpération de l'état du flags ServerSignature et sauvegarde des méssages dans une variable pour pour afficher sur un rapport


    if (ServerSignature == 0):
        msg_sig="KO: le flag ServerSignature est à ON \n"
        msg_sig0_advice0= "Pour la sécurité du serveur, nous recommandons que le flag ServerSignature soit à Off \n"
        print(msg_sig)
        print_list_to_send.append(msg_sig)
        print(msg_sig0_advice0)
        print_list_to_send.append(msg_sig0_advice0)
        
    if (ServerSignature == 1): 
        msg_sig="OK: le flag ServerSignature est à Off \n"
        msg_sig1_advice0=""
        print(msg_sig)
        print_list_to_send.append(msg_sig)
        
    if (ServerSignature == 2):
        msg_sig="KO: le flag ServerSignature est à Email \n"
        msg_sig2_advice0="Pour la sécurité du serveur, nous recommandons que le flag ServerSignature soit à Off \n"
        print(msg_sig)
        print_list_to_send.append(msg_sig)
        print(msg_sig2_advice0)
        print_list_to_send.append(msg_sig2_advice0)

    #Récurpération de l'état du flags TraceEnable et sauvegarde des méssages dans une variable pour pour afficher sur un rapport

    if (Trace_enable == 0):
        msg_trace="KO: le flag TraceEnable est à ON \n"
        msg_trace_advice0= "Pour la sécurité du serveur, nous recommandons que le flag TraceEnable soit à Off \n"
        print(msg_trace)
        print_list_to_send.append(msg_trace)
        print(msg_trace_advice0)
        print_list_to_send.append(msg_trace_advice0)
        
    if (Trace_enable == 1): 
        msg_trace="OK: le flag TraceEnable est à Off \n"
        msg_trace1_advice0=""
        print(msg_trace)
        print_list_to_send.append(msg_trace)
        
    if (Trace_enable == 2):
        msg_trace="KO: le flag TraceEnable est à extended \n"
        msg_trace2_advice0="Pour la sécurité du serveur, nous recommandons que le flag TraceEnable soit à Off \n"
        print(msg_trace)
        print_list_to_send.append(msg_trace)
        print(msg_trace2_advice0)
        print_list_to_send.append(msg_trace2_advice0)
        

    #Récurpération de l'état du des autres flags

        
    if (xframe_option == 0):
        msg_xframe= "OK: mode de protection xframe: Sameorigine trouvé, protection clicjacking activé \n"
        print(msg_xframe)
        print_list_to_send.append(msg_xframe)
        
    if (xframe_option == 1):
        msg_xframe="OK: En-tête xframe: deby trouvé, protection clicjacking activé \n"
        print(msg_xframe)
        print_list_to_send.append(msg_xframe)

    if (xss_option == 0):
        msg_xss="OK: le module xss est présent, le mode block est activé \n"
        print(msg_xss)
        print_list_to_send.append(msg_xss)
        


    def hardening():

        rapport = FPDF()
        rapport.add_page('P', 'A4')
        rapport.set_font('Arial', 'B', 12)
        rapport.set_top_margin(10)
        rapport.set_left_margin(10)
        rapport.set_right_margin(10)
        
        
        
        if (ServerTokens_OS != 4 or ServerSignature != 1 or Trace_enable != 1): 
                
            #os.system('cp %s %s.bk'%(security_conf,security_conf))
            #os.system('cp %s %s.bk'%(apache2_conf,apache2_conf))
                #os.system('cp ' +str(security_conf) + ' ' +str(security_conf) + '.bk')
                
            if (ServerTokens_OS != 4):             
                    
                print("Correction : flag ServerTokens Passé à Prod \n")
                print_list_to_send.append("Correction : flag ServerTokens Passé à Prod \n")
                    
                if (ServerTokens_OS == 0):
                    os.system('sed -i -e \'s/ServerTokens OS/ServerTokens Prod/\' %s'%(security_conf))
                    rapport.text(12, 35, msg_token)
                    rapport.text(12, 40, msg_token_advice0)
                    rapport.text(12, 45, "Correction: flag ServerTokens passé à Prod")
                        
                if (ServerTokens_OS == 1):
                    os.system('sed -i -e \'s/ServerTokens Full/ServerTokens Prod/\' %s'%(security_conf))
                    rapport.text(12, 50, msg_token)
                    rapport.text(12, 55, msg_token_advice1)
                        
                if (ServerTokens_OS == 2):
                    os.system('sed -i -e \'s/ServerTokens Minimal/ServerTokens Prod/\' %s'%(security_conf))
                    rapport.text(12, 60, msg_token)
                    rapport.text(12, 65, msg_token_advice2)
                        
                if (ServerTokens_OS == 3):
                    os.system('sed -i -e \'s/ServerTokens Minor/ServerTokens Prod/\' %s'%(security_conf))
                    rapport.text(12, 70, msg_token)
                    rapport.text(12, 75, msg_token_advice3)
                
                    rapport.text(12, 80, msg_token)
                    
            else: 
                
                rapport.text(12, 85, msg_token)
                
                    
                    
            if (ServerSignature != 1):
                
                print("Correction : flag ServerSignature passé à Off \n")
                print_list_to_send.append("Correction : flag ServerSignature passé à Off \n")
                    
                if (ServerSignature ==  0):
                    os.system('sed -i -e \'s/ServerSignature On/ServerSignature Off/\' %s'%(security_conf))
                    rapport.text(12, 90, msg_sig)
                    rapport.text(12, 95, msg_sig0_advice0)
                    rapport.text(12, 100, "Correction: flag ServerSignature passé à Off")
                    
                if (ServerSignature == 2):
                    os.system('sed -i -e \'s/ServerSignature Email/ServerSignature Off/\' %s'%(security_conf))
                    rapport.text(12, 105, msg_sig) 
                    rapport.text(12, 110, msg_sig2_advice0)
                    rapport.text(12, 115, "Correction: flag Trace_enable passé à Off")
                    
            else: 
                    
                rapport.text(12, 120, msg_sig)
                rapport.text(12, 125, "Correction: Aucune modification apportée")
                
            if (Trace_enable != 1): 
                    
                print ("Correction : flag Trace_enable passé à Off \n ")
                print_list_to_send.append("Correction : flag Trace_enable passé à Off \n ")
                
                if (Trace_enable == 0): 
                    os.system('sed -i -e \'s/TraceEnable On/TraceEnable Off/\' %s'%(security_conf))
                    rapport.text(12, 130, msg_trace)
                    rapport.text(12, 135, msg_trace_advice0)
                    rapport.text(12, 140, "Correction: Flag Trace_enable passé à Off")
                        
                if (Trace_enable == 2): 
                    os.system('sed -i -e \'s/TraceEnable extended/TraceEnable Off/\' %s'%(security_conf))
                    rapport.text(12, 145, msg_trace)
                    rapport.text(12, 150, msg_trace2_advice0)
                    rapport.text(12, 155, "Correction: Flag Trace_enable passé à Off")
                        
            else: 
                    
                rapport.text(12, 160, msg_trace)
                rapport.text(12, 165, "Correction: aucune modification apportée")
                    
                rapport.text(12, 170, msg_xframe)
                rapport.text(12, 175, msg_xss)
                rapport.text(12, 180, msg_timeout)
                    
            print("Génération du rapport de scan effectuée \n")
            print_list_to_send.append("Génération du rapport de scan effectuée \n")
            print("Une copie de votre configuration a bien été effectuée dans le dossier courant \n")
            print_list_to_send.append("Une copie de votre configuration a bien été effectuée dans le dossier courant \n")
        
    ''' 
            else: 
                
        
                if (ServerTokens_OS != 4):             
                    
                    
                    if (ServerTokens_OS == 0):
                        rapport.text(12, 35, msg_token)
                        rapport.text(12, 40, msg_token_advice0)
                        
                    if (ServerTokens_OS == 1):
                        rapport.text(12, 50, msg_token)
                        rapport.text(12, 55, msg_token_advice1)
                        
                    if (ServerTokens_OS == 2):
                        rapport.text(12, 60, msg_token)
                        rapport.text(12, 65, msg_token_advice2)
                        
                    if (ServerTokens_OS == 3):
                        rapport.text(12, 70, msg_token)
                        rappsort.text(12, 75, msg_token_advice3)
                    
                    rapport.text(12, 80, msg_token)
                
                else: 
                    rapport.text(12, 85, "")
                    
                    
                if (ServerSignature != 1):
                    
                    
                    if (ServerSignature ==  0):
                        rapport.text(12, 90, msg_sig)
                        rapport.text(12, 95, msg_sig0_advice0)
                    
                    
                    if (ServerSignature == 2):
                        rapport.text(12, 105, msg_sig) 
                        rapport.text(12, 110, msg_sig2_advice0)
                        
                    
                else: 
                    rapport.text(12, 120, msg_sig)
                    
                
                if (Trace_enable != 1): 
                    
                    
                    if (Trace_enable == 0): 
                        rapport.text(12, 130, msg_trace)
                        rapport.text(12, 135, msg_trace_advice0)
                        
                    if (Trace_enable == 2): 
                        rapport.text(12, 145, msg_trace)
                        rapport.text(12, 150, msg_trace2_advice0)
                        
                else: 
                    rapport.text(12, 160, msg_trace)
                
                rapport.text(12, 170, msg_xframe)
                rapport.text(12, 175, msg_xss)
                rapport.text(12, 180, msg_timeout)
                print("Génération du rapport de scan effectuée \n")
                print("Aucune modification n'a été apportée à vos fichiers de configuration \n")
                
            
        rapport.output('scan_report.pdf', 'F')
                
            
    hardening()
    '''

    return print_list_to_send       
