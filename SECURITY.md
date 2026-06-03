# Politique de sécurité

## Modèle de confiance

Email Manager est une application **100 % locale** :

- elle s'exécute sur `127.0.0.1` et ne communique qu'avec **tes** fournisseurs
  de mail (IMAP/SMTP/OAuth) ;
- les comptes, identifiants et le cache des messages restent dans le dossier
  `data/`, **exclu du dépôt git** ;
- les identifiants (mots de passe d'application, jetons OAuth) sont stockés dans
  le gestionnaire d'identifiants du système (Windows Credential Manager /
  Keychain) lorsqu'il est disponible, sinon localement dans `data/accounts.json`.

> Ne partage jamais ton dossier `data/` : il peut contenir des jetons d'accès
> en clair selon ta plateforme.

## Bonnes pratiques

- Utilise un **mot de passe d'application** dédié (jamais ton mot de passe
  principal) et révoque-le si besoin chez ton fournisseur.
- Pour Outlook, l'authentification se fait par **OAuth** (aucun mot de passe
  stocké) ; tu peux révoquer l'accès dans les paramètres de sécurité Microsoft.
- Les actions de suppression/désabonnement de masse sont puissantes : configure
  la liste des **expéditeurs protégés** avant tout nettoyage.

## Signaler une vulnérabilité

Merci de **ne pas** ouvrir d'issue publique pour une faille de sécurité.
Utilise l'onglet **Security → Report a vulnerability** du dépôt GitHub, ou
ouvre une issue générique demandant un contact privé. Indique :

- une description du problème et son impact ;
- les étapes de reproduction (sans données personnelles réelles).

Nous nous efforcerons de répondre dans les meilleurs délais.
