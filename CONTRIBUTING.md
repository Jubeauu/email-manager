# Contribuer à Email Manager

Merci de l'intérêt que tu portes au projet ! Les contributions sont les bienvenues.

## 🐛 Signaler un bug / proposer une idée

Ouvre une [issue](https://github.com/Jubeauu/email-manager/issues) en décrivant :
- ce que tu attendais et ce qu'il s'est passé ;
- les étapes pour reproduire ;
- ton OS, ta version de Python et ton fournisseur de mail (sans données perso !).

> ⚠️ **Ne colle jamais** d'adresse e-mail réelle, de mot de passe, de jeton ou
> de capture non floutée dans une issue.

## 🛠 Développement

```bash
git clone https://github.com/Jubeauu/email-manager.git
cd email-manager
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt   # Windows
# .venv/bin/pip install -r requirements.txt      # Linux/macOS
cd backend && python -m uvicorn main:app --reload --port 8000
```

### Organisation du code

- `backend/` — API FastAPI + logique métier (un module par responsabilité :
  `imap_client`, `oauth_ms`, `smtp_client`, `phishing`, `categorize`, `rules`,
  `scheduler`, `db`, `unsubscribe`).
- `frontend/` — interface en HTML/CSS/JS natif, servie par FastAPI (aucun build).
- `data/` — données locales générées à l'exécution, **ignorées par git**.

### Conventions

- Python : style PEP 8, commentaires et messages utilisateur en français.
- Garde les modules ciblés et testables ; pas de dépendance lourde sans raison.
- Vérifie qu'un `import` du backend passe avant d'ouvrir une PR :
  `python -c "import main"` depuis `backend/`.

## 🔀 Pull requests

1. Crée une branche (`git checkout -b feat/ma-fonctionnalite`).
2. Commits clairs et atomiques.
3. Décris le **pourquoi** dans la PR, pas seulement le **quoi**.
4. Aucune donnée personnelle dans le diff, les tests ou les captures.

## 💡 Pistes d'amélioration

- Connecteurs OAuth supplémentaires (Gmail/Google en OAuth natif).
- Améliorer la détection de phishing (listes de marques, homoglyphes).
- Tests automatisés, internationalisation, thème clair.

Merci ! 🙌
