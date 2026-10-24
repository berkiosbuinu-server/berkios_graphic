# Déploiement initial sur VPS

1. Choisir un nom de domaine pour l'API, par exemple `api.votre-domaine.com`, et faire pointer son enregistrement DNS A/AAAA vers le VPS.
2. Installer Docker Engine et le plugin Docker Compose sur le VPS.
3. Copier le dossier `backend/` sur le serveur. Créer `backend/.env` depuis `.env.example` et définir `BERKIOS_CORS_ORIGINS` avec l'URL exacte du Studio (pas l'URL de l'API), ainsi qu'un `BERKIOS_SUPER_ADMIN_TOKEN` aléatoire de grande longueur.
4. Adapter `Caddyfile.example` avec le vrai domaine et installer Caddy pour terminer TLS. Le port `8787` ne doit pas être ouvert publiquement; le proxy HTTPS est le seul point d'entrée.
5. Lancer `docker compose up -d --build` depuis `backend/`. Vérifier `https://api.votre-domaine.com/api/health`.
6. Dans BERKIOS Studio, ouvrir **Profil**, saisir l'URL HTTPS de l'API puis se connecter ou créer un compte.
7. Sauvegarder régulièrement le volume Docker `berkios_accounts`; tester la restauration avant de traiter des paiements réels.

Le endpoint de super_admin ne doit être utilisé que depuis un outil d'administration de confiance. Ne distribuez jamais le secret d'administration dans le Studio, BERKIOS Code ou les applications générées.

## Limites de cette première étape

Cette version reste une base d’intégration et de test, pas une certification de production. Elle ne comprend pas encore la vérification d’e-mail/téléphone, la récupération de mot de passe, la limitation de débit, la gestion multi-instance ni les webhooks de paiement. Les baux hors ligne Ed25519 sont implémentés, mais nécessitent une gestion sécurisée des clés et une validation de déploiement. Le contrôle de capacités doit être appelé côté Bridge pour chaque build et côté services Code/Core pour chaque opération protégée. Le cache hors ligne du Studio est un dernier état connu, pas une preuve cryptographique inviolable.


## Intégration des droits dans BERKIOS Bridge (v0.7.34)

Sur le serveur de production, configurez le Bridge avec :

```env
BERKIOS_ACCOUNT_ENFORCEMENT=1
BERKIOS_ACCOUNT_API_URL=https://accounts.example.com
```

Remplacez `https://accounts.example.com` par l'URL HTTPS réelle du backend. Le Studio doit transmettre `accountToken` dans le corps JSON des appels Bridge protégés, en plus du jeton propre au Bridge dans l'en-tête Authorization. Ne transmettez jamais le jeton super_admin au Studio.

Si le backend de comptes est inaccessible, les opérations protégées échouent de manière sûre ; le mode hors ligne doit s'appuyer sur un mécanisme distinct de licence signée vérifiée localement. Ce mécanisme de licence hors ligne est décrit dans `OFFLINE_LICENSES.md`. Les clés privées doivent rester sur le VPS; la clé publique doit être installée de façon fiable dans le Bridge.
