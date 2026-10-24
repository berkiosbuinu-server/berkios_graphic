# Backend comptes et abonnements BERKIOS v0.7.91

Backend Node.js + SQLite pour les comptes BERKIOS Studio, BERKIOS Code et BERKIOS Core. Il couvre l'inscription e-mail/téléphone, les sessions, les abonnements Free/Pro/Premium, les codes de licence mensuels pour une machine et l'activation administrative. Il est prêt à être déployé derrière un reverse proxy HTTPS sur VPS, mais **ne pas exposer publiquement avant configuration et audit de production**.

## Prérequis et démarrage

- Node.js 22.18+ (utilise `node:sqlite`).
- Dans `backend/` : `npm ci` si un lockfile est fourni, puis `npm start`.
- Variables : `HOST=127.0.0.1` en développement; `PORT=8787`; `BERKIOS_DB=/var/lib/berkios/accounts.sqlite`; `BERKIOS_CORS_ORIGINS=https://studio.votre-domaine.tld`; `BERKIOS_SUPER_ADMIN_TOKEN=<secret-long-aleatoire>`.
- Pour un VPS, garder Node lié à localhost et exposer l'API par Caddy/Nginx avec HTTPS. Ne jamais mettre le jeton super_admin dans le Studio ou le dépôt Git.

## Offres

| Offre | Prix mensuel affiché | Fonctionnalités annoncées par l'API |
|---|---:|---|
| Free | 0 $ | 12 composants dans les capacités, pas de build mobile, crédit de 120 minutes/jour |
| Pro | 6 $ (7,50 $ avant réduction de 20 %) | environ 150 composants, build mobile |
| Premium | 20 $ (25 $ avant réduction de 20 %) | tous les composants et co-working |

Les nombres et indicateurs d'offre sont des métadonnées de capacité. Le Bridge et les API de génération doivent les appliquer côté serveur avant les opérations payantes; une interface seule n'est pas une frontière de sécurité. Le crédit Free doit être mesuré par le Studio/runtime local et synchronisé lorsqu'Internet revient.

## Routes

- `GET /api/health`
- `POST /api/auth/register` : `{email, phone, password}`; mot de passe de 10 à 256 caractères.
- `POST /api/auth/login` : `{identifier, password}` où identifier est l'e-mail ou le téléphone.
- `GET /api/account/me`, `GET /api/account/capabilities`, `POST /api/account/logout` avec `Authorization: Bearer <token>`.
- `POST /api/licenses/redeem` : `{code, machineId}`. Un code s'utilise une fois et est lié à une machine.
- `POST /api/admin/licenses/issue` : en-tête `X-Berkios-Admin-Token`, corps `{email, plan:'pro'|'premium', months:1}`. Le code en clair n'est retourné qu'une fois.
- `POST /api/admin/payments/cash-record` : enregistre un paiement cash confirmé et émet le code en une transaction atomique; champs `{email, plan, months, amount, currency:'USD'|'CDF', reference, note?}`. La référence est unique par devise.
- `GET /api/admin/payments` : derniers encaissements et totaux par devise, protégé par `X-Berkios-Admin-Token`.
- `GET /api/payments/providers` : liste les fournisseurs préparés et leur état désactivé; ne requiert pas de secret administrateur.
- `POST /api/admin/subscriptions/activate` : même en-tête, corps `{email, plan, months}` pour activer/renouveler un abonnement sans perdre la liaison machine existante.
- `POST /api/admin/subscriptions/transfer-machine` : même en-tête, `{email, reason?}` pour autoriser un transfert de machine et réinitialiser la liaison.
- `POST /api/admin/subscriptions/revoke` : même en-tête, `{email, reason?}` pour révoquer l’abonnement et basculer le compte sur Free.
- `POST /api/payments/checkout` : route d'extension préparée; retourne HTTP 501 jusqu'à l'intégration d'un fournisseur et de ses webhooks signés.
- `POST /api/account/plan` : désactivée (HTTP 410); les utilisateurs ne peuvent plus s'attribuer Pro/Premium eux-mêmes.

## Expiration

Un abonnement payant est considéré en période de grâce pendant 48 heures après son expiration. Après ce délai, il revient automatiquement à Free lors de la prochaine lecture de l'abonnement. Les applications peuvent fonctionner hors ligne avec le dernier état mis en cache, mais elles doivent resynchroniser le statut au retour du réseau. Le Bridge utilise des baux hors ligne signés Ed25519 limités à 24 heures et vérifie leur signature, leur date et la liaison à la machine. La révocation serveur ne peut pas invalider immédiatement un bail déjà signé quand la machine est hors ligne; ce bail reste valide jusqu’à son expiration.

## Paiements ultérieurs

Le point d'entrée indique des adaptateurs possibles (`stripe`, `flutterwave`, `orange-money`, `mpesa`, `airtel-money`). Aucun paiement en ligne n'est simulé comme réussi. Les encaissements cash sont enregistrés manuellement dans `cash_payments`; l'interface accepte USD/CDF mais ne calcule pas le taux de change. Chaque adaptateur devra vérifier côté serveur la signature du webhook, l'idempotence, la devise et le statut réel de transaction avant de créer/renouveler un abonnement.

## Avant la production

Configurer HTTPS, sauvegardes SQLite, limites de débit, vérification d'e-mail/téléphone, récupération de compte, rotation/révocation des sessions, journalisation protégée, secrets hors dépôt, contrôle de permissions, politique de confidentialité et tests de charge. Pour plusieurs instances VPS, migrer de SQLite vers PostgreSQL et ajouter des migrations versionnées. Le rôle `super_admin` ne doit jamais être attribué via l'inscription publique; les actions d'administration utilisent le secret serveur.
