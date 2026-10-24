# Licences hors ligne signées — v0.7.86

## Ce qui est livré

- Endpoint authentifié `POST /api/account/offline-lease`, avec `Authorization: Bearer <session>` et JSON `{ "machineId": "identifiant-stable-de-la-machine" }`.
- Signature Ed25519 de la charge utile (offre, capacités, compte, machine, date d'émission et expiration).
- Première demande : l'abonnement est lié à la machine; une autre machine reçoit HTTP 409 et doit demander un transfert au support.
- Validité maximale d'une licence hors ligne : 24 heures. Il faut renouveler périodiquement la licence lorsque le serveur est accessible.
- Vérificateur pur `verifyLease` et tests de signature, d'expiration et de liaison machine.

## Configuration VPS

1. Dans `backend/`, exécuter `npm run keys:generate` une seule fois, dans un emplacement privé et persistant.
2. Configurer `BERKIOS_LICENSE_PRIVATE_KEY_FILE` et `BERKIOS_LICENSE_PUBLIC_KEY_FILE` vers ces fichiers. Sauvegarder la clé privée de façon sécurisée; ne jamais la distribuer.
3. Redémarrer le backend. Sans ces clés, l'endpoint retourne HTTP 503 plutôt que de produire une licence non signée.

## Appel

```http
POST /api/account/offline-lease
Authorization: Bearer <session>
Content-Type: application/json

{"machineId":"stable-id-from-local-bridge"}
```

La réponse contient `lease.algorithm`, `lease.payload` et `lease.signature`, ainsi que la clé publique. En production, installer la clé publique approuvée dans le Bridge et configurer `BERKIOS_LICENSE_PUBLIC_KEY_FILE` (ne pas faire confiance à la clé publique renvoyée par l’API).

## Limites explicites

Le Bridge tente de renouveler le bail lors d’un contrôle en ligne et le conserve dans `~/.berkios/offline-lease.json` avec permissions restreintes. En cas d’indisponibilité réseau, il vérifie la signature avec la clé publique épinglée dans `BERKIOS_LICENSE_PUBLIC_KEY_FILE`, la date et l’identifiant local. La machine est identifiée par un hachage de nom d’hôte, système et architecture : une réinstallation ou un changement de nom peut donc nécessiter un transfert/réactivation. Cette empreinte n’est pas une preuve matérielle inviolable; la signature empêche surtout la fabrication ou la modification simple des droits. Le mode hors ligne est limité à la validité du bail (24 h max).


## Cycle de renouvellement, transfert et révocation (v0.7.86)

- Une nouvelle activation administrative ou un code de renouvellement conserve la liaison machine existante.
- Pour un remplacement de machine, un opérateur authentifié appelle `POST /api/admin/subscriptions/transfer-machine` avec `email` ou `phone` et, si souhaité, `reason`. Cela remet la liaison à zéro; le client doit ensuite demander un nouveau bail sur la nouvelle machine.
- Pour révoquer un abonnement, un opérateur appelle `POST /api/admin/subscriptions/revoke`. Le compte revient à Free. Un bail Pro/Premium déjà signé reste toutefois utilisable hors ligne jusqu'à son expiration, au maximum 24 heures; la révocation immédiate hors réseau n'est pas possible avec un bail autonome.
- Les deux routes administratives exigent `X-Berkios-Admin-Token`. Ne jamais placer ce secret dans le Studio, le Bridge ou une application cliente.
