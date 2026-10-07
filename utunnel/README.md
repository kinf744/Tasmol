# utunnel — tunnel UDP propriétaire (type Hysteria, sans Hysteria)

Tunnel UDP de bout en bout **implémenté from scratch en Go** : aucune
dépendance Hysteria/QUIC/quic-go. Congestion et fiabilité maison.

**Documentation complète** (protocole octet par octet, algorithmes,
concurrence, réglages, intégration app/serveur, diagnostic, roadmap) :
[docs/DOCUMENTATION_TECHNIQUE.md](docs/DOCUMENTATION_TECHNIQUE.md).

## Protocole

```
Client (SOCKS5 :10080)                    Serveur (UDP :5669)
  │  handshake1: [eph X25519 | ts | HMAC16 | pad aléatoire]
  ├────────────────────────────────────►  (PSK + ts ±120 s, anti-rejeu)
  │  handshake2: [eph X25519 | confirm16]
  ◄────────────────────────────────────
  │  paquets de session: [8B token | 24B nonce | AEAD(hdr|payload)]
  ├────────────────────────────────────►  ARQ sélectif, SACK, multi-sessions
```

- **Chiffrement** : X25519 éphémère + XChaCha20-Poly1305 (nonce 24B
  aléatoire par paquet), clés de session dérivées par HKDF-SHA3 informées
  du PSK, sens distincts C→S / S→C. Token de session = AAD + masque
  d'en-tête (aucun motif constant sur le fil).
- **Fiabilité** : fenêtre d'émission glissante, ACK cumulatif honnête
  (frontière contiguë) + SACK bitmask (32 seq hors-ordre au-dessus),
  retransmission rapide (triple-ACK) et RTO Jacobson/Karels (min 80 ms),
  slow-start + AIMD, pacing `srtt/cwnd`.
- **Multiplexage** : frames par stream `[op|sid|seq|finSeq|len|payload]` —
  réordonnancement par stream, FIN ordonné (n'agit qu'après TOUTES les
  données qui le précèdent), OPEN idempotent (réémission ARQ sans effet).
- **Tunnels transportés** : TCP (proxy CONNECT) + UDP (ASSOCIATE,
  datagrammes chiffrés fiables).

## Plage de ports / port-hopping

- **Serveur** : une socket UDP unique ; toute une PLAGE (ex. 34000-49999)
  peut être DNAT-ée dessus par nftables (deploy/utunnel.nft) — même
  approche que stivaros-zivpn.
- **Client** : rotation du port source (`-hop-port-every N` secondes) —
  le serveur suit l'adresse:port du pair **à chaque paquet**, donc la
  rotation est gratuite (aucun re-handshake). Un ping immédiat après hop
  met l'adresse du pair à jour.

## Comptes / expiration (mode stivaros)

`-users-file` : fichier `uuid|secret|YYYY-MM-DD` (users.list stivaros).
Chaque entrée devient un PSK (`SHA256(uuid:secret)`), purge quotidienne
des entrées expirées, rechargement horaire. La clé statique
(`-key-file`) est toujours préservée.

## Usage

```sh
# serveur
printf '<secret>' > /etc/utunnel/server.psk && chmod 600 /etc/utunnel/server.psk
utunnel-server -listen :5669 -key-file /etc/utunnel/server.psk

# client (clé = hex(sha256(secret serveur)) — ou uuid|secret stivaros)
utunnel-client -server <ip>:5669 -key-file client.psk -socks 127.0.0.1:10080
```

## Intégration application Android

Type de tunnel `utunnel` intégré à l'app EPHANG VPN : éditeur
(« CONFIGS » → add server → **Utunnel UDP** : host, port réel, clé PSK,
rotation du port source), binaire embarqué (`lib_utunnel.so`), et log
détaillé dans le journal (kighmu.txt, exportable vers Download depuis
l'onglet LOGS). Détails : [docs/DOCUMENTATION_TECHNIQUE.md](docs/DOCUMENTATION_TECHNIQUE.md#7-application).

## Tests

```sh
go test ./proto/ -v        # paquet, handshake, E2E (TCP+UDP), pertes 15 %
```

Suite complète : chiffrement (roundtrip, tamper, AAD), handshake (mauvaise
clé, rejeu), session E2E (proxy TCP, 1 Mo intègre, stream UDP), résistance
aux pertes (256 Ko à travers 15 % de pertes bidirectionnelles).

## Déploiement

Voir `deploy/` : unité systemd durcie + table nftables (DNAT plage).
`scripts/build_utunnel.sh` produit les binaires amd64/arm64/armv7
(obfusqués par garble si installé).

## Diagnostic

`UTUNNEL_TRACE=1` sur le client ou le serveur active une trace des
premiers frames mux (op/sid/seq) — utile pour diagnostiquer un lien
très perturbé.
