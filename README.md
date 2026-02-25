# Certy Backend (Rust + Let's Encrypt)

Backend modular para emissão de certificados via ACME (Let's Encrypt), usando desafio DNS-01 e
persistência no PostgreSQL.

As migrations rodam automaticamente na inicialização.

## Opção 1: Backend local + DB em Docker

```bash
cp .env.example .env
docker compose -f docker-compose.db.yml up -d
cargo run
```

Para essa opção, mantenha no `.env`:

```env
DATABASE_URL=postgres://postgres:postgres@localhost:5432/certy
```

## Opção 2: Backend + DB em Docker

```bash
docker compose up --build -d
```

Backend: `http://localhost:8080`

## Configuração principal (`.env`)

```env
BACKEND_BIND_ADDR=0.0.0.0:8080
DATABASE_URL=postgres://postgres:postgres@localhost:5432/certy
ACME_USE_STAGING=false
SESSION_TTL_MINUTES=60
ACME_POLL_TIMEOUT_SECONDS=120
ACME_POLL_INITIAL_DELAY_MS=500
ACME_POLL_BACKOFF=1.8
RUST_LOG=info
```

## Endpoints da API

- `GET /health`
- `POST /api/v1/certificates/sessions`
- `GET /api/v1/certificates/sessions/{session_id}`
- `POST /api/v1/certificates/sessions/{session_id}/finalize`

## Fluxo

1. `POST /sessions` com `domain` e `email`.
2. API devolve o(s) registro(s) TXT `_acme-challenge`.
3. Você cria os registros no DNS.
4. Chama `POST /finalize`.
5. Quando validado, resposta retorna `certificate_pem` e `private_key_pem`.

## Exemplo de criação de sessão

```bash
curl -X POST http://localhost:8080/api/v1/certificates/sessions \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com","email":"ops@example.com"}'
```

## Exemplo de finalização

```bash
curl -X POST http://localhost:8080/api/v1/certificates/sessions/<SESSION_ID>/finalize
```
