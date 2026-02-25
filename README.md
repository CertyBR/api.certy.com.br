# Certy Backend (Rust + Let's Encrypt)

Backend modular para emissão de certificados via ACME (Let's Encrypt), usando desafio DNS-01 e
persistência no PostgreSQL.

As migrations rodam automaticamente na inicialização.

## Política de segurança de sessão e chaves

- `certificate_pem` e `private_key_pem` **não são persistidos** no banco.
- Certificado/chave são retornados **apenas** no `POST /sessions/{session_id}/finalize` quando o
  status chega em `issued`.
- Após emissão com sucesso, a sessão é imediatamente encerrada (removida da tabela ativa).
- O backend mantém auditoria em `certificate_session_events` com:
  - `session_id`
  - `domain`
  - `email`
  - `ip_address`
  - `action`
  - `details`
  - `created_at`
- O e-mail é validado via API externa da Likn (`/v1/public/email-validation/validate`) no backend
  antes de iniciar uma sessão.

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

Se quiser ativar validação de token no backend com Docker:

```bash
PROXY_SHARED_TOKEN=seu-token docker compose up --build -d
```

## Configuração principal (`.env`)

```env
BACKEND_BIND_ADDR=0.0.0.0:8080
DATABASE_URL=postgres://postgres:postgres@localhost:5432/certy
PROXY_SHARED_TOKEN=
EMAIL_VALIDATION_API_URL=https://api.likn.dev/v1/public/email-validation/validate
EMAIL_VALIDATION_TIMEOUT_MS=4500
ACME_USE_STAGING=false
SESSION_TTL_MINUTES=60
ACME_POLL_TIMEOUT_SECONDS=120
ACME_POLL_INITIAL_DELAY_MS=500
ACME_POLL_BACKOFF=1.8
RUST_LOG=info
```

Se `PROXY_SHARED_TOKEN` for preenchido, o backend exige:
- header `X-Certy-Proxy-Token` em `/api/v1/certificates/*`
- recomendação: enviar esse header apenas via Cloudflare Worker (`proxy/`)

## Endpoints da API

- `GET /health`
- `POST /api/v1/certificates/sessions`
- `GET /api/v1/certificates/sessions/{session_id}`
- `POST /api/v1/certificates/sessions/{session_id}/finalize`

`session_id` é um token longo aleatório (base64url), não um UUID.

## Fluxo

1. `POST /sessions` com `domain` e `email`.
2. API devolve o(s) registro(s) TXT `_acme-challenge`.
3. Você cria os registros no DNS.
4. Chama `POST /finalize`.
5. Quando validado, `POST /finalize` retorna `certificate_pem` e `private_key_pem` uma única vez.
6. A sessão é invalidada imediatamente após a emissão.

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
