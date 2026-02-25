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
- Após a criação da sessão, o backend envia um código de verificação para o e-mail informado.
- A emissão só continua após validar esse código.
- Antes de chamar a CA, o backend faz pré-checagem DNS dos registros TXT esperados.

## Opção 1: Backend local + DB em Docker

```bash
cp .env.example .env
mkdir -p ./data/postgres
docker compose -f docker-compose.db.yml up -d
cargo run
```

Para essa opção, mantenha no `.env`:

```env
DATABASE_URL=postgres://postgres:postgres@localhost:5432/certy
```

`POSTGRES_DATA_DIR` define o bind mount do Postgres (pasta física no host):

```env
POSTGRES_DATA_DIR=./data/postgres
# ou caminho absoluto:
# POSTGRES_DATA_DIR=/home/user/zerocert/certy.com.br/backend/data/postgres
```

## Opção 2: Backend + DB em Docker

```bash
mkdir -p ./data/postgres
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
POSTGRES_DATA_DIR=./data/postgres
EMAIL_VALIDATION_API_URL=https://api.likn.dev/v1/public/email-validation/validate
EMAIL_VALIDATION_TIMEOUT_MS=4500
EMAIL_VERIFICATION_CODE_TTL_MINUTES=10
EMAIL_VERIFICATION_MAX_ATTEMPTS=5
EMAIL_VERIFICATION_MAX_RESENDS=3
EMAIL_VERIFICATION_RESEND_INTERVAL_MINUTES=10
EMAIL_VERIFICATION_SECRET=change-me-in-production
RESEND_API_KEY=
RESEND_API_URL=https://api.resend.com/emails
RESEND_FROM_EMAIL=certy.zerocert@send.likncorp.com
RESEND_FROM_NAME=Certy by ZeroCert
SMTP_HOST=
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_FROM_EMAIL=
SMTP_FROM_NAME=Certy
SMTP_STARTTLS=true
DNS_CHECK_RESOLVER_URL=https://dns.google/resolve
DNS_CHECK_TIMEOUT_MS=4500
ACME_USE_STAGING=false
SESSION_TTL_MINUTES=60
ACME_POLL_TIMEOUT_SECONDS=120
ACME_POLL_INITIAL_DELAY_MS=500
ACME_POLL_BACKOFF=1.8
RUST_LOG=info
```

Prioridade de envio de e-mail:
1. Resend (`RESEND_API_KEY`)
2. SMTP (se `RESEND_API_KEY` estiver vazio e `SMTP_HOST` configurado)
3. Modo local (log) quando nenhum provedor estiver configurado

Se `PROXY_SHARED_TOKEN` for preenchido, o backend exige:
- header `X-Certy-Proxy-Token` em `/api/v1/certificates/*`
- recomendação: enviar esse header apenas via Cloudflare Worker (`proxy/`)

## Endpoints da API

- `GET /health`
- `POST /api/v1/certificates/sessions`
- `GET /api/v1/certificates/sessions/{session_id}`
- `POST /api/v1/certificates/sessions/{session_id}/verification-code`
- `POST /api/v1/certificates/sessions/{session_id}/verify-email`
- `POST /api/v1/certificates/sessions/{session_id}/dns-check`
- `POST /api/v1/certificates/sessions/{session_id}/finalize`

`session_id` é um token longo aleatório (base64url), não um UUID.

## Fluxo

1. `POST /sessions` com `domain` e `email`.
2. Backend envia código de verificação para o e-mail informado.
3. Reenvio do código: máximo de 3 reenvios por sessão, com intervalo mínimo de 10 minutos entre reenvios.
4. `POST /sessions/{session_id}/verify-email` com o código.
5. API devolve o(s) registro(s) TXT `_acme-challenge`.
6. Você cria os registros no DNS.
7. `POST /sessions/{session_id}/dns-check` para pré-checagem DNS no backend.
8. `POST /sessions/{session_id}/finalize` somente após DNS pronto.
9. Quando validado, `POST /finalize` retorna `certificate_pem` e `private_key_pem` uma única vez.
10. A sessão é invalidada imediatamente após a emissão.

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

## Exemplo de verificação de e-mail

```bash
curl -X POST http://localhost:8080/api/v1/certificates/sessions/<SESSION_ID>/verify-email \
  -H "Content-Type: application/json" \
  -d '{"code":"123456"}'
```
