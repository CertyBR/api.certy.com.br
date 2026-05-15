# Certy Backend

Backend em Rust para emissão de certificados TLS/SSL via Let's Encrypt (ACME DNS-01), com fluxo por sessão, verificação de e-mail por código e persistência em PostgreSQL. Inclui também endpoint de verificação de certificados SSL via conexão TLS direta.

As migrations rodam automaticamente na inicialização.

## Visão geral

Este backend implementa dois conjuntos de funcionalidades:

### Emissão de certificados (fluxo por sessão)

1. valida domínio e e-mail;
2. valida desafio Cloudflare Turnstile (se `TURNSTILE_SECRET_KEY` configurado);
3. valida e-mail via API externa (Likn);
4. cria sessão com `session_id` aleatório;
5. envia código de verificação por e-mail (Resend, SMTP ou modo local);
6. após código válido, reutiliza/cria conta ACME compartilhada, cria pedido e retorna registros DNS;
7. faz pré-checagem DNS antes de acionar a CA;
8. finaliza emissão e retorna certificado/chave apenas uma vez;
9. invalida a sessão imediatamente após emissão.

### Verificação de certificados SSL

- Conecta diretamente ao host na porta 443 via TLS;
- Aceita qualquer certificado (inclusive expirados/autoassinados) para inspeção;
- Extrai CN, SANs, emissor, validade, número de série do X.509;
- Em paralelo, faz probe HTTPS com validação real (determina se o cert é confiável);
- Sem dependências externas — não consulta CT logs nem APIs de terceiros.

## Stack

- Rust `1.85+` (edition `2024`)
- Axum `0.8`
- SQLx + PostgreSQL
- instant-acme (`Let's Encrypt`)
- reqwest (validação de e-mail + DNS resolver + Resend + Turnstile)
- tokio-rustls + x509-parser (inspeção TLS direta)
- lettre (SMTP opcional)
- Docker Compose (opcional)

## Estrutura do projeto

```txt
backend/
  migrations/
    0001_create_certificate_sessions.sql
    0002_session_id_to_text.sql
    0003_harden_session_storage.sql
    0004_add_email_verification_fields.sql
    0005_add_email_resend_controls.sql
    0006_create_acme_accounts.sql
  src/
    config.rs
    error.rs
    main.rs
    models.rs
    repositories/
      session_repository.rs
    routes/
      cert_check.rs       ← verificação SSL direta
      certificates.rs
      health.rs
      mod.rs
    services/
      acme.rs
      dns_precheck.rs
      email_sender.rs
      email_validation.rs
      email_verification.rs
    session_id.rs
    state.rs
    validation.rs
  tests/
    validation_domain_tests.rs
    validation_email_tests.rs
```

## Segurança e privacidade

- `certificate_pem` e `private_key_pem` nunca são persistidos no banco.
- Após emissão bem-sucedida, a sessão é removida de `certificate_sessions`.
- O backend mantém trilha de auditoria em `certificate_session_events` com: `session_id`, `domain`, `email`, `action`, `details`, `ip_address`, `created_at`.
- Sessões expiradas são removidas por `prune_expired()` em cada endpoint de sessão.
- Se `PROXY_SHARED_TOKEN` estiver configurado, o backend exige `X-Certy-Proxy-Token` em todas as rotas de certificados.
- Se `TURNSTILE_SECRET_KEY` estiver configurado, a criação de sessão exige token Turnstile válido.
- O IP é obtido de `X-Forwarded-For` (primeiro IP) ou `X-Real-IP`.

> O CORS do backend está aberto (`Any`). Em produção, exponha apenas via proxy oficial.

## Fluxo de sessão e status

Status possíveis (`SessionStatus`):

- `awaiting_email_verification`
- `pending_dns`
- `validating`
- `issued`
- `failed`
- `expired`

Fluxo real da API:

1. `POST /sessions` — cria sessão em `awaiting_email_verification`; valida Turnstile se configurado; envia código por e-mail; retorna `session_id`.
2. `POST /sessions/{id}/verification-code` — reenvia código; limite: `EMAIL_VERIFICATION_MAX_RESENDS` (padrão `3`); intervalo mínimo: `EMAIL_VERIFICATION_RESEND_INTERVAL_MINUTES` (padrão `10`).
3. `POST /sessions/{id}/verify-email` — aceita código de 6 dígitos; limite: `EMAIL_VERIFICATION_MAX_ATTEMPTS` (padrão `5`); se válido, cria ordem ACME e retorna registros DNS.
4. `POST /sessions/{id}/dns-check` — pré-checagem dos TXT esperados via DoH.
5. `POST /sessions/{id}/finalize` — revalida DNS; finaliza ordem ACME; retorna `certificate_pem` e `private_key_pem` apenas nessa resposta; remove sessão ativa.

`session_id` é gerado com 48 bytes criptograficamente aleatórios, codificado em base64url (sem padding).

## Requisitos

- Rust toolchain (`cargo`)
- PostgreSQL 16+ (ou Docker)
- Acesso externo para:
  - Let's Encrypt (ACME)
  - API de validação de e-mail (Likn)
  - Resolver DNS DoH
  - Cloudflare Turnstile `/siteverify` (se habilitado)
  - Resend (se habilitado)

## Configuração (`.env`)

```bash
cp .env.example .env
```

### Variáveis obrigatórias

| Variável | Descrição |
| --- | --- |
| `BACKEND_PORT` | Porta do servidor (bind e Docker Compose) |
| `DATABASE_URL` | URL de conexão PostgreSQL |

### Segurança

| Variável | Descrição | Default |
| --- | --- | --- |
| `PROXY_SHARED_TOKEN` | Token exigido em `X-Certy-Proxy-Token` | vazio (desabilitado) |
| `TURNSTILE_SECRET_KEY` | Chave secreta Cloudflare Turnstile | vazio (desabilitado) |
| `EMAIL_VERIFICATION_SECRET` | Segredo HMAC do código de verificação | `certy-dev-secret-change-me` |

### Banco de dados (Docker Compose)

| Variável | Default |
| --- | --- |
| `POSTGRES_DB` | `certy` |
| `POSTGRES_USER` | `postgres` |
| `POSTGRES_PASSWORD` | `postgres` |
| `POSTGRES_HOST_PORT` | `5432` |
| `POSTGRES_DATA_DIR` | `./data/postgres` |

### E-mail

| Variável | Descrição | Default |
| --- | --- | --- |
| `EMAIL_VALIDATION_API_URL` | Endpoint Likn | `https://api.likn.dev/v1/public/email-validation/validate` |
| `EMAIL_VALIDATION_TIMEOUT_MS` | Timeout validação e-mail | `4500` |
| `EMAIL_VERIFICATION_CODE_TTL_MINUTES` | TTL do código | `10` |
| `EMAIL_VERIFICATION_MAX_ATTEMPTS` | Tentativas máximas | `5` |
| `EMAIL_VERIFICATION_MAX_RESENDS` | Reenvios máximos | `3` |
| `EMAIL_VERIFICATION_RESEND_INTERVAL_MINUTES` | Intervalo entre reenvios | `10` |
| `RESEND_API_KEY` | Chave Resend (prioridade 1) | vazio |
| `RESEND_API_URL` | Endpoint Resend | `https://api.resend.com/emails` |
| `RESEND_FROM_EMAIL` | Remetente Resend | `certy.zerocert@send.likncorp.com` |
| `RESEND_FROM_NAME` | Nome remetente Resend | `Certy by ZeroCert` |
| `SMTP_HOST` | Host SMTP (fallback) | vazio |
| `SMTP_PORT` | Porta SMTP | `587` |
| `SMTP_USERNAME` | Usuário SMTP | vazio |
| `SMTP_PASSWORD` | Senha SMTP | vazio |
| `SMTP_FROM_EMAIL` | E-mail remetente SMTP | vazio |
| `SMTP_FROM_NAME` | Nome remetente SMTP | `Certy` |
| `SMTP_STARTTLS` | Ativa STARTTLS | `true` |

Prioridade de envio: **Resend** → **SMTP** → **modo local** (loga o código no console).

### DNS e ACME

| Variável | Descrição | Default |
| --- | --- | --- |
| `DNS_CHECK_RESOLVER_URL` | Resolver DoH para pré-checagem TXT | `https://dns.google/resolve` |
| `DNS_CHECK_TIMEOUT_MS` | Timeout DNS | `4500` |
| `ACME_DIRECTORY_URL` | URL direta da CA (opcional) | vazio |
| `ACME_USE_STAGING` | Let's Encrypt Staging | `false` |
| `ACME_ACCOUNT_CONTACT_EMAIL` | E-mail conta ACME compartilhada | vazio |
| `ACME_ACCOUNT_CREDENTIALS_JSON` | Credenciais JSON conta ACME existente | vazio |
| `SESSION_TTL_MINUTES` | TTL da sessão | `60` |
| `ACME_POLL_TIMEOUT_SECONDS` | Timeout polling ACME | `120` |
| `ACME_POLL_INITIAL_DELAY_MS` | Delay inicial polling | `500` |
| `ACME_POLL_BACKOFF` | Backoff exponencial (>1.0) | `1.8` |

### Outros

| Variável | Default |
| --- | --- |
| `RUST_LOG` | `info` |

## Executando

### Opção A: backend local + banco em Docker

```bash
mkdir -p ./data/postgres
docker compose -f docker-compose.db.yml up -d
# .env deve ter: DATABASE_URL=postgres://postgres:postgres@localhost:5432/certy
cargo run
```

### Opção B: backend + banco em Docker (recomendado)

```bash
mkdir -p ./data/postgres
docker compose up --build -d
```

O `docker-compose.yml` sobe o backend na porta `BACKEND_PORT` e o banco na rede interna Docker (sem exposição no host).

## Endpoints

Base local: `http://localhost:3000`

| Método | Rota | Descrição |
| --- | --- | --- |
| `GET` | `/health` | Health check |
| `POST` | `/api/v1/certificates/sessions` | Criar sessão de emissão |
| `GET` | `/api/v1/certificates/sessions/{id}` | Consultar sessão |
| `POST` | `/api/v1/certificates/sessions/{id}/verification-code` | Reenviar código |
| `POST` | `/api/v1/certificates/sessions/{id}/verify-email` | Verificar código de e-mail |
| `POST` | `/api/v1/certificates/sessions/{id}/dns-check` | Pré-checar registros DNS |
| `POST` | `/api/v1/certificates/sessions/{id}/finalize` | Finalizar emissão |
| `GET` | `/api/v1/certificates/check?host=example.com` | Verificar certificado SSL |

Se `PROXY_SHARED_TOKEN` estiver definido, envie em todas as rotas:

```http
X-Certy-Proxy-Token: <token>
```

### Exemplos

**Criar sessão (com Turnstile)**

```bash
curl -X POST http://localhost:3000/api/v1/certificates/sessions \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com","email":"ops@example.com","turnstile_token":"<TOKEN>"}'
```

**Verificar código de e-mail**

```bash
curl -X POST http://localhost:3000/api/v1/certificates/sessions/<ID>/verify-email \
  -H "Content-Type: application/json" \
  -d '{"code":"123456"}'
```

**Verificar certificado SSL**

```bash
curl "http://localhost:3000/api/v1/certificates/check?host=example.com"
```

Resposta inclui: `host`, `site_ok`, `site_error`, `redirects_to`, `cert` (serial, issuer, SANs, validade, `days_remaining`, `is_wildcard`, `is_expired`).

## Banco de dados

Migrations aplicadas automaticamente na inicialização:

- `0001`: cria `certificate_sessions`
- `0002`: migra `id` de `UUID` para `TEXT`
- `0003`: remove colunas persistentes de certificado/chave; cria `certificate_session_events`
- `0004`: adiciona campos de verificação de e-mail
- `0005`: adiciona controle de reenvio (`last_sent_at`, `resend_count`)
- `0006`: cria `acme_accounts` para reutilização de conta ACME por `directory_url`

Retenção:

- sessão ativa em `certificate_sessions` até expirar ou finalizar;
- após emissão, sessão é removida;
- auditoria permanece em `certificate_session_events`.

## Testes

```bash
cargo test
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
```

## Notas de produção

- Defina `EMAIL_VERIFICATION_SECRET` forte e exclusivo.
- Defina `PROXY_SHARED_TOKEN` e exponha o backend apenas via proxy.
- Configure `TURNSTILE_SECRET_KEY` para proteção contra bots no form de emissão.
- Use `ACME_USE_STAGING=false` em produção.
- Não deixe o modo local de e-mail ativo em ambiente público.

## Contribuição

Guia completo em [CONTRIBUTING.md](./CONTRIBUTING.md).

## Licença

Projeto licenciado sob MIT. Veja [LICENSE](./LICENSE).
