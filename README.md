# Certy Backend

Backend em Rust para emissão de certificados TLS/SSL via Let's Encrypt (ACME DNS-01), com fluxo por sessão, verificação de e-mail por código e persistência em PostgreSQL.

As migrations rodam automaticamente na inicialização.

## Visão geral

Este backend implementa um fluxo em etapas:

1. valida domínio e e-mail;
2. valida e-mail via API externa (Likn);
3. cria sessão com `session_id` aleatório;
4. envia código de verificação por e-mail (Resend, SMTP ou modo local);
5. após código válido, cria pedido ACME e retorna registros DNS;
6. faz pré-checagem DNS antes de acionar a CA;
7. finaliza emissão e retorna certificado/chave apenas uma vez;
8. invalida a sessão imediatamente após emissão.

## Stack

- Rust `1.93` (edition `2024`)
- Axum `0.8`
- SQLx + PostgreSQL
- instant-acme (`Let's Encrypt`)
- reqwest (validação de e-mail + DNS resolver + Resend)
- lettre (SMTP opcional)
- docker compose (opcional)

## Estrutura do projeto

```txt
backend/
  migrations/
    0001_create_certificate_sessions.sql
    0002_session_id_to_text.sql
    0003_harden_session_storage.sql
    0004_add_email_verification_fields.sql
    0005_add_email_resend_controls.sql
  src/
    config.rs
    error.rs
    main.rs
    models.rs
    repositories/
      session_repository.rs
    routes/
      certificates.rs
      health.rs
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
- O backend mantém trilha de auditoria em `certificate_session_events` com:
  - `session_id`, `domain`, `email`, `action`, `details`, `ip_address`, `created_at`.
- Sessões expiradas são removidas por `prune_expired()` em cada endpoint de sessão.
- Se `PROXY_SHARED_TOKEN` estiver configurado, o backend exige `X-Certy-Proxy-Token` nas rotas de certificados.
- O IP é obtido de `X-Forwarded-For` (primeiro IP) ou `X-Real-IP`.

Observação: atualmente o CORS do backend está aberto (`Any`), então o uso recomendado em produção é atrás do proxy oficial.

## Fluxo de sessão e status

Status possíveis (`SessionStatus`):

- `awaiting_email_verification`
- `pending_dns`
- `validating`
- `issued`
- `failed`
- `expired`

Fluxo real da API:

1. `POST /sessions`
   - cria sessão em `awaiting_email_verification`;
   - envia código por e-mail;
   - retorna `session_id`.
2. `POST /sessions/{id}/verification-code`
   - reenvia código;
   - limite: até `EMAIL_VERIFICATION_MAX_RESENDS` reenvios por sessão (padrão `3`);
   - intervalo mínimo entre reenvios: `EMAIL_VERIFICATION_RESEND_INTERVAL_MINUTES` (padrão `10`).
3. `POST /sessions/{id}/verify-email`
   - aceita código de 6 dígitos;
   - limite de tentativas: `EMAIL_VERIFICATION_MAX_ATTEMPTS` (padrão `5`);
   - se válido, cria ordem ACME e retorna registros DNS.
4. `POST /sessions/{id}/dns-check`
   - faz pré-checagem dos TXT esperados usando DoH (`DNS_CHECK_RESOLVER_URL`).
5. `POST /sessions/{id}/finalize`
   - revalida DNS internamente;
   - finaliza ordem ACME;
   - retorna `certificate_pem` e `private_key_pem` apenas nessa resposta;
   - remove sessão ativa após sucesso.

`session_id` é gerado com 48 bytes criptograficamente aleatórios, codificado em base64url (sem padding), e validado para caracteres seguros de URL.

## Requisitos

- Rust toolchain (`cargo`)
- PostgreSQL 16+ (ou Docker)
- Acesso externo para:
  - Let's Encrypt (ACME)
  - API de validação de e-mail (Likn)
  - Resolver DNS DoH
  - Resend (se habilitado)

## Configuração (`.env`)

Copie e ajuste:

```bash
cp .env.example .env
```

Variáveis principais:

| Variável | Descrição | Default |
| --- | --- | --- |
| `BACKEND_BIND_ADDR` | Endereço de bind HTTP | `0.0.0.0:8080` |
| `DATABASE_URL` | URL de conexão PostgreSQL | `postgres://postgres:postgres@localhost:5432/certy` |
| `PROXY_SHARED_TOKEN` | Token opcional exigido em `X-Certy-Proxy-Token` | vazio |
| `POSTGRES_DATA_DIR` | Pasta local para bind mount do Postgres no Docker | `./data/postgres` |
| `EMAIL_VALIDATION_API_URL` | Endpoint Likn para validação de e-mail | `https://api.likn.dev/v1/public/email-validation/validate` |
| `EMAIL_VALIDATION_TIMEOUT_MS` | Timeout da validação de e-mail | `4500` |
| `EMAIL_VERIFICATION_CODE_TTL_MINUTES` | TTL do código de verificação | `10` |
| `EMAIL_VERIFICATION_MAX_ATTEMPTS` | Tentativas máximas do código | `5` |
| `EMAIL_VERIFICATION_MAX_RESENDS` | Reenvios máximos por sessão | `3` |
| `EMAIL_VERIFICATION_RESEND_INTERVAL_MINUTES` | Intervalo mínimo entre reenvios | `10` |
| `EMAIL_VERIFICATION_SECRET` | Segredo para hash do código | `certy-dev-secret-change-me` |
| `RESEND_API_KEY` | Chave API da Resend (prioridade 1 de envio) | vazio |
| `RESEND_API_URL` | Endpoint da Resend | `https://api.resend.com/emails` |
| `RESEND_FROM_EMAIL` | E-mail remetente Resend | `certy.zerocert@send.likncorp.com` |
| `RESEND_FROM_NAME` | Nome remetente Resend | `Certy by ZeroCert` |
| `SMTP_HOST` | Host SMTP (fallback) | vazio |
| `SMTP_PORT` | Porta SMTP | `587` |
| `SMTP_USERNAME` | Usuário SMTP | vazio |
| `SMTP_PASSWORD` | Senha SMTP | vazio |
| `SMTP_FROM_EMAIL` | E-mail remetente SMTP | vazio |
| `SMTP_FROM_NAME` | Nome remetente SMTP | `Certy` |
| `SMTP_STARTTLS` | Ativa STARTTLS no SMTP | `true` |
| `DNS_CHECK_RESOLVER_URL` | Resolver DoH para pré-checagem TXT | `https://dns.google/resolve` |
| `DNS_CHECK_TIMEOUT_MS` | Timeout de pré-checagem DNS | `4500` |
| `ACME_DIRECTORY_URL` | URL direta da CA ACME (opcional) | vazio |
| `ACME_USE_STAGING` | Usa Let's Encrypt Staging quando `ACME_DIRECTORY_URL` vazio | `false` |
| `SESSION_TTL_MINUTES` | TTL da sessão de emissão | `60` |
| `ACME_POLL_TIMEOUT_SECONDS` | Timeout de polling ACME | `120` |
| `ACME_POLL_INITIAL_DELAY_MS` | Delay inicial de polling ACME | `500` |
| `ACME_POLL_BACKOFF` | Backoff do polling ACME (>1.0) | `1.8` |
| `RUST_LOG` | Nível de logs | `info` |

Prioridade de envio de e-mail no código:

1. Resend (`RESEND_API_KEY` preenchido)
2. SMTP (`SMTP_HOST` preenchido, sem `RESEND_API_KEY`)
3. Modo local (não envia, apenas loga o código)

## Executando

### Opção A: backend local + banco em Docker

```bash
mkdir -p ./data/postgres
docker compose -f docker-compose.db.yml up -d
cargo run
```

Garanta:

```env
DATABASE_URL=postgres://postgres:postgres@localhost:5432/certy
```

### Opção B: backend + banco em Docker

```bash
mkdir -p ./data/postgres
docker compose up --build -d
```

Nessa opção, o backend usa internamente:

```env
DATABASE_URL=postgres://postgres:postgres@db:5432/certy
```

`docker-compose.yml` sobe backend na porta `8080` e DB na `5432`.

## Endpoints

Base local: `http://localhost:8080`

- `GET /health`
- `POST /api/v1/certificates/sessions`
- `GET /api/v1/certificates/sessions/{session_id}`
- `POST /api/v1/certificates/sessions/{session_id}/verification-code`
- `POST /api/v1/certificates/sessions/{session_id}/verify-email`
- `POST /api/v1/certificates/sessions/{session_id}/dns-check`
- `POST /api/v1/certificates/sessions/{session_id}/finalize`

Se `PROXY_SHARED_TOKEN` estiver definido, envie:

```http
X-Certy-Proxy-Token: <token>
```

### Exemplo: criar sessão

```bash
curl -X POST http://localhost:8080/api/v1/certificates/sessions \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com","email":"ops@example.com"}'
```

### Exemplo: verificar código de e-mail

```bash
curl -X POST http://localhost:8080/api/v1/certificates/sessions/<SESSION_ID>/verify-email \
  -H "Content-Type: application/json" \
  -d '{"code":"123456"}'
```

### Exemplo: pré-checagem DNS

```bash
curl -X POST http://localhost:8080/api/v1/certificates/sessions/<SESSION_ID>/dns-check
```

### Exemplo: finalizar emissão

```bash
curl -X POST http://localhost:8080/api/v1/certificates/sessions/<SESSION_ID>/finalize
```

## Banco de dados

Migrations aplicadas automaticamente:

- `0001`: cria `certificate_sessions`
- `0002`: migra `id` de `UUID` para `TEXT`
- `0003`: remove colunas persistentes de certificado/chave e cria `certificate_session_events`
- `0004`: adiciona campos de verificação de e-mail
- `0005`: adiciona controle de reenvio (`last_sent_at`, `resend_count`)

Retenção:

- sessão ativa em `certificate_sessions` até expirar ou finalizar;
- após emissão, sessão é removida;
- auditoria permanece em `certificate_session_events`.

## Testes e validações

```bash
cargo test
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
```

Testes existentes cobrem normalização/validação de domínio e e-mail, além de partes dos serviços.

## Notas de produção

- Defina `EMAIL_VERIFICATION_SECRET` forte e exclusivo.
- Configure `PROXY_SHARED_TOKEN` e exponha o backend apenas via proxy.
- Em produção, prefira `ACME_USE_STAGING=false` (ou `ACME_DIRECTORY_URL` explícita).
- Não deixe modo local de e-mail ativo em ambiente público.

## Contribuição

Guia completo em [CONTRIBUTING.md](./CONTRIBUTING.md).

## Licença

Projeto licenciado sob MIT. Veja [LICENSE](./LICENSE).
