# Certy Backend (Rust + Let's Encrypt)

Backend modular para emissão de certificados via ACME (Let's Encrypt), usando desafio DNS-01.

## Rodar local

```bash
cp .env.example .env
cargo run
```

Servidor padrão: `http://0.0.0.0:8080`

## Endpoints

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
