# Contribuindo com o Certy Backend

Obrigado por contribuir com o Certy.

## Pré-requisitos

- Rust 1.93+ (Cargo)
- PostgreSQL 16+ (ou Docker)
- Git

## Setup local

```bash
cp .env.example .env
mkdir -p ./data/postgres
docker compose -f docker-compose.db.yml up -d
cargo run
```

## Fluxo recomendado

1. Faça fork do repositório.
2. Crie uma branch descritiva:
   - `feat/...` para funcionalidade
   - `fix/...` para correção
   - `chore/...` para manutenção
   - `docs/...` para documentação
3. Implemente mudanças pequenas, objetivas e sem escopo extra.
4. Rode as validações locais antes de abrir PR.
5. Abra um Pull Request com contexto claro.

## Validações obrigatórias

```bash
cargo test
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
```

## Padrões do projeto

- Não persista certificado/chave privada no banco.
- Não enfraqueça o fluxo de verificação por e-mail e DNS.
- Evite logs com dados sensíveis.
- Nunca commitar segredos, tokens ou `.env` real.
- Mantenha documentação atualizada quando mudar comportamento da API.

## O que incluir no Pull Request

- Objetivo da mudança.
- Resumo técnico do que foi alterado.
- Impacto em segurança/fluxo de emissão.
- Mudanças em migrations e compatibilidade (se houver).
- Exemplos de request/response quando alterar endpoints.

## Checklist antes de enviar

- Compila e testa localmente.
- Não inclui arquivos sensíveis.
- Não altera comportamentos críticos sem justificativa.
- README e exemplos de API estão atualizados.

## Reportar problemas

- Issues e sugestões: https://github.com/CertyBR/certy.com.br

## Reporte de segurança

Para vulnerabilidades, prefira reporte responsável aos mantenedores antes de abrir issue pública.
