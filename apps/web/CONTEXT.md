# Web Context

## Objetivo desta pasta

`apps/web` está preparada para receber o frontend do IpeSign.

O frontend ainda não existe. O backend já existe e pode ser testado hoje via CLI ou HTTP.

## O que o frontend precisa cobrir primeiro

### Fluxo 1: assinar PDF

Tela com:

- upload de PDF
- exibição do `documentHash`
- exibição do `recordId`
- download ou cópia do resultado da assinatura

### Fluxo 2: verificar PDF

Tela com:

- upload de PDF
- envio do certificado e assinatura associados
- resultado visual de:
  - `valid`
  - `signatureValid`
  - `ledgerRecordValid`
  - `singleUseConfirmed`

### Fluxo 3: detalhes técnicos

Tela ou drawer com:

- `certHash`
- `recordId`
- `policyId`
- `documentHash`
- dados da AC da Ipê

## Endpoints a consumir

Backend atual:

- `GET /v1/health`
- `GET /v1/ca`
- `POST /v1/sign`
- `POST /v1/verify`
- `GET /v1/chain/walk`
- `GET /v1/chain/verify`

Backend alvo para organização futura:

- `POST /v1/documents/sign`
- `POST /v1/documents/verify`
- `GET /v1/records/:recordId`

## Estado funcional do produto

O que o usuário final realmente está usando hoje no core:

- assinatura de hash de PDF
- certificado temporário real
- verificação real
- ledger persistido

O que ainda não existe para o frontend:

- sessão/auth
- painel admin pronto
- UX final de assinatura
- assinatura embutida no PDF

## Recomendação de arquitetura frontend

- `src/features/sign/` para upload e resultado de assinatura
- `src/features/verify/` para verificação
- `src/features/admin/` para auditoria e ledger
- `src/lib/api/` para o client HTTP
- `src/lib/env/` para variáveis de ambiente

## Recomendação prática

Na primeira iteração, o frontend não precisa modelar tudo.

Basta entregar:

- uma tela de assinatura
- uma tela de verificação
- uma tela de detalhes do resultado

Isso já permite demo funcional para produto e validação com usuários.
