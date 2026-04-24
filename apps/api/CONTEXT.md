# API Context

## Objetivo desta pasta

`apps/api` é a casa da API web pública do IpeSign.

O transporte HTTP público agora mora nesta pasta, enquanto `internal/api` continua como camada de aplicação reutilizável.

## Estratégia recomendada

- manter o domínio em `internal/`
- manter transporte HTTP em `apps/api/`
- migrar aos poucos handlers e middleware para esta pasta sem reescrever a lógica central

## O que o core já faz

- criar ou restaurar a AC da Ipê
- criar ou restaurar o ledger
- assinar o hash de um PDF real
- verificar certificado, assinatura e ledger
- persistir em arquivo ou PostgreSQL

## Endpoints públicos atuais

- `GET /v1/health`
- `GET /v1/ca`
- `POST /v1/documents/sign`
- `POST /v1/documents/verify`
- `GET /v1/records/:recordId`
- `GET /v1/chain/walk`
- `GET /v1/chain/verify`

## Compatibilidade legada

- `POST /v1/sign`
- `POST /v1/verify`

## Endpoints recomendados para a próxima fase

- `POST /v1/certificates/:certHash/revoke`
- `GET /v1/admin/ledger/summary`

## Contrato atual de assinatura

Entrada:

- multipart form
- campo `pdf`
- campo opcional `policy_id`

Saída principal:

- `documentHash`
- `signatureBase64`
- `certificatePem`
- `certHash`
- `recordId`
- `policyId`

## Contrato atual de verificação

Entrada:

- multipart form
- campo `pdf`
- campo `certificate_pem`
- campo `signature_base64`

Saída principal:

- `valid`
- `signatureValid`
- `ledgerRecordValid`
- `singleUseConfirmed`
- `recordId`

## Persistência

O backend escolhe o store por configuração:

- com `DATABASE_URL`: PostgreSQL
- sem `DATABASE_URL`: arquivos em `./data`

## Limites e premissas atuais

- o sistema assina o hash do PDF
- o PDF ainda não recebe assinatura embutida
- a política default é `participation-v1`
- a instituição emissora é única: `ipe`

## Recomendações para quem for continuar

- manter o roteamento em `apps/api/http/router`
- manter handlers por feature em `apps/api/http/handlers`
- manter request/response compartilhados em `packages/contracts`
- não mover a lógica criptográfica para a camada HTTP
