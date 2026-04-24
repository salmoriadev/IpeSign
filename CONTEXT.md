# IpeSign Context

## O que é

IpeSign é uma aplicação para assinatura e verificação de PDFs com:

- certificado efêmero por documento
- assinatura do hash do PDF
- chave privada temporária descartada após o uso
- ledger append-only encadeado por hash
- persistência local em arquivo ou em PostgreSQL

## Modelo atual

O sistema hoje opera com uma única instituição emissora:

- `issuerId = ipe`
- uma AC da Ipê persistida entre reinícios
- uma blockchain local assinada pelo próprio sistema

O modelo atual é de:

- integridade criptográfica
- auditabilidade
- rastreabilidade
- uso único por `cert_hash`

Não é um sistema blockchain distribuído. É um ledger institucional auditável.

## Fluxo atual

### Assinatura

1. Ler PDF real
2. Calcular `SHA-256` do PDF
3. Gerar chave efêmera `ed25519`
4. Emitir certificado X.509 temporário assinado pela AC da Ipê
5. Registrar `CERTIFICATE_ISSUED` no ledger
6. Assinar o hash do PDF
7. Descartar a chave privada efêmera
8. Registrar `SIGNATURE_REGISTERED` no ledger
9. Retornar sidecar JSON ou resposta HTTP

### Verificação

1. Ler PDF real
2. Recalcular `SHA-256` do PDF
3. Validar assinatura com a chave pública do certificado
4. Validar se o certificado foi emitido pela AC da Ipê
5. Ler o `documentHash` embutido no certificado
6. Consultar o ledger
7. Confirmar `singleUseConfirmed`

## O que já está pronto

- CLI para `sign` e `verify`
- servidor HTTP básico
- persistência em arquivo
- persistência opcional em PostgreSQL
- linked list da cadeia com verificação forward/backward
- emissão de certificado efêmero real

## O que ainda não está pronto

- assinatura embutida dentro do PDF
- PAdES
- autenticação e autorização
- revogação administrativa completa
- frontend
- proteção forte das chaves privadas

## Layout do repositório

```text
apps/api/            estrutura preparada para a API web
apps/web/            estrutura preparada para o frontend
packages/contracts/  contratos compartilhados

cmd/ipesign/         CLI atual
internal/api/        servidor HTTP atual
internal/authority/  AC da Ipê e emissão de certificados
internal/ledger/     ledger local encadeado por hash
internal/persist/    persistência em arquivo e PostgreSQL
```

## Regra importante para o time

O core criptográfico e o ledger já existem e devem ser reutilizados.

Para a próxima fase:

- frontend fala com `apps/api`
- `apps/api` chama o core em `internal/`
- evitar duplicar regra de negócio no frontend ou na camada HTTP
