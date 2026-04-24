# IpêSign MVP Plan

## Decisão arquitetural

Como o sistema **sempre será operado por uma única instituição, a Ipê**, eu **não usaria Hyperledger Fabric** nem no MVP nem na primeira versão séria do produto.

Eu implementaria o IpêSign como:

- `serviço de assinatura/verificação`
- `certificados efêmeros de uso único`
- `ledger append-only encadeado por hash`
- `assinatura dos eventos do ledger`
- `âncora externa periódica do hash raiz`

Motivo:

- Fabric resolve um problema de governança distribuída
- esse problema não existe quando a única autoridade é a `Ipê`
- o custo operacional de peer, orderer, MSP, canal e chaincode não traz benefício proporcional
- a regra central do sistema continua sendo a mesma: `um cert_hash só pode ser usado uma vez`

## Posição técnica honesta

Se a Ipê for a única instituição, eu não chamaria isso de blockchain.

Os termos corretos são:

- `ledger auditável encadeado por hash`
- `log append-only com integridade criptográfica`
- `tamper-evident ledger`

Isso comunica o que o sistema realmente entrega:

- integridade
- auditabilidade
- rastreabilidade
- evidência de adulteração

Sem sugerir descentralização que não existe.

---

## Escopo do MVP

O MVP deve provar 5 coisas:

1. o sistema gera uma chave efêmera por documento
2. o sistema emite um certificado de uso único vinculado ao hash do documento
3. o documento é assinado
4. a chave privada é descartada após a assinatura
5. a verificação confirma integridade, emissor confiável e uso único no ledger

## O que eu não colocaria no MVP inicial

- Hyperledger Fabric
- frontend web
- multi-organização
- Keycloak
- PAdES avançado com carimbo temporal e cadeia ICP completa
- storage distribuído
- banco relacional separado

## Corte de risco importante

Para o primeiro MVP, eu faria em **duas camadas de escopo**:

### MVP A - prova criptográfica e de uso único

Assina o **hash do PDF** e gera um artefato verificável no terminal.

Saídas:

- `document.pdf`
- `document.sig.json`
- `document.cert.pem`
- `document.bundle.json`
- `ledger.jsonl` ou `ledger.db`

Esse MVP prova a regra de negócio central sem depender da parte mais chata de PDF/PAdES.

### MVP B - assinatura embutida no PDF

Depois que o fluxo estiver correto, evoluímos para assinatura PDF real.

Esse segundo passo pode ser:

- ainda em Go, se aceitarmos limitações da stack de PDF
- ou com um adaptador externo depois, se quisermos PAdES mais sério

---

## Arquitetura recomendada para o MVP

```text
CLI Go (`ipesign`)
  ├── issuer service
  ├── ephemeral cert service
  ├── document signer
  ├── document verifier
  ├── ledger service
  └── storage layer
```

## Visão prática

```text
Usuário
  ↓
CLI `ipesign`
  ├── init-issuer
  ├── sign
  ├── verify
  ├── revoke-cert
  ├── inspect-record
  └── audit-ledger
```

## Estrutura sugerida do projeto

```text
cmd/ipesign/main.go

internal/app/
internal/crypto/
internal/cert/
internal/document/
internal/ledger/
internal/ledger/localchain/
internal/ledger/fabric/
internal/store/
internal/issuer/
internal/verify/

pkg/types/

testdata/
data/
```

## Interfaces centrais

```go
type Ledger interface {
    RegisterIssuer(ctx context.Context, issuer Issuer) error
    RegisterCertificate(ctx context.Context, cert CertificateRecord) error
    RegisterSignature(ctx context.Context, sig PDFSignatureRecord) error
    GetCertificate(ctx context.Context, certHash string) (*CertificateRecord, error)
    GetSignatureByCertHash(ctx context.Context, certHash string) (*PDFSignatureRecord, error)
    VerifyRecord(ctx context.Context, input VerifyLedgerInput) (*VerifyLedgerResult, error)
    RevokeCertificate(ctx context.Context, certHash string, reason string) error
}
```

Isso mantém o domínio desacoplado do mecanismo de ledger.

Mesmo sem intenção de migrar para Fabric, essa separação continua valendo porque evita misturar regra de negócio com persistência.

---

## Modelo para a versão simples

## Issuer

Uma única autoridade emissora:

- `issuer_id = ipe-city`
- chave raiz de emissão
- chave de auditoria do ledger

Eu separaria:

- `issuer signing key`
- `ledger sealing key`

Assim o ledger pode ser assinado independentemente dos certificados emitidos.

## Ledger local

Eu usaria **SQLite** com duas camadas:

1. tabela append-only de eventos
2. índices materializados para consulta rápida

### Tabela de eventos

Cada evento vira um bloco encadeado:

```go
type LedgerBlock struct {
    Index           uint64          `json:"index"`
    PrevHash        string          `json:"prevHash"`
    BlockHash       string          `json:"blockHash"`
    Timestamp       time.Time       `json:"timestamp"`
    EventType       string          `json:"eventType"`
    Payload         json.RawMessage `json:"payload"`
    PayloadHash     string          `json:"payloadHash"`
    LedgerSignature string          `json:"ledgerSignature"`
}
```

### Tipos de evento

- `ISSUER_REGISTERED`
- `CERTIFICATE_ISSUED`
- `SIGNATURE_REGISTERED`
- `CERTIFICATE_REVOKED`
- `SIGNATURE_REVOKED`

### Âncora externa

Como existe apenas uma instituição, o ponto mais importante não é consenso distribuído, e sim reduzir a capacidade de adulteração silenciosa do histórico.

Eu adicionaria uma rotina de checkpoint:

- a cada `N` eventos ou a cada `24h`, calcula-se o `latest_block_hash`
- esse hash é publicado em um meio externo verificável
- o verificador consegue conferir se o ledger local continua consistente com os checkpoints publicados

Exemplos práticos:

- repositório git com tag assinada
- objeto imutável em storage com versionamento e retenção
- e-mail assinado enviado para uma caixa institucional separada
- serviço externo de timestamp

### Regra de uso único

Na hora de registrar `SIGNATURE_REGISTERED`:

- procura `cert_hash`
- verifica se já existe uso anterior
- se existir, retorna erro
- se não existir, grava evento e marca estado `USED`

## Vantagem disso

- simples de rodar localmente
- fácil de testar
- determinístico
- auditável
- barato de evoluir

## Limitação disso

Como a própria Ipê controla a infraestrutura, o modelo de confiança continua sendo institucional.

O objetivo do ledger não é eliminar confiança na Ipê. O objetivo é:

- tornar fraude interna mais difícil
- tornar alteração retroativa detectável
- manter trilha auditável de emissão, uso e revogação

Se alguém com controle total da máquina tentar reescrever a cadeia inteira, ele ainda enfrentará:

- validação da hash chain
- assinatura dos blocos
- checkpoints externos já publicados

---

## Fluxo do MVP no terminal

## 1. Inicialização do emissor

Comando:

```bash
ipesign init-issuer --issuer-id ipe-city
```

Saídas:

- gera chave raiz do emissor
- gera certificado raiz local
- gera chave de auditoria do ledger
- cria ledger genesis

## 2. Assinatura

Comando:

```bash
ipesign sign ./input.pdf --policy participation-v1 --issuer ipe-city --out ./signed
```

Fluxo:

1. lê bytes do PDF
2. calcula `document_hash`
3. gera chave efêmera
4. emite certificado de uso único amarrado ao `document_hash`
5. registra `CERTIFICATE_ISSUED` no ledger
6. assina o documento
7. descarta a chave privada efêmera
8. calcula `signature_hash`
9. registra `SIGNATURE_REGISTERED` no ledger
10. grava artefatos de saída

## 3. Verificação

Comando:

```bash
ipesign verify ./signed/input.pdf \
  --manifest ./signed/input.sig.json \
  --cert ./signed/input.cert.pem
```

Fluxo:

1. carrega assinatura, certificado e manifesto
2. verifica assinatura criptográfica
3. verifica emissor confiável
4. recalcula hashes
5. consulta ledger
6. confirma uso único
7. imprime resultado detalhado no terminal

## 4. Revogação

Comando:

```bash
ipesign revoke-cert --cert-hash <hash> --reason "issued by mistake"
```

## 5. Auditoria

Comando:

```bash
ipesign audit-ledger
```

Valida:

- hash chain íntegra
- assinatura de cada bloco
- consistência de estados materializados

---

## Estratégia de assinatura do documento

## Opção recomendada para o MVP

No primeiro ciclo, eu **não tentaria PAdES completo**.

Eu faria:

- hash do PDF
- assinatura digital desse hash com chave efêmera
- certificado temporário emitido pela `Ipê City`
- manifesto JSON com os metadados
- bundle JSON apontando para os artefatos emitidos

Exemplo de manifesto:

```json
{
  "version": 1,
  "issuer_id": "ipe-city",
  "policy_id": "participation-v1",
  "document_hash": "sha256:...",
  "cert_hash": "sha256:...",
  "public_key_hash": "sha256:...",
  "signature_hash": "sha256:...",
  "signed_at": "2026-04-24T14:02:10Z",
  "record_id": "pdfsig-001"
}
```

### Por que isso é melhor no começo

- reduz drasticamente a complexidade
- deixa o núcleo de segurança validado
- evita travar o projeto na parte mais difícil

## Evolução depois

Quando esse fluxo estiver sólido, aí sim entramos em:

- assinatura embutida no PDF
- extração do certificado do próprio PDF
- validação mais próxima de PAdES

---

## Escolhas criptográficas sugeridas

## Para o MVP

- `SHA-256` para hashes
- `ECDSA P-256` ou `Ed25519` para assinatura
- `X.509` para certificado emitido pela `Ipê City`

## Recomendação prática

Se quisermos simplicidade:

- `Ed25519` para assinatura

Se quisermos caminho mais tradicional com X.509 e ecossistema corporativo:

- `ECDSA P-256`

Eu escolheria **ECDSA P-256** no MVP para ficar mais próximo do que um stack institucional espera.

---

## Entregáveis por fase

## Fase 1 - Núcleo de domínio

Objetivo:

- modelar issuer, certificate record, signature record e política de uso único

Entregáveis:

- tipos Go
- hashes
- geração de chaves
- emissão de certificado temporário
- descarte explícito da chave efêmera
- testes unitários

Critério de aceite:

- gerar certificado de uso único amarrado ao `document_hash`

## Fase 2 - Ledger simples

Objetivo:

- implementar ledger local encadeado por hash

Entregáveis:

- bloco genesis
- append de eventos
- cálculo de `prevHash` e `blockHash`
- assinatura dos blocos
- consulta por `cert_hash`
- trava de uso único
- publicação de checkpoints

Critério de aceite:

- segunda tentativa de usar o mesmo `cert_hash` falha

## Fase 3 - CLI funcional

Objetivo:

- operar tudo pelo terminal

Entregáveis:

- `init-issuer`
- `sign`
- `verify`
- `revoke-cert`
- `inspect-record`
- `audit-ledger`

Critério de aceite:

- fluxo end-to-end sem interface web

## Fase 4 - Assinatura do artefato

Objetivo:

- assinar o hash do PDF e gerar pacote verificável

Entregáveis:

- manifesto assinado
- certificado emitido
- verificação local
- saída amigável no terminal

Critério de aceite:

- alteração de 1 byte no PDF invalida a verificação

## Fase 5 - PDF embedded

Objetivo:

- mover de pacote lateral para assinatura embutida no PDF

Entregáveis:

- adaptador PDF
- extração de assinatura/certificado
- verificação integrada

Critério de aceite:

- um único arquivo PDF basta para verificar

## Fase 6 - Hardening do ledger

Objetivo:

- endurecer o ledger institucional para auditoria real

Entregáveis:

- checkpoints externos automáticos
- trilha de auditoria administrativa
- retenção e versionamento dos snapshots
- export de prova verificável por terceiros

Critério de aceite:

- um auditor consegue validar assinatura, integridade da cadeia e checkpoints externos sem depender de acesso privilegiado à base

---

## Decisão arquitetural recomendada

## Escolha agora

Implementar:

- `Go CLI`
- `ledger local encadeado por hash`
- `uma instituição: ipe`
- `assinatura do hash do PDF`
- `checkpoints externos`

## Deixar preparado

- interface `Ledger`
- esquema de eventos estável
- IDs e payloads consistentes

## Adiar

- Hyperledger Fabric
- web app
- multi-org
- PAdES completo

---

## Riscos principais

## Risco 1 - PDF/PAdES atrasar o projeto

Mitigação:

- validar primeiro o fluxo com assinatura do hash do PDF

## Risco 2 - ledger simples parecer fraco demais

Mitigação:

- assinar blocos
- manter export de âncoras
- documentar claramente o modelo de confiança

## Risco 3 - misturar domínio e backend de ledger

Mitigação:

- usar interface `Ledger`
- manter casos de uso independentes do storage

## Risco 4 - apagar acidentalmente material sensível

Mitigação:

- chave efêmera somente em memória
- logs sem chave privada
- zeroização explícita quando viável

---

## Sequência sugerida de execução

1. criar CLI mínima em Go
2. implementar `Issuer`, `CertificateRecord`, `SignatureRecord`
3. implementar geração de chave efêmera e certificado temporário
4. implementar ledger local append-only com hash chain
5. implementar trava de uso único
6. implementar `sign` com assinatura do hash do PDF
7. implementar `verify`
8. adicionar revogação
9. adicionar auditoria do ledger
10. decidir se vale evoluir para PDF embutido

---

## Resultado esperado do MVP

Ao final, teremos um comando de terminal capaz de:

- assinar um PDF com chave efêmera
- descartar a chave privada após uso
- emitir certificado temporário vinculado ao documento
- registrar emissão e uso em ledger auditável
- impedir reuso do certificado
- verificar autenticidade e integridade

Isso já prova a tese central do IpêSign com um desenho compatível com o cenário real: uma única instituição, auditoria forte e controle de uso único sem sobrecarga de blockchain permissionada.
