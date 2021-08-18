# Основные определения
## DID
В основе технологии SSI лежит понятие децентрализованного идентификатора ([DID](https://www.w3.org/TR/did-core/)).

```
did:sov:BzCbsNYhMrjHiqZDTUASHg
```

С каждым DID связан т.н. DID Document

```json
{
  '@context': 'https://w3id.org/did/v1',
  'id': 'UNeAfCugwSoeukbBLXdPcU',
  'authentication': [
    {
      'publicKey': 'UNeAfCugwSoeukbBLXdPcU#1',
      'type': 'Ed25519SignatureAuthentication2018'
    }
  ],
  'publicKey': [
    {
      'id': '1',
      'type': 'Ed25519VerificationKey2018',
      'controller': 'UNeAfCugwSoeukbBLXdPcU',
      'publicKeyBase58': 'FvKTRgSYJkmuaPYdFQNBSJ71c1ajKG3BpQ3sopsTsdug'
    }
  ],
  'service': [
    {
      'id': 'did:peer:UNeAfCugwSoeukbBLXdPcU;indy',
      'type': 'IndyAgent',
      'priority': 0,
      'recipientKeys': [
        'UNeAfCugwSoeukbBLXdPcU#1'
      ],
      'serviceEndpoint': 'https://demo.socialsirius.com/endpoint/e0f9bbdfcc82468f8c10e8ac33c0d79c'
    }
  ]
}
```

Порядок получения DIDDoc по DID определяется методом DID. Владелец (и только он) DID может вносить изменения в DIDDoc для ротации ключей,
изменения точки подключения и т.д.

Каждый SSI субъект может создавать неограниченное число своих собственных DID.

Более подробное описание технологии DID можно найти в книге [Self-Sovereign Identity](https://www.manning.com/books/self-sovereign-identity)
или соответствующем стандарте [W3C](https://www.w3.org/TR/did-core/).
### Приватный  DID
DIDDoc приватного DID доступен только тому, кому он был отправлен лично владельцем соответствующего DID. Приватные DID 
нигде не регистрируются. Обычно приватные DID используются для установления доверенных соединений между агентами.
Обычной практикой является создание уникального DID для каждого соединения.
### Публичный DID
Публичный DID регистрируется в [публичном реестре](https://www.w3.org/TR/did-spec-registries/). Таким образом, соответствующий
DIDDoc доступен неограниченному кругу лиц. Размещение DIDDoc в публичном реестре позволяет поддерживать его в актуальном
состоянии, не изменяя при этом сам DID.
### Инфраструктура публичных ключей
## SSI кошелек
Кошелек представляет собой хранилище публичных и приватных ключей, проверяемых учетных данных, DID и других приватных
криптографических данных, принадлежащих субъекту SSI и ни при каких обстоятельствах не передаваемых в открытом виде.
## Агент
Субъекты в экосистеме SSI взаимодействуют друг с другом при помощи своих агентов. Агенты выполняют техническую работу по
установке соединения, обмену данными в соответствии с протоколами, непосредственно взаимодействуют с SSI кошельком.
Агенты взаимодействуют друг с другом путем обмена сообщений ([DIDComm](https://identity.foundation/didcomm-messaging/spec/)).

Концепция SSI агентов преложена в [Aries RFC 0004](https://github.com/hyperledger/aries-rfcs/tree/main/concepts/0004-agents).

### Облачный агент
Подходит для случая, когда SSI субъектом является юридическое лицо. Облачный агент управляется из корпоративного
приложения при помощи IndiLynx-SDK.

Для подключения и управления облачным агентом в IndiLynx SDK достаточно вызвать следующую команду
```python
# служебная информация, необходимая для соединения с облачным агентом или инициализации мобильного агента
AGENT = {
    server_uri = "<Sirius Hub URL>",
    credentials = "<Hub account credentials>",
   p2p = sirius_sdk.P2PConnection(
     my_keys=("<sdk-public-key>", "<sdk-secret-key>"),
     their_verkey="<agent-side-public-key>"
   )
}
sirius_sdk.init(
   **AGENT
)
```
либо
```python
async with sirius_sdk.context(**AGENT):
    #...
```

### Мобильный агент
Подходит для случая, когда SSI субъектом является физическое лицо. В этом случае SSI кошелек хранится исключительно на 
устройстве пользователя. Таким образом, отпадает необходимость в доверенном облачном хранилище.

Пример создания мобильного агента на java.
### Медиатор
Мобильный агент по разным причинам не может быть доступен 24/7 и у него скорее всего нет постоянного URL адреса. 
Таким образом, требуется некоторое промежуточное звено, которое бы предоставляло мобильному агенту постоянный URL адрес
и служило бы хранилищем входящих сообщений на время отсутствия мобильного агента. Естественно, что это звено не должно
иметь доступа к семантике сообщений и информации о личности владельца агента. Таким звеном в экосистеме SSI служит медиатор.

## Проверяемые учетные данные (Verifiable Credentials)
Проверяемые учетные данные (VC) в рамках экосистемы SSI являются цифровым аналогом привычных бумажных документов, 
таких как паспорт, права, диплом об образовании. Существенным является тот факт, что VC хранятся не в централизованном
хранилище, а исключительно у его владельца. Только владелец VC решает, кому и в каком объеме передавать свои
персональные данные (ПД). Такой подход значительно снижает вероятность несанкционированного доступа и обработки ПД.
Вместе с тем на владельца SSI VC ложится дополнительная ответственность на сохранность своего SSI кошелька.
### Схема проверяемых учетных данных
Как и в случае бумажных документов, VC должны иметь заранее определенную структуру с конкретным набором полей.
Создадим простую схему с тремя полями: Имя, фамилия и возраст. Необходимо также указать DID автора схемы (скорее всего это будет государство).

```python
schema_id, anon_schema = await sirius_sdk.AnonCreds.issuer_create_schema(
            GOV_DID, 'demo_passport', '1.0', ['first_name', 'last_name', 'birthday']
        )
```
Экосистема Indy требует обязательной записи схемы в реестр
```python
dkms = await sirius_sdk.ledger(network_name)
schema_ = await dkms.ensure_schema_exists(anon_schema, ISSUER_DID)
```
### Credential definition
Данная структура является специфичной для Indy.

Является связкой схемы и конкретного эмитента. Например, государство может определять схему для документа об 
образовании, и каждый университет, который выпускает документы данного образца, регистрирует в реестре 
соответствущий credential definition

```python
ok, cred_def_ = await dkms.register_cred_def(
                cred_def=sirius_sdk.CredentialDefinition(tag='TAG', schema=schema_),
                submitter_did=ISSUER_DID
            )
```

# Установка доверенного соединения между агентами
IndiLynx SDK позволяет устанавливать защищенное соединение между двумя агентами в соответствии с протоколом 
[0160-connection-protocol](https://github.com/hyperledger/aries-rfcs/tree/main/features/0160-connection-protocol).

В процессе установки защищенного соединения участвуют две стороны: Inviter и Invitee. Inviter инициирует процесс установки
соединения путем выпуска приглашения (Invitation). Приглашение может быть публичным для неопределенного круга лиц или 
приватным и выпускаться для конкретного пользователя.

```python
# Работаем от лица агента Inviter-а
async with sirius_sdk.context(**INVITER):
    connection_key = await sirius_sdk.Crypto.create_key() # уникальный ключ соединения
    invitation = Invitation(
        label='Inviter',
        endpoint=inviter_endpoint.address(), # URL адрес Inviter
        recipient_keys=[connection_key]
    )
```
Invitee получает от Invter-а приглашение по независимому каналу связи (например через qr-код)
```python
# Работаем от лица агента Invitee
async with sirius_sdk.context(**INVITEE):
    # Создадим новый DID для соединения с Inviter-ом
    my_did, my_verkey = await sirius_sdk.DID.create_and_store_my_did()
    me = sirius_sdk.Pairwise.Me(did=my_did, verkey=my_verkey)
    # Создадим экземпляр автомата для установки соединения на стороне Invitee
    invitee_machine = sirius_sdk.aries_rfc.Invitee(me, invitee_endpoint)
    ok, pairwise = await invitee_machine.create_connection(invitation=invitation, my_label='Invitee')
```

IndiLynx SDK инкапсулирует всю внутреннюю логику протокола
[0160-connection-protocol](https://github.com/hyperledger/aries-rfcs/tree/main/features/0160-connection-protocol) в двух
конечных автоматах: sirius_sdk.aries_rfc.Inviter и sirius_sdk.aries_rfc.Invitee.

```python
# Работаем от лица агента Inviter-а
async with sirius_sdk.context(**INVITER):
    # Создадим новый DID для соединений в рамках ранее созданного invitation
    my_did, my_verkey = await sirius_sdk.DID.create_and_store_my_did()
    me = sirius_sdk.Pairwise.Me(did=my_did, verkey=my_verkey)
    # Создадим экземпляр автомата для установки соединения на стотоне Inviter-а
    inviter_machine = Inviter(me, connection_key, inviter_endpoint)
    listener = await sirius_sdk.subscribe()
    async for event in listener:
        request = event['message']
        # Inviter получает ConnRequest от Invitee и проверяет, что он относится к ранее созданному приглашению
        if isinstance(request, ConnRequest) and event['recipient_verkey'] == connection_key:
            # запускаем процесс установки соединения
            ok, pairwise = await inviter_machine.create_connection(request)
```

Результатом установки соединения у обеих сторон является объект Pairwise. Следует отметить, что установка соединения
в общем случае производится один раз и не зависит жизненного цикла агентов или внутренних сетевых соединений. Аналогом установки
соединения между агентами является обмен визитками или номерами телефонов, с той лишь разницей, что в рассматриваемом
случае уставленное соединение защищено современной криптографией и основано на технологии [DID](https://www.w3.org/TR/did-core/).

# Создание и регистрация схем проверяемых учетных данных

# Выдача и получение проверяемых учетных данных
IndiLynx SDK позволяет выдавать и получать проверяемые учетные данные в соответствии с протоколом
[0036-issue-credential](https://github.com/hyperledger/aries-rfcs/tree/main/features/0036-issue-credential).

В процессе выдачи проверяемых учетных данных участвуют две стороны: Issuer и Holder. Issuer выдает VC, выпущенный
в соответствии с ранее созданной схемой и Credential Definition и подписанный его цифровой подписью. Holder сохраняет
данный VC в своем защищенном кошельке.

IndiLynx SDK инкапсулирует всю внутреннюю логику протокола [0036-issue-credential](https://github.com/hyperledger/aries-rfcs/tree/main/features/0036-issue-credential)
в двух конечных автоматах: Issuer и Holder.

Предполагается, что между Issuer и Holder установлено доверенное соединение.

```python
# Работаем от лица агента Issuer-а
async with sirius_sdk.context(**ISSUER):
    # Создаем конечный автомат для выдачи VC
    issuer_machine = sirius_sdk.aries_rfc.Issuer(holder=holder_pairwise)
    
    values = {
        'first_name': 'Mike',
        'last_name': 'L.', 
        'birthday': '17.03.1993'
    }

    ok = await issuer_machine.issue(
        values=values,
        schema=schema,
        cred_def=cred_def,
        comment="Here is your document",
        locale="en"
    )
```

```python
# Работаем от лица агента Holder-а
async with sirius_sdk.context(**HOLDER):
    holder_machine = sirius_sdk.aries_rfc.Holder(pairwise)
    listener = await sirius_sdk.subscribe()
    async for event in listener:
        # Holder получает предложение получения VC (OfferCredentialMessage) от Issuer-а
        if isinstance(event['message'], OfferCredentialMessage):
            offer: OfferCredentialMessage = event.message
            # Holder запускает процесс получения VC. Результат записывается в его кошелек
            success, cred_id = await holder_machine.accept(offer=offer, master_secret_id=PROVER_SECRET_ID)
```

# Запрос и предоставление проверяемых учетных данных
IndiLynx SDK позволяет запрашивать сведения и формировать криптографические доказательства о проверяемых учетных данных
владельца в соответствии с протоколом
[0037-present-proof](https://github.com/hyperledger/aries-rfcs/tree/main/features/0037-present-proof).

В процессе выдачи проверяемых учетных данных участвуют две стороны: Verifier и Prover.

IndiLynx SDK инкапсулирует всю внутреннюю логику протокола [0037-present-proof](https://github.com/hyperledger/aries-rfcs/tree/main/features/0037-present-proof)
в двух конечных автоматах: Verifier и Prover.

Предполагается, что между Verifier и Prover установлено доверенное соединение.

```python
# Работаем от лица агента Verifier-а
async with sirius_sdk.context(**VERIFIER):
    proof_request = {
        "name": "Demo Proof Request",
        "version": "0.1",
        "requested_attributes": {
            'attr1_referent': {
                "name": "first_name",
                "restrictions": {
                    "issuer_did": ISSUER_DID
                }
            },
            'attr2_referent': {
                "name": "last_name",
                "restrictions": {
                    "issuer_did": ISSUER_DID
                }
            },
            'attr3_referent': {
                "name": "birthday",
                "restrictions": {
                    "issuer_did": ISSUER_DID
                }
            }
        },
        "nonce": await sirius_sdk.AnonCreds.generate_nonce()
    }
    dkms = await sirius_sdk.ledger(network_name)
        verifier_machine = sirius_sdk.aries_rfc.Verifier(
            prover=prover,
            ledger=dkms
        )
    success = await feature_0037.verify(proof_request)
```

```python
# Работаем от лица агента Prover-а
async with sirius_sdk.context(**PROVER):
listener = await sirius_sdk.subscribe()
async for event in listener:
    if isinstance(event.message, RequestPresentationMessage):
        proof_request: sirius_sdk.aries_rfc.RequestPresentationMessage = event.message
        holder_machine = sirius_sdk.aries_rfc.Prover(
            verifier=verifier,
            ledger=dkms
        )
        success = await holder_machine.prove(
            request=proof_request,
            master_secret_id=PROVER_SECRET_ID
        )
```


# Установка доверенной среды между агентами