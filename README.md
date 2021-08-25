# Основные определения
## DID
В основе технологии SSI лежит понятие децентрализованного идентификатора ([DID](https://www.w3.org/TR/did-core/)).
Например, DID сети [Sovrin](https://sovrin-foundation.github.io/sovrin/spec/did-method-spec-template.html) выглядит
следующим образом
```
did:sov:BzCbsNYhMrjHiqZDTUASHg
```

С каждым DID связан т.н. DID Document, который хранит криптографическую информацию, способную идентифицировать его владельца,
и способы взаимодействия с владельцем DID (например URL-адреса его SSI агентов):

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

Порядок получения DIDDoc по DID определяется [методом DID](https://www.w3.org/TR/did-core/#methods). 
Владелец DID (и только он) может вносить изменения в DIDDoc для ротации ключей, изменения точки подключения и т.д.

Каждый SSI субъект может создавать неограниченное число своих собственных DID.

Более подробное описание технологии DID можно найти в книге [Self-Sovereign Identity](https://www.manning.com/books/self-sovereign-identity)
или соответствующем стандарте [W3C](https://www.w3.org/TR/did-core/).
### Приватный  DID
DIDDoc приватного DID доступен только тому, кому он был отправлен лично владельцем соответствующего DID. Приватные DID 
нигде не регистрируются. Обычно приватные DID используются для установления доверенных соединений между агентами.
Обычной практикой является создание уникального DID для каждого соединения.
DID методы, не требующие использования реестра, описаны в стандартах [did:key](https://w3c-ccg.github.io/did-method-key/),
[did:peer](https://identity.foundation/peer-did-method-spec/).

IndiLynx SDK позволяет создавать приватный DID следующим образом
```python
async with sirius_sdk.context(**AGENT):
    # Данный вызов создает новый DID и сохраняет его в Wallet
    agent_did, agent_verkey = await sirius_sdk.DID.create_and_store_my_did()
```
### Публичный DID
Публичный DID регистрируется в [публичном реестре](https://www.w3.org/TR/did-spec-registries/). Таким образом, соответствующий
DIDDoc доступен неограниченному кругу лиц. Размещение DIDDoc в публичном реестре позволяет поддерживать его в актуальном
состоянии, не изменяя при этом сам DID.

В рамках экосистемы Indy право на добавление DID в реестр имеют только агенты со специальной 
[ролью](https://hyperledger-indy.readthedocs.io/projects/node/en/latest/auth_rules.html) - Steward.
```python
async with sirius_sdk.context(**STEWARD):
    dkms = await sirius_sdk.ledger(network_name)
    await dkms.write_nym(
        submitter_did=steward_did,
        target_did=agent_did,
        ver_key=agent_verkey
    )
```

## SSI кошелек
Кошелек представляет собой хранилище публичных и приватных ключей, проверяемых учетных данных, DID и других приватных
криптографических данных, принадлежащих субъекту SSI и ни при каких обстоятельствах не передаваемых в открытом виде.
## Агент
Субъекты в экосистеме SSI взаимодействуют друг с другом при помощи своих агентов. Агенты выполняют техническую работу по
установке соединения, обмену данными в соответствии с протоколами, непосредственно взаимодействуют с SSI кошельком.
Агенты взаимодействуют друг с другом путем обмена сообщений ([DIDComm](https://identity.foundation/didcomm-messaging/spec/)).

Концепция SSI агентов описана в [Aries RFC 0004](https://github.com/hyperledger/aries-rfcs/tree/main/concepts/0004-agents).

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

# Создание локальной тестовой среды IndiLynx
Тестовую среду IndiLynx для запуска представленных в настоящей документации примеров и проведения экспериментов легче всего
развернуть при помощи [специально подготовленного docker-compose](https://github.com/Sirius-social/sirius-sdk-python/tree/master/test_suite).
В указанной папке достаточно вызвать
```
docker-compose up -d
```
.
Будет развернута вся необходимая инфраструктура и созданы 4 независимых SSI агента.

# Установка доверенного соединения между агентами
IndiLynx SDK позволяет устанавливать защищенное соединение между двумя агентами в соответствии с протоколом 
[0160-connection-protocol](https://github.com/hyperledger/aries-rfcs/tree/main/features/0160-connection-protocol).

В процессе установки защищенного соединения участвуют две стороны: Inviter и Invitee. Inviter инициирует процесс установки
соединения путем выпуска приглашения (Invitation). Приглашение может быть публичным для неопределенного круга лиц или 
приватным и выпускаться для конкретного пользователя.

IndiLynx SDK инкапсулирует всю внутреннюю логику протокола
[0160-connection-protocol](https://github.com/hyperledger/aries-rfcs/tree/main/features/0160-connection-protocol) в двух
конечных автоматах: sirius_sdk.aries_rfc.Inviter и sirius_sdk.aries_rfc.Invitee.

Inviter создает приглашение на установку соединения:
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
Invitee получает от Invter-а приглашение по независимому каналу связи (например через qr-код):
```python
# Работаем от лица агента Invitee
async with sirius_sdk.context(**INVITEE):
    # Создадим новый приватный DID для соединения с Inviter-ом
    my_did, my_verkey = await sirius_sdk.DID.create_and_store_my_did()
    me = sirius_sdk.Pairwise.Me(did=my_did, verkey=my_verkey)
    # Создадим экземпляр автомата для установки соединения на стороне Invitee
    invitee_machine = sirius_sdk.aries_rfc.Invitee(me, invitee_endpoint)
    ok, pairwise = await invitee_machine.create_connection(
        invitation=invitation,
        my_label='Invitee'
    )
```

Установка соединения на стороне Inviter-а:
```python
# Работаем от лица агента Inviter-а
async with sirius_sdk.context(**INVITER):
    # Создадим новый приватный DID для соединений в рамках ранее созданного invitation
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

Результатом установки соединения у обеих сторон является объект Pairwise, который хранится в Wallet обоих сторон. 
Следует отметить, что установка соединения
в общем случае производится один раз и не зависит жизненного цикла агентов или внутренних сетевых соединений. Аналогом установки
соединения между агентами является обмен визитками или номерами телефонов, с той лишь разницей, что в рассматриваемом
случае уставленное соединение защищено современной криптографией и основано на технологии [DID](https://www.w3.org/TR/did-core/).

# Выдача и получение проверяемых учетных данных
IndiLynx SDK позволяет выдавать и получать проверяемые учетные данные в соответствии с протоколом
[0036-issue-credential](https://github.com/hyperledger/aries-rfcs/tree/main/features/0036-issue-credential).

В процессе выдачи проверяемых учетных данных участвуют две стороны: Issuer и Holder. Issuer выдает VC, выпущенный
в соответствии с ранее созданной схемой и Credential Definition и подписанный его цифровой подписью. Holder сохраняет
данный VC в своем защищенном кошельке.

IndiLynx SDK инкапсулирует всю внутреннюю логику протокола [0036-issue-credential](https://github.com/hyperledger/aries-rfcs/tree/main/features/0036-issue-credential)
в двух конечных автоматах: Issuer и Holder.

Предполагается, что между Issuer и Holder установлено доверенное соединение.

Выдача VC со стороны ПО Issuer-а выглядит следующим образом: 
```python
# Подключаемся к агенту Issuer-а и работаем от его имени
async with sirius_sdk.context(**ISSUER):
    # Создаем конечный автомат для выдачи VC
    issuer_machine = sirius_sdk.aries_rfc.Issuer(holder=holder_pairwise)
    
    # Заполняем поля схемы данными
    values = {
        'first_name': 'Mike',
        'last_name': 'L.', 
        'birthday': '17.03.1993'
    }

    # Запускаем процедуру выдачи VC
    ok = await issuer_machine.issue(
        values=values,
        schema=schema,
        cred_def=cred_def,
        comment="Here is your document",
        locale="en"
    )
```

Для агента Holder-а процедура получения VC выглядит так же просто:
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
            success, cred_id = await holder_machine.accept(
                offer=offer,
                master_secret_id=PROVER_SECRET_ID
            )
```

# Запрос и предоставление проверяемых учетных данных
IndiLynx SDK позволяет запрашивать сведения и формировать криптографические доказательства о проверяемых учетных данных
владельца в соответствии с протоколом
[0037-present-proof](https://github.com/hyperledger/aries-rfcs/tree/main/features/0037-present-proof).
Важно отметить, что владелец учетных данных (Prover) передает не сами учетные данные, а криптографические доказательства,
подтверждающие факт владения Prover-а указанными VC и содержащие только тот минимальный объем информации, которую запросил Verifier.
Вместе с самими данными автоматически передается доказательство факта передачи этих данных от Prover-а к Verifier-у.

В процессе выдачи проверяемых учетных данных участвуют две стороны: Verifier и Prover.

IndiLynx SDK инкапсулирует всю внутреннюю логику протокола [0037-present-proof](https://github.com/hyperledger/aries-rfcs/tree/main/features/0037-present-proof)
в двух конечных автоматах: Verifier и Prover.

Предполагается, что между Verifier и Prover установлено доверенное соединение.

```python
# Работаем от лица агента Verifier-а
async with sirius_sdk.context(**VERIFIER):
    # Verifier указывает требуемые поля VC и требования к ним
    proof_request = {
        "name": "Demo Proof Request",
        "version": "0.1",
        "requested_attributes": {
            'attr1_referent': {
                "name": "first_name",
                "restrictions": {
                    "issuer_did": GOV_DID
                }
            },
            'attr2_referent': {
                "name": "last_name",
                "restrictions": {
                    "issuer_did": GOV_DID
                }
            },
            'attr3_referent': {
                "name": "birthday",
                "restrictions": {
                    "issuer_did": GOV_DID
                }
            }
        },
        "nonce": await sirius_sdk.AnonCreds.generate_nonce()
    }
    # Подключение к инфраструктуре публичных ключей
    dkms = await sirius_sdk.ledger(network_name)
        verifier_machine = sirius_sdk.aries_rfc.Verifier(
            prover=prover_pairwise,
            ledger=dkms
        )
    # Запуск процесса верификации VC
    success = await verifier_machine.verify(proof_request)
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
        # Prover самостоятельно ищет в своем кошельке необходимые поля VC, формирует криптографическое доказательство
        # их корректности и направляет доказательство Verifier-у
        success = await holder_machine.prove(
            request=proof_request,
            master_secret_id=PROVER_SECRET_ID
        )
```


# Установка доверенной среды между агентами
Платформа IndiLynx-SDK позволяет устанавливать доверенную среду между множеством участников для исполнения смарт-контрактов.
Логика смарт-контрактов исполняется непосредственно на агентах участников, таким образом отсутствует необходимость в использовании
дорогостоящих публичных децентрализованных виртуальных машин, таких как [Ethereum](https://ethereum.org/).
Использование защищенных соединений между SSI агентами совместно с алгоритмами подключаемого консенсуса позволяет обеспечить
необходимый уровень доверия между всеми заинтересованными сторонами.