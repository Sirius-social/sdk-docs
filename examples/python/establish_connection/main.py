import sirius_sdk
import asyncio
from python.helpers import *


async def run():
    # В данном примере участвуют два агента: Inviter и Invitee
    inviter_agent_params = await get_agent_params("agent1")
    invitee_agent_params = await get_agent_params("agent2")

    async def get_invitation():
        # Работаем от имени агента Inviter
        async with sirius_sdk.context(**inviter_agent_params):
            connection_key = await sirius_sdk.Crypto.create_key()  # уникальный ключ соединения
            inviter_endpoint = [e for e in await sirius_sdk.endpoints() if e.routing_keys == []][0]
            global invitation
            invitation = sirius_sdk.Invitation(
                label='Inviter',
                endpoint=inviter_endpoint.address,  # URL адрес Inviter
                recipient_keys=[connection_key]
            )
            return invitation, connection_key

    invitation, connection_key = await get_invitation()

    async def inviter_routine():
        # Создадим новый приватный DID для соединений в рамках ранее созданного invitation
        my_did, my_verkey = await sirius_sdk.DID.create_and_store_my_did()
        me = sirius_sdk.Pairwise.Me(did=my_did, verkey=my_verkey)
        inviter_endpoint = [e for e in await sirius_sdk.endpoints() if e.routing_keys == []][0]
        # Создадим экземпляр автомата для установки соединения на стороне Inviter-а
        inviter_machine = sirius_sdk.Inviter(me, connection_key, inviter_endpoint)
        listener = await sirius_sdk.subscribe()
        # Ждем сообщение от Invitee
        async for event in listener:
            request = event['message']
            # Inviter получает ConnRequest от Invitee и проверяет, что он относится к ранее созданному приглашению
            if isinstance(request, sirius_sdk.ConnRequest) and event['recipient_verkey'] == connection_key:
                # запускаем процесс установки соединения
                ok, pairwise = await inviter_machine.create_connection(request)

    # Inviter по независимому каналу связи (например через QR код) передает Invitation Invitee
    # чтобы он зарегистрировал его в реестре

    async def invitee_routine():
        # Работаем от имени Invitee
        async with sirius_sdk.context(**invitee_agent_params):
            # Создадим новый приватный DID для соединения с Inviter-ом
            my_did, my_verkey = await sirius_sdk.DID.create_and_store_my_did()
            me = sirius_sdk.Pairwise.Me(did=my_did, verkey=my_verkey)
            # Создадим экземпляр автомата для установки соединения на стороне Invitee
            invitee_machine = sirius_sdk.aries_rfc.Invitee(
                me=me,
                my_endpoint=[e for e in await sirius_sdk.endpoints() if e.routing_keys == []][0])

            # Запускаем процесс установки соединения
            ok, pairwise = await invitee_machine.create_connection(
                invitation=invitation,
                my_label='Invitee'
            )

    await asyncio.wait([inviter_routine(), invitee_routine()])


if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(run())