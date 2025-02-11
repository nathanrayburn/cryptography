import base64
import datetime
from dataclass import msg
from dataclass import localmsg

LocalMessage = localmsg.LocalMessage
Message = msg.Message

def convert_local_to_message(local_message: LocalMessage) -> Message:
    """
    \brief Converts a LocalMessage object to a Message object.
    \param local_message The LocalMessage instance to convert.
    \return The converted Message instance.
    """
    return Message(
        sender=local_message.sender,
        receiver=local_message.receiver,
        id=local_message.id,
        senderEphemeralPublicKey=local_message.senderEphemeralPublicKey,
        content=local_message.content,
        nonce=local_message.nonce,
        signature=local_message.signature,
        timeBeforeUnlock=datetime.datetime.fromisoformat(local_message.timeBeforeUnlock)
    )