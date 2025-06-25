package crypto

import (
	"encoding/json"
)

// SerializePayload converts a MessagePayload to bytes
func SerializePayload(payload MessagePayload) ([]byte, error) {
	return json.Marshal(payload)
}

// DeserializePayload converts bytes back to a MessagePayload
func DeserializePayload(data []byte) (*MessagePayload, error) {
	var payload MessagePayload
	err := json.Unmarshal(data, &payload)
	if err != nil {
		return nil, err
	}
	return &payload, nil
}

// SerializeEncryptedMessage converts an EncryptedMessage to bytes
func SerializeEncryptedMessage(msg *EncryptedMessage) ([]byte, error) {
	return json.Marshal(msg)
}

// DeserializeEncryptedMessage converts bytes back to an EncryptedMessage
func DeserializeEncryptedMessage(data []byte) (*EncryptedMessage, error) {
	var msg EncryptedMessage
	err := json.Unmarshal(data, &msg)
	if err != nil {
		return nil, err
	}
	return &msg, nil
}

// SerializePeerAnnouncement converts a PeerAnnouncement to bytes
func SerializePeerAnnouncement(announcement *PeerAnnouncement) ([]byte, error) {
	return json.Marshal(announcement)
}

// DeserializePeerAnnouncement converts bytes back to a PeerAnnouncement
func DeserializePeerAnnouncement(data []byte) (*PeerAnnouncement, error) {
	var announcement PeerAnnouncement
	err := json.Unmarshal(data, &announcement)
	if err != nil {
		return nil, err
	}
	return &announcement, nil
}

// SerializeKeyExchange converts a KeyExchangeMessage to bytes
func SerializeKeyExchange(keyExchange *KeyExchangeMessage) ([]byte, error) {
	return json.Marshal(keyExchange)
}

// DeserializeKeyExchange converts bytes back to a KeyExchangeMessage
func DeserializeKeyExchange(data []byte) (*KeyExchangeMessage, error) {
	var keyExchange KeyExchangeMessage
	err := json.Unmarshal(data, &keyExchange)
	if err != nil {
		return nil, err
	}
	return &keyExchange, nil
}
