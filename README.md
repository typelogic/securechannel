# Secure Channel Establishment

It involved two steps. In strict order, they are `INIT-UPDATE` and `EXT-AUTH`.

The laptop generates 8 random bytes and send this to the card in the `INIT-UPDATE` 
phase. The `p1` and `p2` also contains intents from the laptop with regards
to keys but this usage is implementation specific. When the card receives the
8 random bytes, the card in turn generate its own 8 random bytes and combining
this with the one that it just received, the card computes what is called a
`cryptogram` using the shared key. The card response shall contain its current
security posture, the 8 random bytes that it generated, and the 8 bytes cryptogram.
The laptop will parse the fields from this response in order to:
- Prepare security protocol objects matching with the card
- Re-compute the received card cryptogram for equivalence 

Take note that the `INIT-UPDATE` communications is in plaintext. No MAC. No encryption. 
The `EXT-AUTH`, however, requires MAC. 

To be clear, here is:
- `host challenge` is the 8 bytes random generated by laptop and sent to card 
- `card challenge` is the 8 bytes random generarted by card and included in response
- `card cryptogram` is the computation of `host challenge` + `card challenge` on shared key
- `host cryptogram` is the computation of `card challenge` + `host challenge` on shared key

It is at the successfull `EXT-AUTH` phase that the card and the laptop know each other. 
The `EXT-AUTH` phase also describes the level of security on the next commands to follow.

This is how the card and the laptop ensures they know each other based on the shared key.

Now we enter the second `EXT-AUTH` phase. The laptop computes `host cryptogram`. As the laptop is already
aware of the card's security posture, it constructs the matching security object. An example, is 
`SCP02`. During the first phase, it is the card that tells to the laptop what it has. In
the second phase, it will be the laptop that tells to the card how it wants to secure
the communication. For example:
- MAC only
- MAC and ENC

The first phase wherein it is the card that is telling something what it has, is called
`INIT-UPDATE`. In the second phase wherein it is the laptop telling on how to secure the communication, 
is the `EXT-AUTH` phase. 

Take note, the `EXT-AUTH` apdu is only MAC and not yet encrypted. Also take note,
the security setting is not encoded in the APDU, but rather it is decided during the `EXT-AUTH`
phase. Therefore, each communicating party should be watchful of this security state to have
synchronous understanding. 

# Diversification Data
This is a method wherein the card must utilize what it can find inside itself that is unique
to itself such as serial number, in order to diversify its security posture. Otherwise, a
breach of one card sharing same key will breach every cards. Many cards can share same shared key,
and the card can use its unique serial number in order to appear different, but yet fully 
communicable. 




