# One ATEP envelope as the unit of transport. Everything outside `envelope`
# is untrusted routing metadata: a receiver MUST verify `envelope` and take
# the signer, class and payload from the verified result, never from these fields.

# The envelope exactly as produced by the sender (COSE_Encrypt, CBOR tag 96;
# ATEP-R requires sign-then-encrypt). Byte for byte what the file, MQTT
# and HTTP carriers would hold.
uint8[] envelope

# Sender's claim about the ATEP-R command class (telemetry, sensor, coordination,
# motion, actuation, safety, maintenance). Compared with the signed class after
# verification, so a mislabelled message is refused.
string command_class

# Sender's claim about its Agent ID text form (atep:...). Convenience only.
string sender_hint

# Suite identifier, "ATEP-1" today. Lets a receiver drop an unsupported suite early.
string suite
