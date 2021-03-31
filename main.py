import sys
import jeffsTLSClass

# Define alice and Bob: ************************************************************************************************
alice = jeffsTLSClass.new()
bob = jeffsTLSClass.new()

# Generate RSA Keys: ***************************************************************************************************
print('Generating RSA Keys...')

# Generate the keys
alice.generateRSAKey(3072)
bob.generateRSAKey(3072)

# Get the public keys
alice.partnerData.rsaKey = bob.publicData.rsaKey
bob.partnerData.rsaKey = alice.publicData.rsaKey

# DHKE Key exchange: ***************************************************************************************************
# Get Values
print()
print('Getting Elliptic Curve Values...')
ecCurve = 'secp384r1'
alice.curveParams.defineEllipticCurve(ecCurve)
bob.curveParams.defineEllipticCurve(ecCurve)

# Do DHKE: *************************************************************************************************************
print()
print('Doing ECDHKE for Key values...')

# Get Alice's and Bob's private values
print('Generating DHKE private values...')
alice.generateDHKEPrivateValue()
bob.generateDHKEPrivateValue()

# Calculate Alice and Bob's Public Points
print('Calculating DHKE Public Points...')
alice.calculatePublicDHKEPoints()
bob.calculatePublicDHKEPoints()

# Send Alice's point to Bob
print('Sending Public Points...')
axMsg = alice.generateRsaSignature(alice.publicData.dhke_point)

# Verify on Bob's end
if not bob.verifyRsaSignature(axMsg[0], axMsg[1]):
    print("Alice's Public Keymessage could not be verified by Bob. Process aborted.")
    sys.exit()
else:
    bob.partnerData.dhke_point = axMsg[0]

# Send Bob's point to Alice
bxMsg = bob.generateRsaSignature(bob.publicData.dhke_point)

# Verify on Alice's end
if not alice.verifyRsaSignature(bxMsg[0], bxMsg[1]):
    print("Bob's Public Key message could not be verified by Alice. Process aborted.")
    sys.exit()
else:
    alice.partnerData.dhke_point = bxMsg[0]

# Compute Secret Keys
print('Computing Secret Keys...')
alice.computeSecretKeys()
bob.computeSecretKeys()

# Do the Nonce the same way as the key: ********************************************************************************
print()
print('Doing ECDHKE for Nonce values...')

# Get Values
print('Generating Nonce Values...')
alice.generateDHKENonceValue()
bob.generateDHKENonceValue()

# Calculate public nonce points
print('Calculating Nonce Public Points...')
alice.calculatePublicDHKENoncePoints()
bob.calculatePublicDHKENoncePoints()

# Send Alice's Point to Bob
print('Sending Nonce Values...')
axMsg = alice.generateRsaSignature(alice.publicData.dhke_noncepoint)

# Verify on Bob's end
if not bob.verifyRsaSignature(axMsg[0], axMsg[1]):
    print("Alice's Public Key message could not be verified by Bob. Process aborted.")
    sys.exit()
else:
    bob.partnerData.dhke_noncepoint = axMsg[0]

# Send Bob's point to Alice
bxMsg = bob.generateRsaSignature(bob.publicData.dhke_noncepoint)

# Verify on Alice's end
if not alice.verifyRsaSignature(bxMsg[0], bxMsg[1]):
    print("Bob's Public Key message could not be verified by Alice. Process aborted.")
    sys.exit()
else:
    alice.partnerData.dhke_noncepoint = bxMsg[0]

# Compute Secret Keys
print('Computing Secret Nonces...')
alice.computeSecretNonce()
bob.computeSecretNonce()

# Send a message from Alice to Bob: ************************************************************************************
print()
print('Sending message from Alice to Bob...')

# Send the message, tag during encryption and create RSA signature
msg = 'How neat is that?!'
eMsg, tag = alice.genereateEncryptedMessage(msg)
vMsg, sig = alice.generateRsaSignature(eMsg)

# Verify the message using the AES GCM tag
msgReceived, isVerified = bob.receiveEncryptedMessage(eMsg, tag)
print("Bob Received Message [GCM Signed]: '" + msgReceived + "'")
if not isVerified:
    print("Bob could not verify Alice's message using the GCM tag")
else:
    print("Bob verified Alice's message using the GCM tag!")

# Now do the RSA verifiaction
print("Bob Received Message [RSA Signed]: '" + bob.receiveEncryptedMessage(vMsg)[0] + "'")
if not bob.verifyRsaSignature(vMsg, sig):
    print("Bob could not verify Alice's message using the RSA Signature")
else:
    print("Bob verified Alice's message using the RSA Signature!")

# Send a message from Bob to Alice: ************************************************************************************
print()
print('Sending message from Bob To Alice...')

# Send the message, tag during encryption and create RSA signature
msg = "That's pretty neat!"
eMsg, tag = bob.genereateEncryptedMessage(msg)
vMsg, sig = bob.generateRsaSignature(eMsg)

# Verify the message using the AES GCM tag
msgReceived, isVerified = alice.receiveEncryptedMessage(eMsg, tag)
print("Alice Received Message [GCM Signed]: '" + msgReceived + "'")
if not isVerified:
    print("Alice could not verify Bob's message using the GCM tag")
else:
    print("Alice verified Bob's message using the GCM tag!")

# Now do the RSA verifiaction
print("Alice Received Message [RSA Signed]: '" + alice.receiveEncryptedMessage(vMsg)[0] + "'")
if not alice.verifyRsaSignature(vMsg, sig):
    print("Alice could not verify Bob's message using the RSA Signature")
else:
    print("Alice verified Bob's message using the RSA Signature!")

# Check for errors: ****************************************************************************************************
print()
print("Sending a 'tampered' message from Bob to Alice...")
# Send "tampered" messages
tMsg, badTag = bob.genereateEncryptedMessage("That's not very neat!")

# Verify the message using the AES GCM tag
msgReceived, isVerified = alice.receiveEncryptedMessage(tMsg, tag)
print("Alice Received Message [GCM Signed]: '" + msgReceived + "'")
if not isVerified:
    print("Alice could not verify Bob's message using the GCM tag")
else:
    print("Alice verified Bob's message using the GCM tag!")

# Now do the RSA verification
print("Alice Received Message [RSA Signed]: '" + alice.receiveEncryptedMessage(tMsg)[0] + "'")
if not alice.verifyRsaSignature(tMsg, sig):
    print("Alice could not verify Bob's message using the RSA Signature")
else:
    print("Alice verified Bob's message using the RSA Signature!")
