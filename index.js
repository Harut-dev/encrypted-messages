require('dotenv').config();

const { Crypto } = require("@peculiar/webcrypto");
const { Convert } = require("pvtsutils");
const DKeyRatchet = require("2key-ratchet");

async function main() {
    const argv = process.argv.slice(2);
    const {PERSON_ONE_ID, PERSON_TWO_ID} = process.env;
    if (!argv[0] || (argv[0] && argv[0] !== PERSON_ONE_ID && argv[0] !== PERSON_TWO_ID)) {
        console.log('Invalid person argument.');
        return;
    }
    if (!argv[1]) {
        console.log('Invalid message argument');
        return;
    }

    const receiverId = argv[0] === PERSON_ONE_ID ? Number(PERSON_ONE_ID) : Number(PERSON_TWO_ID);
    const senderId = receiverId === Number(PERSON_ONE_ID) ? Number(PERSON_TWO_ID) : Number(PERSON_ONE_ID);
    const message = argv[1];
    
    
    const crypto = new Crypto();
    DKeyRatchet.setEngine("@peculiar/webcrypto", crypto);

    // Create PersonOne's identity
    const PersonOneID = await DKeyRatchet.Identity.create(senderId, 1);

    // Create PreKeyBundle
    const PersonOnePreKeyBundle = new DKeyRatchet.PreKeyBundleProtocol();
    await PersonOnePreKeyBundle.identity.fill(PersonOneID);
    PersonOnePreKeyBundle.registrationId = PersonOneID.id;
    // Add info about signed PreKey
    const preKey = PersonOneID.signedPreKeys[0];
    PersonOnePreKeyBundle.preKeySigned.id = 0;
    PersonOnePreKeyBundle.preKeySigned.key = preKey.publicKey;
    await PersonOnePreKeyBundle.preKeySigned.sign(PersonOneID.signingKey.privateKey);
    // Convert proto to bytes
    const PersonOnePreKeyBundleProto = await PersonOnePreKeyBundle.exportProto();
    // console.log("PersonOne's bundle: ", Convert.ToHex(PersonOnePreKeyBundleProto));

    // Create PersonTwo's identity
    const PersonTwoID = await DKeyRatchet.Identity.create(receiverId, 1);

    // Parse PersonOne's bundle
    const bundle = await DKeyRatchet.PreKeyBundleProtocol.importProto(PersonOnePreKeyBundleProto);
    // Create PersonTwo's cipher
    const PersonTwoCipher = await DKeyRatchet.AsymmetricRatchet.create(PersonTwoID, bundle);
    // Encrypt message for PersonOne
    const PersonTwoMessageProto = await PersonTwoCipher.encrypt(Convert.FromUtf8String(message));
    // convert message to bytes array
    const PersonTwoMessage = await PersonTwoMessageProto.exportProto();
    console.log("Encrypted message:", Convert.ToHex(PersonTwoMessage));

    // Decrypt message by PersonOne
    // Note: First message from PersonTwo must be PreKeyMessage
    // parse PersonTwo's message
    const proto = await DKeyRatchet.PreKeyMessageProtocol.importProto(PersonTwoMessage);
    // Creat PersonOne's cipher for PersonTwo's message
    const PersonOneCipher = await DKeyRatchet.AsymmetricRatchet.create(PersonOneID, proto);
    // Decrypt message
    const bytes = await PersonOneCipher.decrypt(proto.signedMessage);
    console.log("Decrypted message:", Convert.ToUtf8String(bytes));
}

main().catch((e) => console.error(e));