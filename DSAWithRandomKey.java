import java.security.*;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

//DSA example with randon key generation.

class Sender {
    Signature signature;
    SecureRandom random;
    KeyPairGenerator generator;
    KeyPair pair;
    PublicKey pubkey;
    PrivateKey privkey;


    public Sender()
            throws Exception {
        signature = Signature.getInstance("SHA1withDSA");
        random = new SecureRandom();
        // create the keys
        generator = KeyPairGenerator.getInstance("DSA");
        generator.initialize(512, random);
        pair = generator.generateKeyPair();
        pubkey = pair.getPublic();
        privkey = pair.getPrivate();

    }
        public byte[] signMessage(String input)
        throws Exception
        {
            byte [] signOfInput;

            System.out.println("\n--------------------\n SENDER \n--------------------");
            //Convert to byte Array and update hash function
            System.out.println("Message: " + input);

            //initialize DSA signature object
            signature.initSign(privkey, random);

            signature.update(Utils.toByteArray(input));

            signOfInput = signature.sign();

            System.out.println("DSA signature: "+ Utils.toHex(signOfInput));
            return signOfInput;
        }

        public PublicKey getPublicKey(){
        return pubkey;
        }
}

class Verifier {
    Signature signature;

    public Verifier()
            throws Exception {
        signature = Signature.getInstance("SHA1withDSA");
    }

    public void verify(String input, byte[] signOfInput, PublicKey pubKey)
            throws Exception {


        System.out.println("Received message:  " + input);
        //Initialize DSA signature object
        signature.initVerify(pubKey);
        //update signature
        signature.update(Utils.toByteArray(input));

        if (signature.verify(signOfInput)) {
            System.out.println("RESULT: Message authenticated.");
        } else {
            System.out.println("RESULT: Message could not been authenticated");
        }
    }
}
public class Lab4DSA {
    public static void main(String[] args)
            throws Exception
    {
        byte[] DSASignature;

        String Message = "This is a message";
        Sender aSender = new Sender();
        DSASignature = aSender.signMessage(Message);

        System.out.println("\n--------------------\n RECEIVER \n--------------------");

        Verifier aVerifier = new Verifier();
        aVerifier.verify(Message, DSASignature, aSender.getPublicKey());


        System.out.println("\n****************************************************************************************************");
        System.out.println("SCENARIO 1 - The message has been changed in passing from Sender to Verifier");

        String Message2 = "This is modified message";
        aVerifier.verify(Message2,DSASignature,aSender.getPublicKey());

    }
}