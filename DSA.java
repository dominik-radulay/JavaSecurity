import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import java.security.MessageDigest;

public class DSA {
    public static void main(
            String[]    args)
            throws Exception
    {
        /* Security.addProvider(new BouncyCastleProvider()); */
        String          input = "This is a message";
        byte[] encoded = MessageDigest.getInstance("SHA-1").digest(input.getBytes());


        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        SecureRandom random = new SecureRandom();

        // create the keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

        generator.initialize(512, random);

        KeyPair pair = generator.generateKeyPair();
        Key pubKey = pair.getPublic();
        Key              privKey = pair.getPrivate();

        //for modified messages
        KeyPair pair1 = generator.generateKeyPair();
        Key pubKey1 = pair1.getPublic();
        Key              privKey1 = pair1.getPrivate();

        System.out.println("\n--------------------\n Encryption \n--------------------");
        System.out.println("input : " +  input);
        System.out.println("encoded : " +  Utils.toHex(encoded));

        // encryption step


        cipher.init(Cipher.ENCRYPT_MODE, privKey);
        byte[] digest = MessageDigest.getInstance("SHA-1").digest(input.getBytes());

        byte[] cipherText = cipher.doFinal(input.getBytes());
        byte[] cipherDigest = cipher.doFinal(digest);

        System.out.println("cipher: " + Utils.toHex(cipherText));


        System.out.println("\n--------------------\n Decryption \n--------------------");
        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, pubKey);
        byte[] message = cipher.doFinal(cipherText);
        String output =  new String(message);
        byte[] Recdigest = cipher.doFinal(cipherDigest);

        System.out.println("received message      : " + output + "  ✓");
        System.out.println("received digest      : " + Utils.toHex(Recdigest)+ "  ✓");
        byte[] newdigest = MessageDigest.getInstance("SHA-1").digest(input.getBytes());
        System.out.println("message (own digest) : " + Utils.toHex(newdigest)+ "  ✓");

        System.out.println("\n--------------------\n Verification \n--------------------");
        //Message change

        String          modified = "This is modified message";
        byte[] digest1 = MessageDigest.getInstance("SHA-1").digest(modified.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, privKey1);
        byte[] cipherText1 = cipher.doFinal(modified.getBytes());
        byte[] cipherDigest1 = cipher.doFinal(digest1);


        System.out.println("****************************************************************************************************");
        System.out.println("SCENARIO 1 - The message has been changed in passing from Sender to Verifier");

        try {
            cipher.init(Cipher.DECRYPT_MODE, pubKey);

            byte[] message1 = cipher.doFinal(cipherText1);
        }
        catch(Exception e) {
            System.out.println("ERROR: Encryption error (Used wrong public key for decryption of the message)");
        }
        System.out.println("****************************************************************************************************");
        //encrypted digest change
        System.out.println("SCENARIO 2 - The encrypted digest has been changed in passing from Sender to Verifier");
        try {
            cipher.init(Cipher.DECRYPT_MODE, pubKey);

            byte[] Recdigest1 = cipher.doFinal(cipherDigest1);
        }
        catch(Exception e) {
            System.out.println("ERROR: Encryption error (Used wrong public key for decryption of the digest)");
        }
        System.out.println("****************************************************************************************************");
        //both modified
        System.out.println("SCENARIO 3 - Both message and encrypted digest have been changed");
        try {
            cipher.init(Cipher.DECRYPT_MODE, pubKey);

            byte[] message1 = cipher.doFinal(cipherText1);
            byte[] Recdigest1 = cipher.doFinal(cipherDigest1);
        }
        catch(Exception e) {
            System.out.println("ERROR: Encryption error (Used wrong public key for decryption of both encrypted message and digest)");
        }
        System.out.println("Verifier would not be able to decrypt the received message and digest because of the error ");
        System.out.println("****************************************************************************************************");



    }

}
