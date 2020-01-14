package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;

public class AgentCommunicationGCM {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for AES in GCM.
         */
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                /*
                 * Alice:
                 * - creates an AES/GCM cipher,
                 * - initializes it for encryption and with given key.
                 * - encrypts the messages,
                 * - sends the ciphertext and the IV to Bob.
                 */
                final String text = "I hope you get this message intact and in secret. Kisses, Alice.";
                final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                //send("bob", pt);
                print("PT:  %s%n", Agent.hex(pt));

                final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                alice.init(Cipher.ENCRYPT_MODE, key);
                final byte[] ct = alice.doFinal(pt);
                //ct[3] = (byte) 3; introduce a n error in the cyphertext --> Tag mismatch
                print("CT:  %s%n", Agent.hex(ct));
                send("bob", ct);
                final byte[] iv = alice.getIV();
                //iv[3] = (byte) 3; //introduce an error in the cyphertext --> Tag mismatch
                send("bob", iv);

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /*
                 * Bob:
                 * - receives the ciphertext and the IV
                 * - creates a AES/GCM cipher
                 * - initializes the cipher with decryption mode, the key and the IV
                 * - decrypts the message and prints it.
                 */

                //final byte[] pt = receive("alice");
                //print("PT:  %s%n", Agent.hex(pt));
                final byte[] ct = receive("alice");
                print("CT:  %s%n", Agent.hex(ct));
                final byte[] IV = receive("alice");
                print("IV:  %s%n", Agent.hex(IV));

                //Decryption
                final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                final GCMParameterSpec specs = new GCMParameterSpec(128, IV);
                cipher.init(Cipher.DECRYPT_MODE, key, specs); // If we use an incorrect key we also get a tag mismatch
                final byte[] pt = cipher.doFinal(ct);
                print("PT: %s as %s%n", new String(pt), Agent.hex(pt));

            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
