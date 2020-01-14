package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * An MITM example showing how merely using a collision-resistant hash
 * function is insufficient to protect against tampering
 */
public class AgentCommunicationMessageDigest {

    public static void main(String[] args) {
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                /*
                 * Alice:
                 * - sends a message that consists of:
                 *   - a message
                 *   - and a message Digest
                 */
                final byte[] message = "I hope you get this message intact. Kisses, Alice.".getBytes(StandardCharsets.UTF_8);

                // TODO: Create the digest and send the (message, digest) pair

                final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                final byte[] hashed_message = digestAlgorithm.digest(message);

                send("mallory", message);
                print("Sent message %s as %s", new String(message), hex(message));
                send("mallory", hashed_message);
                print("Sent hash %s", hex(hashed_message));

            }
        });

        env.add(new Agent("mallory") {
            @Override
            public void task() throws Exception {
                // Intercept the message from Alice
                final byte[] message = receive("alice");
                final byte[] tag = receive("alice");

                // TODO: Modify the message

                print("MITM received message %s as %s", new String(message), hex(message));
                print("MITM received hash %s", hex(tag));

                final byte[] message2 = "I hope you get this message intact. Kisses, MITM.".getBytes(StandardCharsets.UTF_8);
                final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                final byte[] tag2 = digestAlgorithm.digest(message2);

                print("MITM sent modified message %s as %s", new String(message2), hex(message2));
                print("MITM sent modified hash %s", hex(tag2));

                // Forward the modified message
                send("bob", message2);
                send("bob", tag2);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /*
                 * Bob
                 * - receives the message that is comprised of:
                 *   - message
                 *   - message digest
                 * - checks if received and calculated message digest checksum match.
                 */
                final byte[] message = receive("alice");
                final byte[] tag = receive("alice");

                // TODO: Check if the received (message, digest) pair is valid

                print("bob received message %s as %s", new String(message), hex(message));
                print("bob received hash %s", hex(tag));

                final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                final byte[] hashed_message = digestAlgorithm.digest(message);
                print("bob created  hash %s", hex(hashed_message));

                if(Arrays.equals(tag, hashed_message))
                    print("Tag checks out");
                else
                    print("Tag does not check out");
            }
        });

        env.mitm("alice", "bob", "mallory");
        env.start();
    }
}
