package week1;


import ch.qos.logback.classic.Level;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static java.lang.System.out;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;


/**
 * Suppose you are told that the one time pad encryption of the message "attack at dawn" is 6c73d5240a948c86981bc294814d
 * <p>
 * (the plaintext letters are encoded as 8-bit ASCII and the given ciphertext is written in hex). What would be the one time pad encryption of the message "attack at dusk" under the same OTP key?
 */
public class OneTimePadCipherDemo {

    private static final String input1 = "attack at dawn";
    private static final String input2 = "attack at dusk";
    private static final String cipherHEX = "6c73d5240a948c86981bc294814d";
    private static Logger log = LoggerFactory.getLogger(OneTimePadCipherDemo.class);

    public OneTimePadCipherDemo() throws UnsupportedEncodingException {
    }

    /**
     * Sets required logging level globally via the root logger
     *
     * @param level required logging level
     */
    private static void setLoggingLevel(Level level) {
        ch.qos.logback.classic.Logger root = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(ch.qos.logback.classic.Logger.ROOT_LOGGER_NAME);
        root.setLevel(level);
    }

    private static void xor(byte[] input1Bytes, byte[] cipherBytes, byte[] result) {
        for (int i = 0; i < input1Bytes.length; i++) {
            int xor = input1Bytes[i] ^ cipherBytes[i];
            result[i] = (byte) xor;
            log.debug(Byte.toString(input1Bytes[i]) + " xor " + Byte.toString(cipherBytes[i]) + " = " + xor);
        }
    }

    @Test
    public void getKeyAndDecrypt() throws UnsupportedEncodingException {
        setLoggingLevel(Level.INFO);
        //get input string as byte array
        byte[] input1Bytes = input1.getBytes(StandardCharsets.US_ASCII);
        printAsBitmap(input1Bytes, "input1");
        //get cipher as byte array
        byte[] cipherBytes = DatatypeConverter.parseHexBinary(cipherHEX);
        log.debug(Arrays.toString(cipherBytes));
        printAsBitmap(cipherBytes, "cipher");
        byte[] key = new byte[input1Bytes.length];
        xor(input1Bytes, cipherBytes, key);
        printAsBitmap(key, "key");
        //apply key to input2 via bitwise XOR
        byte[] input2Bytes = input2.getBytes(StandardCharsets.US_ASCII);
        byte[] output = new byte[input2Bytes.length];
        xor(input2Bytes, key, output);
        printAsBitmap(input2Bytes, "input2");
        printAsBitmap(output, "encoded input2");
        //print output as HEX
        printAsHEX(output, "encoded input2");
        printAsHEX(key, "key");
    }

    @Test
    public void testHardcoded() {
        setLoggingLevel(Level.INFO);
        //Given input2,encoded input2, the key
        byte[] input2Bytes = input2.getBytes(StandardCharsets.US_ASCII);
        byte[] encodedInput2Bytes = DatatypeConverter.parseHexBinary("6C73D5240A948C86981BC2808548");
        byte[] keyBytes = DatatypeConverter.parseHexBinary("0D07A14569FFACE7EC3BA6F5F623");
        //Then XOR encoded input2 and the key
        byte[] decodedInput2Bytes = new byte[input2Bytes.length];
        xor(encodedInput2Bytes, keyBytes, decodedInput2Bytes);
        //Check that encoded and decoded values are equals
        printAsBitmap(decodedInput2Bytes, "actual");
        printAsBitmap(input2Bytes, "expected");
        out.println(new String(decodedInput2Bytes, StandardCharsets.US_ASCII));
        out.println(new String(input2Bytes, StandardCharsets.US_ASCII));
        assertArrayEquals(input2Bytes, decodedInput2Bytes);
        assertEquals(new String(decodedInput2Bytes, StandardCharsets.US_ASCII), new String(input2Bytes, StandardCharsets.US_ASCII));
    }

    private void printAsHEX(byte[] bytes, String name) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        System.out.println(sb.toString() + ": " + name);
    }

    private void printAsBitmap(byte[] bytes, String name) {
        for (byte aByte : bytes) {
            //TODO Substitute this magic https://stackoverflow.com/a/12310078/6793472 by a common utilities (Guava primitives ?)
            String binaryAsString = Integer.toBinaryString((aByte & 0xFF) + 0x100).substring(1);
            //print bits grouped by 4 items
            int counter = 0;
            for (char aChar : binaryAsString.toCharArray()) {
                out.print(aChar);
                counter++;
                if (counter == 4) {
                    out.print(" ");
                    counter = 0;
                }
            }
        }
        out.print(" :" + name);
        out.println();
    }

}
