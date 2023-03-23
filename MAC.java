/*
 * Copyright (c) 1997, 2017, Oracle and/or its affiliates. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of Oracle nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

import javax.crypto.*;

    /**
     * This program demonstrates how to generate a secret-key object for
     * HMACSHA256, and initialize an HMACSHA256 object with it.
     */

    public class MAC {

        public static void main(String[] args) throws Exception {

            // Generate secret key for HmacSHA256
            KeyGenerator kg = KeyGenerator.getInstance("HmacSHA256");
            SecretKey sk = kg.generateKey();

            String msg1 = "Hello darkness my old friend";

            // Get instance of Mac object implementing HmacSHA256, and
            // initialize it with the above secret key
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(sk);
            byte[] results = mac.doFinal(msg1.getBytes());
            //System.out.println(toHexString(result));

            //Verifier
            //Condition(1) same key, same msg -> same MAC
            Mac macv = Mac.getInstance("HmacSHA256");
            macv.init(sk);
            byte[] resultv = macv.doFinal(msg1.getBytes());
            //System.out.println("Verifier: "+toHexString(resultv));

            System.out.println("\n \n****************************************************************************************************");
            System.out.println("SCENARIO 1 - if a Verifier uses the same secret key to initialise his/her mac object and recalculate \n" +
                    "MAC code of the same text, then the result will be the same \n ");

            if (java.util.Arrays.equals(results, resultv)) {
                System.out.println("RESULT: --TRUE--");
            } else {
                System.out.println("RESULT: --FALSE--");
            }

            System.out.println("****************************************************************************************************");
            System.out.println("SCENARIO 2 - if a Verifier uses the same secret key, but calculates MAC code of a different text,\n" +
                    "then the result will be different\n ");


            //condition (2) same key, different msg -> different MAC
            String msg2 = "Ive come to talk with you again";
            resultv = macv.doFinal(msg2.getBytes());
            //System.out.println("Verified: "+toHexString(resultv));

            if (!java.util.Arrays.equals(results, resultv)) {
                System.out.println("RESULT: --TRUE--");
            } else {
                System.out.println("RESULT: --FALSE--");
            }

            System.out.println("****************************************************************************************************");
            System.out.println("SCENARIO 2 - If a Verifier uses a different secret key, but calculates MAC code of the same text,\n" +
                    "then the result will be different\n ");


            //Condition (3) different key, same msg -> different MAC?
            KeyGenerator kgv = KeyGenerator.getInstance("HmacSHA256");
            SecretKey skv = kgv.generateKey();

            Mac macv2 = Mac.getInstance("HmacSHA256");
            macv2.init(skv);

            resultv = macv2.doFinal(msg1.getBytes());


            if (!java.util.Arrays.equals(results, resultv)) {
                System.out.println("RESULT: --TRUE--");
            } else {
                System.out.println("RESULT: --FALSE--");
            }

            System.out.println("****************************************************************************************************");
        }

       /*
     * Converts a byte to hex digit and writes to the supplied buffer
     */
        private static void byte2hex(byte b, StringBuffer buf) {
            char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                                '9', 'A', 'B', 'C', 'D', 'E', 'F' };
            int high = ((b & 0xf0) >> 4);
            int low = (b & 0x0f);
            buf.append(hexChars[high]);
            buf.append(hexChars[low]);
        }

/*
     * Converts a byte array to hex string
     */
        private static String toHexString(byte[] block) {
            StringBuffer buf = new StringBuffer();
            int len = block.length;
            for (int i = 0; i < len; i++) {
                byte2hex(block[i], buf);
                if (i < len-1) {
                    buf.append(":");
                }
            }
            return buf.toString();
        }



    }
