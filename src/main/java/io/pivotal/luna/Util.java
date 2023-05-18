package io.pivotal.luna;

import java.util.HashMap;
import java.util.Map;

final class Util {

    private Util() {
    }

    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();

    static synchronized String bytesToHex(byte[] bytes) {

        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }

        return new String(hexChars);

    }

    static synchronized byte[] hexToBytes(String hex) {

        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }

        return data;

    }

    static synchronized <K, V> Map<K, V> zip(K[] keys, V[] values) {

        Map<K, V> map = new HashMap<>();
        for (int i = 0; i < keys.length; i++) {
            map.put(keys[i], values[i]);
        }

        return map;

    }

}
