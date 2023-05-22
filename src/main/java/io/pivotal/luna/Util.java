package io.pivotal.luna;

import java.util.HashMap;
import java.util.Map;

final class Util {

    private Util() {
    }

    static synchronized <K, V> Map<K, V> zip(K[] keys, V[] values) {
        Map<K, V> map = new HashMap<>();
        for (int i = 0; i < keys.length; i++) {
            map.put(keys[i], values[i]);
        }
        return map;
    }

}
