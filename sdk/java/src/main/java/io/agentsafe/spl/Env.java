package io.agentsafe.spl;

import java.util.HashMap;
import java.util.Map;
import java.util.function.BiFunction;

/**
 * Evaluation environment for SPL policies.
 */
public class Env {
    public Map<String, Node> req = new HashMap<>();
    public Map<String, Node> vars = new HashMap<>();
    public BiFunction<String, String, Integer> perDayCount = (a, d) -> 0;
    public CryptoCallbacks crypto = new CryptoCallbacks();
    public int maxGas = 10_000;
}
