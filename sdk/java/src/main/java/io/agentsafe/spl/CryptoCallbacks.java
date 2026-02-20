package io.agentsafe.spl;

import java.util.List;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Crypto callback functions provided by the host.
 */
public class CryptoCallbacks {
    public Supplier<Boolean> dpopOk = () -> true;
    public Function<List<Node>, Boolean> merkleOk = (tuple) -> true;
    public BiFunction<String, Double, Boolean> vrfOk = (day, amount) -> true;
    /**
     * thresh_ok — Threshold co-signature verification.
     * Expected protocol: k-of-n co-signatures where the verifier checks each
     * signature against its corresponding public key and confirms count >= threshold.
     * Not implemented in v0.1 — remains an interface stub.
     */
    public Supplier<Boolean> threshOk = () -> true;
}
