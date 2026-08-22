package com.vandam.prism;

interface IPrismAppBridge {
    String openSession(String session, String bootId) = 1;
    String readSignal(String session, int signal) = 2;
    String writeGate(String session, int gate, String value) = 3;
    String startRootChain(
        String session,
        String bridgeNonce,
        int helperPid,
        String helperStart,
        int donorPid,
        String donorStart,
        int ueventdPid
    ) = 4;
    String closeSession(String session) = 5;
    String probe(String nonce, String bootId) = 6;
    String validateProcessTeardown(String session, String token) = 7;
    String completeProcessTeardown(String session, String token) = 8;
    String inspectProcessTeardownResidue(String session, String bootId) = 9;
    String recordStrictCleanReceipt(String session, String receipt) = 10;
    String recordSafeMissReceipt(
        String session,
        String result,
        String progress,
        String binding
    ) = 11;
    String inspectSafeReset(String session, String bootId) = 12;
    String completeSafeReset(String session, String binding, String receipt) = 13;
    String acknowledgeSafeReset(String session, String binding) = 14;
}
