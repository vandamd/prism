package com.vandam.prism;

interface IPrismUserService {
    String preflight(String nonce) = 1;
    String startReSukiSuActivation(String nonce, int managerUid) = 2;
    String getActivationSnapshot(String nonce) = 3;
    String recoverStaleActivation(String session, String bootId) = 4;
    String prepareReSukiSuActivation(String nonce, int managerUid) = 5;
    String releasePreparedActivation(String nonce) = 6;
    void destroy() = 16777114;
}
