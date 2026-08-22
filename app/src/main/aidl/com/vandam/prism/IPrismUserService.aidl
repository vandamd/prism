package com.vandam.prism;

interface IPrismUserService {
    String preflight(String nonce) = 1;
    String startReSukiSuActivation(String nonce, int managerUid) = 2;
    String getActivationSnapshot(String nonce) = 3;
    String recoverStaleActivation(String session, String bootId) = 4;
    void destroy() = 16777114;
}
